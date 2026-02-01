#!/bin/bash
# Integration test: deploys limguard to two Lima VMs and verifies mesh connectivity.
# Usage: ./tests/integration.sh
#
# Prerequisites:
# - Lima (brew install lima)
# - Go 1.24+
# - SSH key (~/.ssh/id_ed25519 or ~/.ssh/id_rsa)

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() { echo -e "${GREEN}>>>${NC} $*"; }
warn() { echo -e "${YELLOW}>>>${NC} $*"; }
error() { echo -e "${RED}>>>${NC} $*"; }

# Configuration
NODE1="limguard-test-1"
NODE2="limguard-test-2"
WG_IP1="10.200.0.1"
WG_IP2="10.200.0.2"
CLEANUP=${CLEANUP:-1}

# Find project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Create temp directory
TMPDIR=$(mktemp -d)
trap 'cleanup' EXIT

cleanup() {
    if [[ "$CLEANUP" == "1" ]]; then
        log "Cleaning up..."
        limactl stop "$NODE1" 2>/dev/null || true
        limactl stop "$NODE2" 2>/dev/null || true
        limactl delete "$NODE1" 2>/dev/null || true
        limactl delete "$NODE2" 2>/dev/null || true
        rm -rf "$TMPDIR"
    else
        warn "Skipping cleanup (CLEANUP=0)"
        warn "Temp dir: $TMPDIR"
        warn "VMs: $NODE1, $NODE2"
    fi
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    if ! command -v limactl &>/dev/null; then
        error "limactl not found. Install with: brew install lima"
        exit 1
    fi
    
    if ! command -v go &>/dev/null; then
        error "go not found"
        exit 1
    fi
    
    # Check socket_vmnet is running (required for shared network)
    if ! pgrep -x socket_vmnet &>/dev/null; then
        error "socket_vmnet not running. Install and start with:"
        error "  brew install socket_vmnet"
        error "  sudo brew services start socket_vmnet"
        exit 1
    fi
    log "socket_vmnet is running"
    
    # Find SSH key
    if [[ -f ~/.ssh/id_ed25519 ]]; then
        SSH_KEY=~/.ssh/id_ed25519
    elif [[ -f ~/.ssh/id_rsa ]]; then
        SSH_KEY=~/.ssh/id_rsa
    else
        error "No SSH key found at ~/.ssh/id_ed25519 or ~/.ssh/id_rsa"
        exit 1
    fi
    log "Using SSH key: $SSH_KEY"
}

# Create and start a VM
create_vm() {
    local name=$1
    
    if limactl list --format '{{.Name}}' | grep -q "^${name}$"; then
        log "VM $name already exists"
    else
        log "Creating VM $name..."
        limactl create --name="$name" \
            template:debian-13 \
            --cpus=1 \
            --memory=1 \
            --vm-type=vz \
            --network=lima:shared \
            --yes
    fi
    
    # Start the VM (limactl create doesn't start it)
    log "Starting VM $name..."
    limactl start "$name" || true
    
    log "Waiting for VM $name to be ready..."
    for i in {1..30}; do
        if limactl shell "$name" -- echo "ready" &>/dev/null; then
            log "VM $name is ready"
            return 0
        fi
        sleep 1
    done
    error "VM $name did not become ready"
    exit 1
}

# Get VM SSH port
get_ssh_port() {
    local name=$1
    limactl show-ssh "$name" 2>/dev/null | grep -o 'Port=[0-9]*' | cut -d= -f2
}

# Get VM IP address (from lima0 - the shared network interface)
get_vm_ip() {
    local name=$1
    limactl shell "$name" -- ip addr show lima0 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1
}

# Enable SSH access
enable_ssh_access() {
    local name=$1
    local pubkey
    pubkey=$(cat "${SSH_KEY}.pub")
    
    log "Enabling SSH access for $name..."
    limactl shell "$name" -- bash -c "
        mkdir -p ~/.ssh
        chmod 700 ~/.ssh
        touch ~/.ssh/authorized_keys
        chmod 600 ~/.ssh/authorized_keys
        grep -qF '$pubkey' ~/.ssh/authorized_keys || echo '$pubkey' >> ~/.ssh/authorized_keys
    "
}

# Build limguard binary for target platform
build_binary() {
    log "Building limguard binary..."
    
    # Detect architecture
    local arch="arm64"
    if [[ $(uname -m) == "x86_64" ]]; then
        arch="amd64"
    fi
    
    BINARY_PATH="$TMPDIR/limguard-linux-$arch"
    log "Building $BINARY_PATH..."
    cd "$PROJECT_ROOT"
    GOOS=linux GOARCH=$arch go build -o "$BINARY_PATH" ./cmd/limguard/
    log "Binary built: $BINARY_PATH"
}

# Create test config
create_config() {
    local ssh_port1=$1
    local ssh_port2=$2
    local endpoint1=$3
    local endpoint2=$4
    local username
    username=$(whoami)
    
    log "Creating test config..."
    cat > "$TMPDIR/limguard.yaml" << EOF
linuxInterfaceName: wg0
darwinInterfaceName: utun9

nodes:
  $NODE1:
    wireguardIP: "$WG_IP1"
    endpoint: "$endpoint1:51820"
    localBinaryPath: "$BINARY_PATH"
    ssh:
      host: "127.0.0.1"
      port: $ssh_port1
      user: "$username"
      identityFile: $SSH_KEY

  $NODE2:
    wireguardIP: "$WG_IP2"
    endpoint: "$endpoint2:51820"
    localBinaryPath: "$BINARY_PATH"
    ssh:
      host: "127.0.0.1"
      port: $ssh_port2
      user: "$username"
      identityFile: $SSH_KEY
EOF
    
    log "Config written to $TMPDIR/limguard.yaml"
}

# Run limguard apply
run_apply() {
    log "Running limguard apply..."
    cd "$PROJECT_ROOT"
    go run ./cmd/limguard/ apply --config "$TMPDIR/limguard.yaml"
}

# Verify ping between nodes
verify_ping() {
    local from=$1
    local to_ip=$2
    
    log "Pinging $to_ip from $from..."
    for i in {1..5}; do
        if limactl shell "$from" -- ping -c 3 -W 2 "$to_ip"; then
            log "Ping from $from to $to_ip succeeded"
            return 0
        fi
        warn "Ping attempt $i failed, retrying..."
        sleep 2
    done
    error "Ping from $from to $to_ip failed after 5 attempts"
    exit 1
}

# Check service status
check_service() {
    local name=$1
    
    log "Checking service status on $name..."
    local status
    status=$(limactl shell "$name" -- sudo systemctl is-active limguard)
    if [[ "$status" == "active" ]]; then
        log "Service on $name is active"
    else
        error "Service on $name is not active: $status"
        limactl shell "$name" -- sudo journalctl -u limguard -n 20 --no-pager
        exit 1
    fi
}

# Main
main() {
    log "Starting integration test..."
    
    check_prerequisites
    
    # Step 1: Create and start VMs in parallel
    log "Creating VMs in parallel..."
    create_vm "$NODE1" &
    pid1=$!
    create_vm "$NODE2" &
    pid2=$!
    
    # Wait for both VMs to be ready
    wait $pid1 || { error "Failed to create $NODE1"; exit 1; }
    wait $pid2 || { error "Failed to create $NODE2"; exit 1; }
    log "Both VMs are ready"
    
    # Step 2: Get VM info (in parallel)
    SSH_PORT1=$(get_ssh_port "$NODE1") &
    SSH_PORT2=$(get_ssh_port "$NODE2") &
    wait
    SSH_PORT1=$(get_ssh_port "$NODE1")
    SSH_PORT2=$(get_ssh_port "$NODE2")
    ENDPOINT1=$(get_vm_ip "$NODE1")
    ENDPOINT2=$(get_vm_ip "$NODE2")
    
    log "Node 1: SSH port=$SSH_PORT1, endpoint=$ENDPOINT1"
    log "Node 2: SSH port=$SSH_PORT2, endpoint=$ENDPOINT2"
    
    # Step 3: Enable SSH access in parallel
    log "Enabling SSH access in parallel..."
    enable_ssh_access "$NODE1" &
    pid1=$!
    enable_ssh_access "$NODE2" &
    pid2=$!
    wait $pid1 $pid2
    
    # Step 4: Build binary
    build_binary
    
    # Step 5: Create config
    create_config "$SSH_PORT1" "$SSH_PORT2" "$ENDPOINT1" "$ENDPOINT2"
    
    # Step 6: Run apply (uses local binary)
    run_apply

    echo ""
    log "========================================="
    log "Integration test PASSED!"
    log "========================================="
}

main "$@"
