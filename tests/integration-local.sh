#!/bin/bash
# Integration test: deploys limguard to two Lima VMs AND the local machine.
# Usage: sudo CLEANUP=0 ./tests/integration-local.sh  # Keep VMs for debugging
#        sudo ./tests/integration-local.sh            # Clean up after test
#
# Prerequisites:
# - Lima (brew install lima)
# - socket_vmnet (see tests/README.md for setup)
# - Go 1.24+
# - SSH key (~/.ssh/id_ed25519 or ~/.ssh/id_rsa)
# - Root privileges (sudo)

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
LOCAL_NODE="local-test"
WG_IP1="10.200.0.1"
WG_IP2="10.200.0.2"
WG_IP_LOCAL="10.200.0.3"
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
        log "Stopping local limguard service..."
        launchctl bootout system/com.limrun.limguard 2>/dev/null || true
        rm -f /Library/LaunchDaemons/com.limrun.limguard.plist
        rm -f /var/log/limguard.log
        
        # Kill any wireguard-go processes for our interface
        pkill -f "wireguard-go utun9" 2>/dev/null || true
        rm -f /var/run/wireguard/utun9.sock 2>/dev/null || true
        
        limactl_cmd stop "$NODE1" 2>/dev/null || true
        limactl_cmd stop "$NODE2" 2>/dev/null || true
        limactl_cmd delete "$NODE1" 2>/dev/null || true
        limactl_cmd delete "$NODE2" 2>/dev/null || true
        rm -rf "$TMPDIR"
    else
        warn "Skipping cleanup (CLEANUP=0)"
        warn "Temp dir: $TMPDIR"
        warn "VMs: $NODE1, $NODE2"
        warn "Local service still installed"
    fi
}

# Run limactl as the original user (not root)
limactl_cmd() {
    if [[ -n "${SUDO_USER:-}" ]]; then
        sudo -u "$SUDO_USER" limactl "$@"
    else
        limactl "$@"
    fi
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Must be root
    if [[ $EUID -ne 0 ]]; then
        error "This test must be run as root (sudo ./integration-local.sh)"
        exit 1
    fi
    
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
        error "socket_vmnet not running. See tests/README.md for setup instructions."
        exit 1
    fi
    log "socket_vmnet is running"
    
    # Find SSH key (check original user's home if running as sudo)
    local user_home
    if [[ -n "${SUDO_USER:-}" ]]; then
        user_home=$(eval echo ~"$SUDO_USER")
    else
        user_home=$HOME
    fi
    
    if [[ -f "$user_home/.ssh/id_ed25519" ]]; then
        SSH_KEY="$user_home/.ssh/id_ed25519"
    elif [[ -f "$user_home/.ssh/id_rsa" ]]; then
        SSH_KEY="$user_home/.ssh/id_rsa"
    else
        error "No SSH key found at $user_home/.ssh/id_ed25519 or $user_home/.ssh/id_rsa"
        exit 1
    fi
    log "Using SSH key: $SSH_KEY"
}

# Create and start a VM
create_vm() {
    local name=$1
    
    if limactl_cmd list --format '{{.Name}}' | grep -q "^${name}$"; then
        log "VM $name already exists"
    else
        log "Creating VM $name..."
        limactl_cmd create --name="$name" \
            template:debian-13 \
            --cpus=1 \
            --memory=1 \
            --vm-type=vz \
            --network=lima:shared \
            --yes
    fi
    
    # Start the VM (limactl create doesn't start it)
    log "Starting VM $name..."
    limactl_cmd start "$name" || true
    
    log "Waiting for VM $name to be ready..."
    for i in {1..30}; do
        if limactl_cmd shell "$name" -- echo "ready" &>/dev/null; then
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
    limactl_cmd show-ssh "$name" 2>/dev/null | grep -o 'Port=[0-9]*' | cut -d= -f2
}

# Get VM IP address (from lima0 - the shared network interface)
get_vm_ip() {
    local name=$1
    limactl_cmd shell "$name" -- ip addr show lima0 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1
}

# Get local machine IP on the shared network
get_local_ip() {
    # The shared network uses 192.168.105.0/24, local host is typically .1
    # But we need to find the actual interface
    ifconfig | grep -A 5 "bridge100" | grep "inet " | awk '{print $2}' || echo "192.168.105.1"
}

# Enable SSH access
enable_ssh_access() {
    local name=$1
    local pubkey
    pubkey=$(cat "${SSH_KEY}.pub")
    
    log "Enabling SSH access for $name..."
    limactl_cmd shell "$name" -- bash -c "
        mkdir -p ~/.ssh
        chmod 700 ~/.ssh
        touch ~/.ssh/authorized_keys
        chmod 600 ~/.ssh/authorized_keys
        grep -qF '$pubkey' ~/.ssh/authorized_keys || echo '$pubkey' >> ~/.ssh/authorized_keys
    "
}

# Build limguard binaries for Linux (VMs) and Darwin (local)
build_binaries() {
    log "Building limguard binaries..."
    
    # Detect architecture
    local arch="arm64"
    if [[ $(uname -m) == "x86_64" ]]; then
        arch="amd64"
    fi
    
    LINUX_BINARY_PATH="$TMPDIR/limguard-linux-$arch"
    DARWIN_BINARY_PATH="$TMPDIR/limguard-darwin-$arch"
    
    log "Building $LINUX_BINARY_PATH..."
    cd "$PROJECT_ROOT"
    GOOS=linux GOARCH=$arch go build -o "$LINUX_BINARY_PATH" ./cmd/limguard/
    
    log "Building $DARWIN_BINARY_PATH..."
    GOOS=darwin GOARCH=$arch go build -o "$DARWIN_BINARY_PATH" ./cmd/limguard/
    
    log "Binaries built"
}

# Create test config
create_config() {
    local ssh_port1=$1
    local ssh_port2=$2
    local endpoint1=$3
    local endpoint2=$4
    local local_endpoint=$5
    local username
    
    if [[ -n "${SUDO_USER:-}" ]]; then
        username="$SUDO_USER"
    else
        username=$(whoami)
    fi
    
    log "Creating test config..."
    cat > "$TMPDIR/limguard.yaml" << EOF
linuxInterfaceName: wg0
darwinInterfaceName: utun9

nodes:
  $NODE1:
    wireguardIP: "$WG_IP1"
    endpoint: "$endpoint1:51820"
    localBinaryPath: "$LINUX_BINARY_PATH"
    ssh:
      host: "127.0.0.1"
      port: $ssh_port1
      user: "$username"
      identityFile: $SSH_KEY

  $NODE2:
    wireguardIP: "$WG_IP2"
    endpoint: "$endpoint2:51820"
    localBinaryPath: "$LINUX_BINARY_PATH"
    ssh:
      host: "127.0.0.1"
      port: $ssh_port2
      user: "$username"
      identityFile: $SSH_KEY

  $LOCAL_NODE:
    wireguardIP: "$WG_IP_LOCAL"
    endpoint: "$local_endpoint:51821"
    interfaceName: utun9
    localBinaryPath: "$DARWIN_BINARY_PATH"
    ssh:
      host: self
EOF
    
    log "Config written to $TMPDIR/limguard.yaml"
}

# Run limguard apply
run_apply() {
    log "Running limguard apply..."
    cd "$PROJECT_ROOT"
    go run ./cmd/limguard/ apply --config "$TMPDIR/limguard.yaml"
}

# Check service status
check_service() {
    local name=$1
    
    log "Checking service status on $name..."
    if [[ "$name" == "$LOCAL_NODE" ]]; then
        if launchctl print system/com.limrun.limguard &>/dev/null; then
            log "Service on $name is active"
        else
            error "Service on $name is not active"
            cat /var/log/limguard.log 2>/dev/null | tail -20 || true
            return 1
        fi
    else
        local status
        status=$(limactl_cmd shell "$name" -- sudo systemctl is-active limguard)
        if [[ "$status" == "active" ]]; then
            log "Service on $name is active"
        else
            error "Service on $name is not active: $status"
            limactl_cmd shell "$name" -- sudo journalctl -u limguard -n 20 --no-pager
            return 1
        fi
    fi
}

# Main
main() {
    log "Starting integration test with local node..."
    
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
    
    # Step 2: Get VM info
    SSH_PORT1=$(get_ssh_port "$NODE1")
    SSH_PORT2=$(get_ssh_port "$NODE2")
    ENDPOINT1=$(get_vm_ip "$NODE1")
    ENDPOINT2=$(get_vm_ip "$NODE2")
    LOCAL_ENDPOINT=$(get_local_ip)
    
    log "Node 1: SSH port=$SSH_PORT1, endpoint=$ENDPOINT1"
    log "Node 2: SSH port=$SSH_PORT2, endpoint=$ENDPOINT2"
    log "Local: endpoint=$LOCAL_ENDPOINT"
    
    # Step 3: Enable SSH access in parallel
    log "Enabling SSH access in parallel..."
    enable_ssh_access "$NODE1" &
    pid1=$!
    enable_ssh_access "$NODE2" &
    pid2=$!
    wait $pid1 $pid2
    
    # Step 4: Build binaries
    build_binaries
    
    # Step 5: Create config
    create_config "$SSH_PORT1" "$SSH_PORT2" "$ENDPOINT1" "$ENDPOINT2" "$LOCAL_ENDPOINT"
    
    # Step 6: Run apply (uses local binaries)
    run_apply
    
    # Step 7: Check services
    check_service "$NODE1"
    check_service "$NODE2"
    check_service "$LOCAL_NODE"
    
    echo ""
    log "========================================="
    log "Integration test with local node PASSED!"
    log "========================================="
}

main "$@"
