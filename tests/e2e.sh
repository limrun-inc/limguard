#!/bin/bash
# Integration test: deploys limguard to two Lima VMs and generates a WireGuard
# client config for the local machine, then validates connectivity.
# Usage: sudo ./tests/integration-local.sh              # Clean up after test
#        sudo CLEANUP=0 ./tests/integration-local.sh    # Keep VMs for debugging
#
# Prerequisites:
# - Lima (brew install lima)
# - socket_vmnet (see tests/README.md for setup)
# - WireGuard tools (brew install wireguard-tools)
# - Go 1.24+
# - SSH key (~/.ssh/id_ed25519 or ~/.ssh/id_rsa)
# - sudo access (for wg-quick)

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
    log "Cleaning up..."
    # Bring down WireGuard interface if it's up
    wg-quick down "$TMPDIR/$LOCAL_NODE-peer.conf" 2>/dev/null || true
    
    if [[ "$CLEANUP" == "1" ]]; then
        limactl_cmd stop "$NODE1" 2>/dev/null || true
        limactl_cmd stop "$NODE2" 2>/dev/null || true
        limactl_cmd delete "$NODE1" 2>/dev/null || true
        limactl_cmd delete "$NODE2" 2>/dev/null || true
        rm -rf "$TMPDIR"
    else
        warn "Skipping VM cleanup (CLEANUP=0)"
        warn "Temp dir: $TMPDIR"
        warn "VMs: $NODE1, $NODE2"
        warn "WireGuard config: $TMPDIR/$LOCAL_NODE-peer.conf"
    fi
}

# Run limactl as the original user (limactl refuses to run as root)
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
    
    # Must be run as root (via sudo) for wg-quick
    if [[ $EUID -ne 0 ]]; then
        error "This test must be run as root for WireGuard operations."
        error "Run with: sudo ./tests/integration-local.sh"
        exit 1
    fi
    
    # Need SUDO_USER to run limactl as the original user
    if [[ -z "${SUDO_USER:-}" ]]; then
        error "Please run with sudo (not as root directly)."
        error "Run with: sudo ./tests/integration-local.sh"
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
    
    if ! command -v wg-quick &>/dev/null; then
        error "wg-quick not found. Install with: brew install wireguard-tools"
        exit 1
    fi
    
    # Check socket_vmnet is running (required for shared network)
    if ! pgrep -x socket_vmnet &>/dev/null; then
        error "socket_vmnet not running. See tests/README.md for setup instructions."
        exit 1
    fi
    log "socket_vmnet is running"
    
    # Find SSH key (use original user's home when running as sudo)
    local user_home="$HOME"
    if [[ -n "${SUDO_USER:-}" ]]; then
        user_home=$(eval echo ~"$SUDO_USER")
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

# Create a VM (without starting)
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
}

# Print Lima logs for a VM
print_lima_logs() {
    local name=$1
    local lima_dir
    if [[ -n "${SUDO_USER:-}" ]]; then
        lima_dir=$(eval echo ~"$SUDO_USER")/.lima
    else
        lima_dir="$HOME/.lima"
    fi
    
    error "=== Lima logs for $name ==="
    if [[ -f "$lima_dir/$name/ha.stderr.log" ]]; then
        error "--- ha.stderr.log ---"
        cat "$lima_dir/$name/ha.stderr.log" >&2
    fi
    for serial_log in "$lima_dir/$name"/serial*.log; do
        if [[ -f "$serial_log" ]]; then
            error "--- $(basename "$serial_log") ---"
            tail -100 "$serial_log" >&2
        fi
    done
}

# Start a VM and wait for it to be ready
start_vm() {
    local name=$1
    
    log "Starting VM $name..."
    if ! limactl_cmd start "$name"; then
        error "Failed to start VM $name"
        print_lima_logs "$name"
        return 1
    fi
    
    log "VM $name is ready"
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

# Build limguard binary for Linux (VMs only - local node uses WireGuard GUI)
build_binaries() {
    log "Building limguard binary for Linux..."
    
    # Detect architecture
    local arch="arm64"
    if [[ $(uname -m) == "x86_64" ]]; then
        arch="amd64"
    fi
    
    LINUX_BINARY_PATH="$TMPDIR/limguard-linux-$arch"
    
    cd "$PROJECT_ROOT"
    GOOS=linux GOARCH=$arch go build -o "$LINUX_BINARY_PATH" ./cmd/limguard/
    
    log "Binary built: $LINUX_BINARY_PATH"
}

# Create test config
create_config() {
    local ssh_port1=$1
    local ssh_port2=$2
    local endpoint1=$3
    local endpoint2=$4
    local username
    # Use original user when running as sudo (VMs run as that user)
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
    ssh:
      host: self
EOF
    
    log "Config written to $TMPDIR/limguard.yaml"
}

# Run limguard apply
run_apply() {
    log "Running limguard apply..."
    cd "$PROJECT_ROOT"
    go run ./cmd/limguard/ apply --config "$TMPDIR/limguard.yaml" --local-wireguard-conf-path "$TMPDIR/$LOCAL_NODE-peer.conf"
}

# Check service status on remote nodes
check_service() {
    local name=$1
    
    log "Checking service status on $name..."
    local status
    status=$(limactl_cmd shell "$name" -- sudo systemctl is-active limguard)
    if [[ "$status" == "active" ]]; then
        log "Service on $name is active"
    else
        error "Service on $name is not active: $status"
        limactl_cmd shell "$name" -- sudo journalctl -u limguard -n 20 --no-pager
        return 1
    fi
}

# Test local node connectivity using the generated WireGuard config
test_local_connectivity() {
    local conf_path="$TMPDIR/$LOCAL_NODE-peer.conf"
    
    log "Testing local node connectivity..."
    
    # Verify config was generated
    if [[ ! -f "$conf_path" ]]; then
        error "WireGuard config not found: $conf_path"
        return 1
    fi
    
    # Verify config contains expected sections
    if ! grep -q "\[Interface\]" "$conf_path" || ! grep -q "\[Peer\]" "$conf_path"; then
        error "Config is missing expected sections"
        cat "$conf_path"
        return 1
    fi
    log "WireGuard config generated: $conf_path"
    
    # Bring up WireGuard interface (already running as root)
    log "Bringing up WireGuard interface..."
    wg-quick up "$conf_path"
    
    # Give it a moment to establish
    sleep 2
    
    # Ping all peers
    log "Pinging peers from local node..."
    
    if ping -c 3 -W 2 "$WG_IP1" &>/dev/null; then
        log "Ping to $NODE1 ($WG_IP1) succeeded"
    else
        error "Ping to $NODE1 ($WG_IP1) failed"
        wg show
        return 1
    fi
    
    if ping -c 3 -W 2 "$WG_IP2" &>/dev/null; then
        log "Ping to $NODE2 ($WG_IP2) succeeded"
    else
        error "Ping to $NODE2 ($WG_IP2) failed"
        wg show
        return 1
    fi
    
    log "Local node connectivity verified"
}

# Mark NODE2 for deletion in the config
mark_node_for_deletion() {
    log "Marking $NODE2 for deletion..."
    
    # Use awk to add 'action: Delete' after the NODE2 line
    # Go's YAML library uses 4-space indentation, so node names are at 4 spaces
    # and their properties are at 8 spaces
    local tmp_config="$TMPDIR/limguard.yaml.tmp"
    awk -v node="$NODE2" '
        {print}
        $0 ~ "^    " node ":$" {print "        action: Delete"}
    ' "$TMPDIR/limguard.yaml" > "$tmp_config"
    mv "$tmp_config" "$TMPDIR/limguard.yaml"
    
    log "Config updated with deletion marker"
}

# Run limguard apply for deletion
run_apply_deletion() {
    log "Running limguard apply (deletion pass)..."
    cd "$PROJECT_ROOT"
    
    # Bring down local WireGuard first since config will change
    wg-quick down "$TMPDIR/$LOCAL_NODE-peer.conf" 2>/dev/null || true
    
    go run ./cmd/limguard/ apply --config "$TMPDIR/limguard.yaml" --local-wireguard-conf-path "$TMPDIR/$LOCAL_NODE-peer.conf"
}

# Verify the deleted node's peer is removed from remaining nodes
test_deletion() {
    log "Testing node deletion..."
    
    # Get the public key of the deleted node from config (before it's removed)
    local deleted_pubkey
    deleted_pubkey=$(grep -A5 "$NODE2:" "$TMPDIR/limguard.yaml" | grep "publicKey:" | awk '{print $2}' | tr -d '"')
    
    if [[ -z "$deleted_pubkey" ]]; then
        error "Could not find public key for deleted node"
        return 1
    fi
    log "Deleted node public key: $deleted_pubkey"
    
    # Check that NODE1 no longer has NODE2 as a peer
    log "Checking $NODE1 no longer has $NODE2 as peer..."
    local peers_on_node1
    peers_on_node1=$(limactl_cmd shell "$NODE1" -- sudo wg show wg0 peers 2>/dev/null || echo "")
    
    if echo "$peers_on_node1" | grep -q "$deleted_pubkey"; then
        error "$NODE1 still has deleted peer $NODE2"
        error "Current peers on $NODE1:"
        limactl_cmd shell "$NODE1" -- sudo wg show wg0
        return 1
    fi
    log "$NODE1 no longer has $NODE2 as peer"
    
    # Verify NODE1 service is still running
    check_service "$NODE1"
    
    # Bring up local WireGuard with new config (which should only have NODE1)
    log "Bringing up local WireGuard with updated config..."
    wg-quick up "$TMPDIR/$LOCAL_NODE-peer.conf"
    sleep 2
    
    # Verify local can still reach NODE1
    if ping -c 3 -W 2 "$WG_IP1" &>/dev/null; then
        log "Ping to $NODE1 ($WG_IP1) after deletion succeeded"
    else
        error "Ping to $NODE1 ($WG_IP1) after deletion failed"
        wg show
        return 1
    fi
    
    # Verify local config only has NODE1 as peer (not NODE2)
    local peer_count
    peer_count=$(grep -c "\[Peer\]" "$TMPDIR/$LOCAL_NODE-peer.conf")
    if [[ "$peer_count" -ne 1 ]]; then
        error "Local config should have 1 peer after deletion, found $peer_count"
        cat "$TMPDIR/$LOCAL_NODE-peer.conf"
        return 1
    fi
    log "Local config correctly has only 1 peer after deletion"
    
    log "Node deletion verified successfully"
}

# Main
main() {
    log "Starting integration test with local node..."
    
    check_prerequisites
    
    # Step 1: Create VMs sequentially (avoids race condition in Lima config init)
    create_vm "$NODE1"
    create_vm "$NODE2"
    
    # Step 2: Start VMs in parallel
    log "Starting VMs in parallel..."
    start_vm "$NODE1" &
    pid1=$!
    start_vm "$NODE2" &
    pid2=$!
    
    wait $pid1 || { error "Failed to start $NODE1"; exit 1; }
    wait $pid2 || { error "Failed to start $NODE2"; exit 1; }
    log "Both VMs are ready"
    
    # Step 3: Get VM info
    SSH_PORT1=$(get_ssh_port "$NODE1")
    SSH_PORT2=$(get_ssh_port "$NODE2")
    ENDPOINT1=$(get_vm_ip "$NODE1")
    ENDPOINT2=$(get_vm_ip "$NODE2")
    
    log "Node 1: SSH port=$SSH_PORT1, endpoint=$ENDPOINT1"
    log "Node 2: SSH port=$SSH_PORT2, endpoint=$ENDPOINT2"
    log "Local node: WireGuard client (no daemon)"
    
    # Step 4: Enable SSH access in parallel
    log "Enabling SSH access in parallel..."
    enable_ssh_access "$NODE1" &
    pid1=$!
    enable_ssh_access "$NODE2" &
    pid2=$!
    wait $pid1 $pid2
    
    # Step 5: Build binaries (only Linux needed for VMs)
    build_binaries
    
    # Step 6: Create config
    create_config "$SSH_PORT1" "$SSH_PORT2" "$ENDPOINT1" "$ENDPOINT2"
    
    # Step 7: Run apply
    run_apply
    
    # Step 8: Check services on VMs
    check_service "$NODE1"
    check_service "$NODE2"
    
    # Step 9: Test local node connectivity
    test_local_connectivity
    
    echo ""
    log "========================================="
    log "Initial deployment PASSED!"
    log "========================================="
    echo ""
    
    # Step 10: Test node deletion
    log "Testing node deletion flow..."
    mark_node_for_deletion
    run_apply_deletion
    test_deletion
    
    echo ""
    log "========================================="
    log "All integration tests PASSED!"
    log "========================================="
}

main "$@"
