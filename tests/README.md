# Integration Tests

This directory contains integration tests for limguard using Lima VMs.

## Prerequisites

### 1. Install Lima & Wireguard

```bash
brew install lima wireguard-tools
```

### 2. Install and Configure socket_vmnet

socket_vmnet provides shared networking for Lima VMs, enabling host ↔ VM and VM ↔ VM communication.

```bash
# Install socket_vmnet
brew install socket_vmnet

# Copy binary to expected location with root ownership (Lima requires root-owned binary)
sudo mkdir -p /opt/socket_vmnet/bin
sudo cp $(brew --prefix socket_vmnet)/bin/socket_vmnet /opt/socket_vmnet/bin/socket_vmnet
sudo chown root:wheel /opt/socket_vmnet/bin/socket_vmnet

# Configure sudoers for Lima networking
limactl sudoers > etc_sudoers.d_lima
sudo install -o root etc_sudoers.d_lima /private/etc/sudoers.d/lima
rm etc_sudoers.d_lima

# Start socket_vmnet service
sudo brew services start socket_vmnet
```

### 3. SSH Key

Ensure you have an SSH key at `~/.ssh/id_ed25519` or `~/.ssh/id_rsa`.

## Running Tests

### End-to-End Test (Two VMs + Local Node)

Tests the full limguard lifecycle:
1. **Initial deployment**: Deploys limguard to two Lima VMs, generates WireGuard config for local node
2. **Connectivity test**: Uses `wg-quick` to bring up local WireGuard interface and ping all peers
3. **Node deletion**: Marks one VM for deletion, runs apply, verifies the peer is removed from remaining nodes

```bash
sudo ./e2e.sh
```

## Options

Keep VMs after test for debugging:

```bash
sudo CLEANUP=0 ./e2e.sh
```

## Manual Cleanup

If tests fail or you used `CLEANUP=0`:

```bash
# Delete test VMs
limactl delete --force limguard-test-1 limguard-test-2
```
