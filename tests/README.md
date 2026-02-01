# Integration Tests

This directory contains integration tests for limguard using Lima VMs.

## Prerequisites

### 1. Install Lima

```bash
brew install lima
```

### 2. Install and Configure socket_vmnet

socket_vmnet provides shared networking for Lima VMs, enabling host ↔ VM and VM ↔ VM communication.

```bash
# Install socket_vmnet
brew install socket_vmnet

# Create hardlink to expected location (Lima rejects symlinks)
sudo mkdir -p /opt/socket_vmnet/bin
sudo ln -f $(brew --prefix socket_vmnet)/bin/socket_vmnet /opt/socket_vmnet/bin/socket_vmnet

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

### Basic Integration Test (Two VMs)

Tests mesh connectivity between two Lima VMs:

```bash
./integration.sh
```

### Integration Test with Local Node

Tests mesh connectivity between two Lima VMs **and** your local machine. Requires root:

```bash
sudo ./integration-local.sh
```

## Options

Keep VMs after test for debugging:

```bash
CLEANUP=0 ./integration.sh
sudo CLEANUP=0 ./integration-local.sh
```

**Note:** For the local test, pass `CLEANUP=0` after `sudo`, not before.

## Manual Cleanup

If tests fail or you used `CLEANUP=0`:

```bash
# Delete test VMs
limactl delete --force limguard-test-1 limguard-test-2
limactl delete --force limguard-local-test-1 limguard-local-test-2

# Remove local service (if integration-local.sh was run)
sudo launchctl unload /Library/LaunchDaemons/com.limrun.limguard.plist 2>/dev/null
sudo rm -f /Library/LaunchDaemons/com.limrun.limguard.plist
sudo rm -f /var/log/limguard.log
sudo rm -rf /usr/local/bin/limguard /etc/limguard
```
