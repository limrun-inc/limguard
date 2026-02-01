# Testing limguard

This guide covers testing limguard using Lima VMs on macOS.

## Prerequisites

- Go 1.21+
- Lima (`brew install lima`)
- socket_vmnet for shared networking (see [tests/README.md](tests/README.md) for full setup)
- SSH key pair (`~/.ssh/id_ed25519` or `~/.ssh/id_rsa`)

## Integration Tests

### Basic Integration Test (Two VMs)

Deploys limguard to two Lima VMs and verifies mesh connectivity:

```bash
./tests/integration.sh
```

The test will:
1. Create two Lima VMs (`limguard-test-1`, `limguard-test-2`)
2. Build and deploy limguard to both VMs
3. Verify mesh connectivity between VMs
4. Clean up VMs

To keep VMs for debugging:

```bash
CLEANUP=0 ./tests/integration.sh
```

### Integration Test with Local Node

Deploys limguard to two Lima VMs **plus your local machine**:

```bash
sudo ./tests/integration-local.sh
```

**Note:** This test requires root because it installs limguard as a service on your machine.

The test will:
1. Create two Lima VMs
2. Build binaries for Linux (VMs) and your local OS
3. Deploy limguard to VMs and local machine (using `ssh.host: self`)
4. Verify full mesh connectivity (VMs ↔ VMs ↔ local)
5. Clean up VMs and local service

To keep everything for debugging:

```bash
CLEANUP=0 sudo ./tests/integration-local.sh
```

### Manual Cleanup

If you used `CLEANUP=0` or the test failed, clean up manually:

```bash
# VMs
limactl stop limguard-test-1 limguard-test-2
limactl delete limguard-test-1 limguard-test-2

# Local service (macOS)
sudo launchctl unload /Library/LaunchDaemons/com.limrun.limguard.plist
sudo rm /Library/LaunchDaemons/com.limrun.limguard.plist
sudo rm -rf /etc/limguard

# Local service (Linux)
sudo systemctl stop limguard
sudo systemctl disable limguard
sudo rm /etc/systemd/system/limguard.service
sudo systemctl daemon-reload
sudo rm -rf /etc/limguard
```

### Unit Tests

Run unit tests (no VMs required):

```bash
go test -v ./...
```

## Manual Testing

### 1. Create Lima VMs

Create two Ubuntu VMs with user-v2 networking (enables VM-to-VM communication):

```bash
# Create and start node-1
limactl create --name=node-1 template://ubuntu-lts --cpus=1 --memory=1 --vm-type=vz --network=lima:user-v2 --yes

# Create and start node-2
limactl create --name=node-2 template://ubuntu-lts --cpus=1 --memory=1 --vm-type=vz --network=lima:user-v2 --yes

# Start the VMs
limactl start node-1
limactl start node-2
```

### 2. Get VM Information

Get the endpoint and SSH information to use in config file:

```bash
# Get SSH connection info for each VM
# Look for the -o Port=XXXXX in the output
echo "SSH information for node-1:"
echo "127.0.0.1:$(limactl show-ssh node-1 2>/dev/null | grep -o 'Port=[0-9]*' | cut -d= -f2)"
echo "Endpoint for node-1: $(limactl shell node-1 -- ip addr show eth0 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)"

echo "SSH information for node-2:"
echo "127.0.0.1:$(limactl show-ssh node-2 2>/dev/null | grep -o 'Port=[0-9]*' | cut -d= -f2)"

echo "Endpoing for node-2: $(limactl shell node-2 -- ip addr show eth0 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)"
```

Note both the SSH ports and VM IPs.

### 3. Enable SSH Access

Copy your SSH key to each VM:

```bash
# Copy SSH keys
limactl shell node-1 -- bash -c "mkdir -p ~/.ssh && echo '$(cat ~/.ssh/id_ed25519.pub)' >> ~/.ssh/authorized_keys && chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys"
limactl shell node-2 -- bash -c "mkdir -p ~/.ssh && echo '$(cat ~/.ssh/id_ed25519.pub)' >> ~/.ssh/authorized_keys && chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys"
```

### 4. Build limguard Binaries

```bash
# From the limguard repo root
mkdir -p dist

# Build for Linux ARM64 (Lima on Apple Silicon)
GOOS=linux GOARCH=arm64 go build -o dist/limguard-linux-arm64 ./cmd/limguard/

# Build for Linux AMD64 (Lima on Intel Mac)
GOOS=linux GOARCH=amd64 go build -o dist/limguard-linux-amd64 ./cmd/limguard/
```

### 5. Create Test Config

Create `test-limguard.yaml` with the values from step 2:

```yaml
interfaceName: wg0
listenPort: 51820
privateKeyPath: /etc/limguard/privatekey
binaryPath: /usr/local/bin/limguard
artifactDir: ./dist

nodes:
  node-1:
    wireguardIP: "10.200.0.1"
    endpoint: "VM_IP_1"          # VM IP from step 2 (e.g., 192.168.104.2)
    publicKey: ""
    ssh:
      host: "127.0.0.1"          # Lima uses localhost
      port: SSH_PORT_1           # SSH port from step 2 (e.g., 55928)
      user: "YOUR_USERNAME"      # Your macOS username
      identityFile: ~/.ssh/id_ed25519

  node-2:
    wireguardIP: "10.200.0.2"
    endpoint: "VM_IP_2"          # VM IP from step 2 (e.g., 192.168.104.3)
    publicKey: ""
    ssh:
      host: "127.0.0.1"          # Lima uses localhost
      port: SSH_PORT_2           # SSH port from step 2 (e.g., 55935)
      user: "YOUR_USERNAME"      # Your macOS username
      identityFile: ~/.ssh/id_ed25519
```

Replace:
- `VM_IP_1`, `VM_IP_2` with the VM IPs from step 2
- `SSH_PORT_1`, `SSH_PORT_2` with the SSH ports from step 2
- `YOUR_USERNAME` with your macOS username

### 6. Run Apply

```bash
go run ./cmd/limguard/ apply --config test-limguard.yaml
```

### 7. Verify the Mesh

```bash
# Ping node-2 from node-1 via WireGuard tunnel
limactl shell node-1 -- ping -c 3 10.200.0.2

# Ping node-1 from node-2 via WireGuard tunnel
limactl shell node-2 -- ping -c 3 10.200.0.1
```

### 8. Check Service Status

```bash
# Check limguard service status
limactl shell node-1 -- sudo systemctl status limguard --no-pager
limactl shell node-2 -- sudo systemctl status limguard --no-pager

# View logs
limactl shell node-1 -- sudo journalctl -u limguard -n 20 --no-pager
```

### 9. Cleanup

```bash
# Stop and delete VMs
limactl stop node-1
limactl stop node-2
limactl delete node-1
limactl delete node-2

# Remove test config
rm test-limguard.yaml
```

## Troubleshooting

### WireGuard module not loaded

```bash
# On the VM, load the WireGuard kernel module
sudo modprobe wireguard
```

### Permission denied errors

Ensure your SSH key is copied to the VMs and the user has sudo access without password:

```bash
limactl shell node-1 -- sudo bash -c 'echo "$(whoami) ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/lima-user'
```

### Service fails to start

Check the logs:

```bash
limactl shell node-1 -- sudo journalctl -u limguard -n 50 --no-pager
```

### Ping fails between nodes

1. Check WireGuard is running: `sudo wg show`
2. Check the interface has the correct IP: `ip addr show wg0`
3. Verify VMs can reach each other on endpoint IPs: `ping <other-vm-ip>`
4. Check firewall rules: `sudo iptables -L -n`
