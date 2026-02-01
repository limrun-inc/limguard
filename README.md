# limguard - WireGuard Mesh Network Manager

`limguard` sets up WireGuard peers between nodes using a single YAML config file.
It runs as a systemd/launchd service and can be deployed before Kubernetes.

## Quick Start

### 1. Build binaries

```bash
GOOS=linux GOARCH=amd64 go build -o dist/limguard-linux-amd64 ./cmd
GOOS=linux GOARCH=arm64 go build -o dist/limguard-linux-arm64 ./cmd
GOOS=darwin GOARCH=arm64 go build -o dist/limguard-darwin-arm64 ./cmd
```

### 2. Create config

```yaml
# limguard.yaml
artifactDir: ./dist

nodes:
  node-1:
    wireguardIP: "10.200.0.1"
    endpoint: "203.0.113.10"
    ssh:
      host: "203.0.113.10"
      user: root

  node-2:
    wireguardIP: "10.200.0.2"
    endpoint: "203.0.113.11"
    ssh:
      host: "203.0.113.11"
      user: root
```

### 3. Deploy

```bash
limguard deploy --config limguard.yaml
```

This:
1. Installs binary on each node
2. Generates WireGuard keys and brings up interface
3. Collects public keys and updates your local YAML
4. Distributes the complete config to all nodes
5. Starts the daemon on all nodes

## Config Format

One YAML file used everywhere:

```yaml
# Optional (defaults shown)
interfaceName: wg0              # utun5 on macOS
listenPort: 51820
privateKeyPath: /etc/limguard/privatekey
binaryPath: /usr/local/bin/limguard

# Required for deploy
artifactDir: ./dist

# All nodes
nodes:
  node-name:
    wireguardIP: "10.200.0.1"   # WireGuard mesh IP
    endpoint: "203.0.113.10"    # Public IP/hostname
    publicKey: "..."            # Filled in by deploy
    ssh:                        # Only needed for deploy
      host: "203.0.113.10"
      port: 22
      user: root

  # Local node (join mesh from this machine)
  ops-laptop:
    wireguardIP: "10.200.0.50"
    endpoint: "203.0.113.50"
    ssh:
      host: self               # Special value: configure locally, no SSH
```

## Commands

```bash
limguard apply --config limguard.yaml   # Deploy to all nodes
limguard run --config /etc/limguard/limguard.yaml  # Run daemon
```

## Joining the Mesh Locally

You can temporarily join the mesh from your local machine (e.g., for operations):

```yaml
nodes:
  ops-laptop:
    wireguardIP: "10.200.0.50"
    endpoint: "your.public.ip"
    ssh:
      host: self    # Special value: no SSH, configure locally
```

Run with root privileges:
```bash
sudo limguard apply --config limguard.yaml
```

To disconnect, remove the node from config and re-run `apply`. Other nodes will automatically remove it as a peer.

## How It Works

- Each node runs `limguard run` as a service
- The daemon watches `/etc/limguard/limguard.yaml` for changes
- When config changes, it reconciles peers (add/update/remove)
- Routes through the WireGuard interface are synced to allowed IPs

## Manual Setup

If not using `deploy`, see [OPERATIONS.md](./OPERATIONS.md) for manual installation steps.

## License

MIT
