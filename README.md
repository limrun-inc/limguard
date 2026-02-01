# limguard - WireGuard Mesh Network Manager

`limguard` sets up WireGuard peers between nodes using a single YAML config file.
It runs as a systemd/launchd service and can be deployed before Kubernetes.

## Quick Start

### 1. Create config

```yaml
# limguard.yaml
nodes:
  node-1:
    wireguardIP: "10.200.0.1"
    endpoint: "203.0.113.10:51820"
    ssh:
      host: "203.0.113.10"
      user: root

  node-2:
    wireguardIP: "10.200.0.2"
    endpoint: "203.0.113.11:51820"
    ssh:
      host: "203.0.113.11"
      user: root
```

### 2. Deploy

```bash
limguard apply --config limguard.yaml
```

This:
1. Downloads the correct binary for each node from GitHub releases
2. Installs binary on each node
3. Generates WireGuard keys and brings up interface
4. Collects public keys and updates your local YAML
5. Distributes the complete config to all nodes
6. Starts the daemon on all nodes

## Config Format

One YAML file used everywhere:

```yaml
# Optional (defaults shown)
linuxInterfaceName: wg0     # WireGuard interface on Linux
darwinInterfaceName: utun9  # WireGuard interface on macOS

# Version of limguard to download from GitHub releases.
# If omitted, the latest release is fetched and written back to this file.
# version: v1.0.0

# All nodes
nodes:
  node-name:
    wireguardIP: "10.200.0.1"   # WireGuard mesh IP
    endpoint: "203.0.113.10:51820"  # Public IP/hostname with port
    publicKey: "..."            # Filled in by apply
    # localBinaryPath: /path/to/limguard  # Optional: use local binary instead of downloading
    ssh:                        # Only needed for apply
      host: "203.0.113.10"
      port: 22
      user: root

  # Local node (join mesh from this machine)
  ops-laptop:
    wireguardIP: "10.200.0.50"
    endpoint: "203.0.113.50:51821"
    ssh:
      host: self               # Special value: configure locally, no SSH
```

## Commands

```bash
limguard apply --config limguard.yaml   # Deploy to all nodes
limguard run --config /etc/limguard/limguard.yaml  # Run daemon
limguard version  # Print version
```

## Joining the Mesh Locally

You can temporarily join the mesh from your local machine (e.g., for operations):

```yaml
nodes:
  ops-laptop:
    wireguardIP: "10.200.0.50"
    endpoint: "your.public.ip:51821"
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

## Versioning

By default, `limguard apply` downloads binaries from GitHub releases:

- If `version` is not set in the config, the latest release is fetched
- The resolved version is automatically written back to your config file
- Subsequent runs will use the same version for reproducibility

To upgrade, either:
- Remove the `version` field to fetch the latest
- Set `version: vX.Y.Z` to pin a specific release

## Using Local Binaries

For development or testing, you can use locally built binaries instead of downloading:

```yaml
nodes:
  node-1:
    wireguardIP: "10.200.0.1"
    endpoint: "203.0.113.10:51820"
    localBinaryPath: "/path/to/limguard-linux-arm64"
    ssh:
      host: "203.0.113.10"
```

When `localBinaryPath` is set for a node, that binary is used instead of downloading from GitHub releases. If all nodes have `localBinaryPath` set, version resolution and downloads are skipped entirely.

## Manual Setup

If not using `apply`, see [OPERATIONS.md](./OPERATIONS.md) for manual installation steps.

## License

MIT
