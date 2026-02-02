# limguard - WireGuard Mesh Network Manager

`limguard` sets up an encrypted VPC for your cluster using WireGuard.
Once set up, you can then use any CNI like Calico, Cilium etc to work
with `wg0` interface to run on this fabric.

The best use cases are the public nodes where you'd like your inter-node
communication to be over private network and encrypted.

## Installation

### macOS (Homebrew)

```bash
brew install limrun-inc/limguard/limguard
```

### Linux

```bash
ARCH=amd64
curl -Lo limguard https://github.com/limrun-inc/limguard/releases/latest/download/limguard-linux-${ARCH}
chmod +x limguard
sudo mv limguard /usr/local/bin/
```

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

Once deployed, the mesh network is established and the daemon watches for
routes that your CNI adds and makes sure WireGuard is aware of them as well,
which means pod & service CIDRs work just as if all is in the same private
network.

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
    ssh:
      host: self    # Special value: no SSH, configure locally
```

Run:
```bash
limguard apply --config limguard.yaml --local-wireguard-conf-path ops-laptop.conf
```

It will write a WireGuard config at `ops-laptop.conf` that you
can import in your WireGuard GUI and connect the network.

Once you're done, you can mark `ops-laptop` for deletion so that its public
key is removed from the nodes:

```yaml
nodes:
  ops-laptop:
    action: Delete
    ...
```

Run:
```bash
limguard apply --config limguard.yaml
```

## How It Works

- Each node runs `limguard run` as a service
- The daemon loads config on startup and configures WireGuard peers
- To update peers, restart the service after updating the config file
- Routes through the WireGuard interface are synced to allowed IPs.
  - Allowed IPs include the CIDRs your CNI adds on the host so you have
    full network capabilities of a LAN.

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

## Troubleshooting

See [`OPERATIONS.md`](./OPERATIONS.md) for helpful tips.

## License

MIT
