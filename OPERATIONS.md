# Operations

## Joining the Mesh from Your Laptop

To temporarily join the mesh from your local machine for debugging or operations:

1. Add a local node to your `limguard.yaml`:
   ```yaml
   nodes:
     ops-laptop:
       wireguardIP: "10.200.0.50"
       ssh:
         host: self
   ```

2. Run apply:
   ```bash
   limguard apply --config limguard.yaml
   ```

3. Import the generated `ops-laptop-peer.conf` into WireGuard app (macOS, Windows, iOS, Android)

4. Activate the tunnel in the WireGuard app

## Leaving the Mesh

1. Deactivate the tunnel in the WireGuard app

2. Mark your node for deletion in `limguard.yaml`:
   ```yaml
   nodes:
     ops-laptop:
       action: Delete
       wireguardIP: "10.200.0.50"
       ssh:
         host: self
   ```

3. Run apply to remove yourself from all remote nodes:
   ```bash
   limguard apply --config limguard.yaml
   ```

4. After successful apply, you can remove the node entry from the config entirely

## Inspecting Nodes

### Service Status

```bash
# Linux
systemctl status limguard
journalctl -u limguard -f

# macOS
cat /var/log/limguard.log
```

### WireGuard Status

```bash
# Show interface and all peers
wg show

# Show just the public key
wg show wg0 public-key
```

### Config and Keys

```bash
# View config
cat /etc/limguard/limguard.yaml

# View public key
cat /etc/limguard/privatekey.pub
```

### Network

```bash
# Check interface exists
ip addr show wg0          # Linux
ifconfig utun9            # macOS

# Ping a peer
ping 10.200.0.1

# Check routes
ip route | grep wg0       # Linux
netstat -rn | grep utun9  # macOS
```

## Common Issues

| Symptom | Check |
|---------|-------|
| No handshake | UDP 51820 open? Public keys match? |
| Interface missing | `modprobe wireguard` (Linux) or `brew install wireguard-go` (macOS) |
| Peers not updating | Restart service after config change |
