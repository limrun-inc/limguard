# Operations

## Manual Installation

If not using `limguard deploy`:

### Linux (systemd)

```bash
# Install binary
sudo cp limguard /usr/local/bin/
sudo chmod +x /usr/local/bin/limguard

# Create config directory
sudo mkdir -p /etc/limguard

# Create systemd service
sudo tee /etc/systemd/system/limguard.service << 'EOF'
[Unit]
Description=limguard WireGuard mesh network manager
After=network-online.target
Before=kubelet.service

[Service]
ExecStartPre=/sbin/modprobe wireguard || true
ExecStart=/usr/local/bin/limguard run --config /etc/limguard/limguard.yaml --node-name %H
Restart=always
RestartSec=5
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable --now limguard
```

### macOS (launchd)

```bash
# Install wireguard-go
brew install wireguard-go

# Install binary
sudo cp limguard /usr/local/bin/

# Create config directory
sudo mkdir -p /etc/limguard

# Create launchd plist
sudo tee /Library/LaunchDaemons/com.limrun.limguard.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.limrun.limguard</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/limguard</string>
        <string>run</string>
        <string>--config</string>
        <string>/etc/limguard/limguard.yaml</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
EOF

# Load service
sudo launchctl load /Library/LaunchDaemons/com.limrun.limguard.plist
```

## Adding a Node

1. Add the node to your `limguard.yaml`:
   ```yaml
   nodes:
     new-node:
       wireguardIP: "10.200.0.10"
       endpoint: "203.0.113.20"
       ssh:
         host: "203.0.113.20"
         user: root
   ```

2. Run deploy:
   ```bash
   limguard deploy --config limguard.yaml
   ```

## Removing a Node

1. Remove from `limguard.yaml`
2. Copy updated config to all remaining nodes
3. Daemons will automatically remove the peer on reload

## Key Rotation

1. Stop daemon on the node
2. Remove peer from all other nodes:
   ```bash
   wg set wg0 peer OLD_PUBLIC_KEY remove
   ```
3. Generate new key:
   ```bash
   rm /etc/limguard/privatekey
   wg genkey > /etc/limguard/privatekey
   chmod 600 /etc/limguard/privatekey
   ```
4. Update `publicKey` in config on all nodes
5. Restart daemon

## Troubleshooting

Check status:
```bash
# Linux
systemctl status limguard
journalctl -u limguard -f

# macOS
tail -f /var/log/limguard.log

# Both
wg show
```

Common issues:
- **No handshake**: Check UDP 51820 is open, public keys match
- **Interface missing**: Ensure wireguard module loaded (Linux) or wireguard-go installed (macOS)
- **Config not reloading**: Check file permissions, restart daemon

## Health Checks

```bash
curl http://localhost:8081/healthz
curl http://localhost:8081/readyz
```

## Backup

Only the private key needs backup:
```bash
/etc/limguard/privatekey
```

If lost, follow key rotation procedure.
