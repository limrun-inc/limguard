#!/bin/bash
# Generate a WireGuard bootstrap script by reading peer info from an existing node.
# Run this on a node that's already part of the WireGuard mesh.
#
# This script reads the current WireGuard configuration using 'wg show' and
# generates a bootstrap script for a node that needs to rejoin the mesh.
#
# Usage:
#   ./generate-bootstrap-from-wg.sh --target-ip <public-ip> --target-wg-ip <wg-ip> [--self-pod-cidr <cidr>]
#
# Example:
#   ./generate-bootstrap-from-wg.sh --target-ip 37.27.118.220 --target-wg-ip 10.200.0.1 --self-pod-cidr 10.244.X.0/26 > bootstrap.sh
#   scp bootstrap.sh root@37.27.118.220:
#   ssh root@37.27.118.220 'bash bootstrap.sh'

set -euo pipefail

# Configuration
INTERFACE_NAME="${INTERFACE_NAME:-wg0}"
TARGET_IP=""
TARGET_WG_IP=""
SELF_POD_CIDR=""

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --target-ip)
      TARGET_IP="$2"
      shift 2
      ;;
    --target-wg-ip)
      TARGET_WG_IP="$2"
      shift 2
      ;;
    --self-pod-cidr)
      SELF_POD_CIDR="$2"
      shift 2
      ;;
    --interface)
      INTERFACE_NAME="$2"
      shift 2
      ;;
    -h|--help)
      echo "Usage: $0 --target-ip <public-ip> --target-wg-ip <wireguard-ip> --self-pod-cidr <cidr>"
      echo ""
      echo "Options:"
      echo "  --target-ip <ip>       Public IP of the node to bootstrap (required)"
      echo "  --target-wg-ip <ip>    WireGuard IP of the target node (required)"
      echo "  --self-pod-cidr <cidr> Pod CIDR(s) of this node, comma-separated (optional)"
      echo "  --interface <name>     WireGuard interface name (default: wg0)"
      echo ""
      echo "Example:"
      echo "  $0 --target-ip 37.27.118.220 --target-wg-ip 10.200.0.1 --self-pod-cidr 10.244.160.64/26"
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      echo "Usage: $0 --target-ip <public-ip> --target-wg-ip <wireguard-ip>" >&2
      exit 1
      ;;
  esac
done

if [ -z "$TARGET_IP" ]; then
  echo "ERROR: --target-ip is required" >&2
  echo "Usage: $0 --target-ip <public-ip> --target-wg-ip <wireguard-ip>" >&2
  exit 1
fi

if [ -z "$TARGET_WG_IP" ]; then
  echo "ERROR: --target-wg-ip is required" >&2
  echo "Usage: $0 --target-ip <public-ip> --target-wg-ip <wireguard-ip>" >&2
  exit 1
fi

# Check wg command is available
if ! command -v wg &> /dev/null; then
  echo "ERROR: 'wg' command not found. Install wireguard-tools." >&2
  exit 1
fi

# Get our own info from the first line of dump (interface line)
# Format: <private-key> <public-key> <listen-port> <fwmark>
IFS=$'\t' read -r _ OUR_PUBLIC_KEY OUR_LISTEN_PORT _ < <(wg show wg0 dump | head -1)
OUR_WG_IP=$(ip addr show wg0 | grep -oP 'inet \K[0-9.]+')
THIS_NODE_ENDPOINT=$(ip route get 1.1.1.1 | grep -oP 'src \K[0-9.]+' | head -1)

# Use provided pod CIDR or try to auto-detect
OUR_POD_CIDR="$SELF_POD_CIDR"
if [ -z "$OUR_POD_CIDR" ]; then
  # Try to detect from blackhole routes (Calico adds these for local pod CIDR)
  OUR_POD_CIDR=$(ip route | grep -E '^blackhole.*proto (bird|kernel)' | awk '{print $2}' | head -1)
fi
if [ -z "$OUR_POD_CIDR" ]; then
  # Try to detect from tunl0 interface (Calico IPIP mode)
  OUR_POD_CIDR=$(ip route | grep 'dev tunl0' | grep -v 'via' | awk '{print $1}' | grep '/' | head -1)
fi
if [ -n "$OUR_POD_CIDR" ]; then
  OUR_ALLOWED_IPS="$OUR_WG_IP/32,$OUR_POD_CIDR"
  echo "# Auto-detected pod CIDR: $OUR_POD_CIDR" >&2
else
  OUR_ALLOWED_IPS="$OUR_WG_IP/32"
  echo "# WARNING: Could not detect pod CIDR. Use --self-pod-cidr to specify it." >&2
fi

# Output the bootstrap script
cat << EOF
#!/bin/bash
# Generated WireGuard bootstrap script
# Run this on the target node to rejoin the WireGuard mesh
set -euo pipefail

# Create interface if it doesn't exist
if ! ip link show wg0 &> /dev/null; then
  echo "Creating WireGuard interface wg0..."
  ip link add wg0 type wireguard
fi

# Configure interface (requires private key at /etc/limguard/privatekey)
if [ -f /etc/limguard/privatekey ]; then
  wg set wg0 private-key /etc/limguard/privatekey listen-port $OUR_LISTEN_PORT
else
  echo "ERROR: /etc/limguard/privatekey not found"
  echo "Create it with:"
  echo "  mkdir -p /etc/limguard"
  echo "  wg genkey > /etc/limguard/privatekey"
  echo "  chmod 600 /etc/limguard/privatekey"
  echo ""
  echo "Then update the node annotation with the new public key:"
  echo "  kubectl annotate node <node-name> limguard.limrun.com/public-key=\\\$(wg pubkey < /etc/limguard/privatekey) --overwrite"
  exit 1
fi

# Add our WireGuard IP to interface
ip addr add $TARGET_WG_IP/32 dev wg0 2>/dev/null || true

# Bring interface up
ip link set wg0 up

echo "Adding peers..."

EOF

# Add this node (the one running the script) as a peer
echo "# Peer: this-node ($OUR_WG_IP)"
echo "wg set wg0 peer '$OUR_PUBLIC_KEY' endpoint '$THIS_NODE_ENDPOINT:$OUR_LISTEN_PORT' allowed-ips '$OUR_ALLOWED_IPS' persistent-keepalive 25"
echo "ip route add $OUR_WG_IP/32 dev wg0 2>/dev/null || true"
if [ -n "$OUR_POD_CIDR" ]; then
  # Handle multiple comma-separated CIDRs
  IFS=',' read -ra cidr_list <<< "$OUR_POD_CIDR"
  for cidr in "${cidr_list[@]}"; do
    echo "ip route add $cidr via $OUR_WG_IP dev wg0 2>/dev/null || true"
  done
fi
echo ""

# Add all other peers (except the target node itself)
# Skip the first line (interface info) with tail -n +2
while IFS=$'\t' read -r pub_key _ endpoint allowed_ips _ _ _ _; do
  
  # Skip the target node itself
  if [[ "$endpoint" == "$TARGET_IP:"* ]]; then
    continue
  fi
  
  # Extract WireGuard IP (the /32 entry from allowed IPs) for the route
  wg_ip=""
  IFS=',' read -ra ip_list <<< "$allowed_ips"
  for ip in "${ip_list[@]}"; do
    if [[ "$ip" == */32 ]]; then
      wg_ip="${ip%/32}"
      break
    fi
  done
  
  # Skip if missing required info
  if [ -z "$endpoint" ] || [ "$endpoint" = "(none)" ] || [ -z "$wg_ip" ]; then
    echo "# WARNING: Skipping peer $pub_key - missing endpoint or WG IP" >&2
    continue
  fi
  
  echo "# Peer: $wg_ip"
  echo "wg set wg0 peer '$pub_key' endpoint '$endpoint' allowed-ips '$allowed_ips' persistent-keepalive 25"
  echo "ip route add $wg_ip/32 dev wg0 2>/dev/null || true"
  # Add routes for pod CIDRs (non-/32 entries)
  for ip in "${ip_list[@]}"; do
    if [[ "$ip" != */32 ]]; then
      echo "ip route add $ip via $wg_ip dev wg0 2>/dev/null || true"
    fi
  done
  echo ""
done < <(wg show wg0 dump | tail -n +2)

cat << 'EOF'
echo ""
echo "Bootstrap complete!"
echo "Verify with: wg show"
echo "Test connectivity: ping <peer-wg-ip>"
echo ""
echo "Don't forget to update the node's public-key annotation if you generated a new key:"
echo "  kubectl annotate node <node-name> limguard.limrun.com/public-key=\$(wg pubkey < /etc/limguard/privatekey) --overwrite"
EOF
