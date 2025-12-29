//go:build darwin

package limguard

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/crossplane/crossplane-runtime/pkg/logging"
)

// DarwinNetworkManager implements NetworkManager for macOS using ifconfig, route, and wg commands.
type DarwinNetworkManager struct {
	// InterfaceName is the WireGuard interface name (e.g., "utun5")
	InterfaceName string

	peerIPList   map[string]*Peer
	peerIPListMu *sync.RWMutex

	log logging.Logger
}

// NewNetworkManager creates a new DarwinNetworkManager.
// It creates the WireGuard interface using wireguard-go, configures it with the private key and listen port,
// and brings it up. This should be called once at startup.
func NewNetworkManager(interfaceName, privateKeyPath string, listenPort int, log logging.Logger) (*DarwinNetworkManager, error) {
	nm := &DarwinNetworkManager{
		InterfaceName: interfaceName,
		peerIPList:    make(map[string]*Peer),
		peerIPListMu:  &sync.RWMutex{},
		log:           log,
	}

	// Check if interface already exists using ifconfig
	if _, err := exec.Command("ifconfig", interfaceName).Output(); err != nil {
		// Interface doesn't exist, create it with wireguard-go
		// wireguard-go creates utun interfaces on macOS
		if out, err := exec.Command("wireguard-go", interfaceName).CombinedOutput(); err != nil {
			return nil, fmt.Errorf("failed to create interface with wireguard-go: %s: %w", string(out), err)
		}
		for i := 0; i < 20; i++ { // Max 10 seconds
			if _, err := exec.Command("ifconfig", interfaceName).Output(); err == nil {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		// Verify the interface is now available
		if _, err := exec.Command("ifconfig", interfaceName).Output(); err != nil {
			return nil, fmt.Errorf("interface %s not available after wireguard-go started: %w", interfaceName, err)
		}
	}
	if out, err := exec.Command("wg", "set", interfaceName,
		"listen-port", fmt.Sprintf("%d", listenPort),
		"private-key", privateKeyPath,
	).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to configure WireGuard: %s: %w", string(out), err)
	}
	// Set MTU like wg-quick: default interface MTU minus 80 bytes for WireGuard overhead
	if err := nm.setMTU(); err != nil {
		log.Info("failed to set MTU, using default", "error", err)
	}
	if out, err := exec.Command("ifconfig", interfaceName, "up").CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to bring interface up: %s: %w", string(out), err)
	}

	go func() {
		ticker := time.NewTicker(5 * time.Second)
		for range ticker.C {
			nm.log.Debug("syncing allowed IPs")
			nm.syncAllowedIPs()
		}
	}()

	return nm, nil
}

// SetWireguardIP sets the IP address on the WireGuard interface.
// ip can be in CIDR notation (e.g., "10.0.0.1/24") or just an IP (e.g., "10.0.0.1").
func (nm *DarwinNetworkManager) SetWireguardIP(ip string) error {
	// On macOS, we use ifconfig similar to wg-quick:
	// ifconfig <interface> inet <ip/cidr> <ip> alias
	// The "alias" keyword allows multiple addresses on the interface.
	out, err := exec.Command("ifconfig", nm.InterfaceName).Output()
	if err != nil {
		return fmt.Errorf("failed to get interface info: %w", err)
	}

	// Check if our IP is already configured
	if strings.Contains(string(out), ip) {
		return nil // Already set, idempotent success
	}
	if out, err := exec.Command("ifconfig", nm.InterfaceName, "inet", ip+"/32", ip, "alias").CombinedOutput(); err != nil {
		outStr := string(out)
		// Handle case where address might already exist
		if strings.Contains(strings.ToLower(outStr), "exists") ||
			strings.Contains(strings.ToLower(outStr), "already") {
			return nil
		}
		return fmt.Errorf("failed to set address: %s: %w", outStr, err)
	}
	return nil
}

// SetPeer configures a WireGuard peer and adds a route for its allowed IPs.
func (nm *DarwinNetworkManager) SetPeer(ctx context.Context, publicKey, endpoint, wireguardIp string) error {
	if out, err := exec.CommandContext(ctx, "wg", "show", nm.InterfaceName, "peers").CombinedOutput(); err == nil && !strings.Contains(string(out), publicKey) {
		// The first time we add this peer, so we configure only its own peer IP.
		if out, err := exec.Command("wg", "set", nm.InterfaceName,
			"peer", publicKey,
			"endpoint", endpoint,
			"allowed-ips", wireguardIp+"/32",
			"persistent-keepalive", "25",
		).CombinedOutput(); err != nil {
			return fmt.Errorf("failed to set peer: %s: %w", string(out), err)
		}
		nm.log.Info("added peer for the first time", "publicKey", publicKey, "endpoint", endpoint)
	}

	// Check if route already exists using "route -n get"
	// If the route exists, the command succeeds and shows route info
	// If not, it fails with "not in table" or similar error
	out, err := exec.Command("route", "-n", "get", wireguardIp).CombinedOutput()
	// Keep this intentionally simple: look for "interface:" followed by whitespace and the interface name.
	// (No anchors/multiline needed; `route -n get` output is small and stable.)
	ifaceRe := regexp.MustCompile(`interface:\s*` + regexp.QuoteMeta(nm.InterfaceName) + `(\s|$)`)
	if err != nil || !ifaceRe.Match(out) {
		if out, err := exec.Command("route", "-n", "add", "-host", wireguardIp, "-interface", nm.InterfaceName).CombinedOutput(); err != nil {
			outStr := string(out)
			// Ignore "route already exists" errors (race condition)
			if !strings.Contains(strings.ToLower(outStr), "exists") {
				return fmt.Errorf("failed to add route: %s: %w", outStr, err)
			}
		}
		nm.log.Info("added route for peer", "peerIP", wireguardIp)
	} else {
		nm.log.Debug("route already exists for peer", "peerIP", wireguardIp, "output", string(out))
	}

	nm.peerIPListMu.Lock()
	defer nm.peerIPListMu.Unlock()
	if nm.peerIPList[wireguardIp] != nil {
		nm.peerIPList[wireguardIp].PublicKey = publicKey
		nm.peerIPList[wireguardIp].Endpoint = endpoint
		return nil
	}
	nm.peerIPList[wireguardIp] = &Peer{
		PublicKey:   publicKey,
		Endpoint:    endpoint,
		WireguardIP: wireguardIp,
	}
	return nil
}

// syncAllowedIPs lists routes, builds a map of CIDRs to peer IPs, and updates
// the allowedIPs of WireGuard peers accordingly.
func (nm *DarwinNetworkManager) syncAllowedIPs() {
	ctx := context.Background()

	// On macOS, use netstat -rn to get routing table
	out, err := exec.Command("netstat", "-rn").Output()
	if err != nil {
		nm.log.Debug("failed to get routing table", "error", err)
		return
	}

	// Parse netstat output to find routes through our interface
	// Example netstat -rn output on macOS:
	// Destination        Gateway            Flags        Netif Expire
	// 10.244.23.0/26     10.200.0.18        UGSc         utun5
	peerCIDRs := make(map[string]map[string]struct{})
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Check if this route uses our interface
		// The interface name is typically in the 4th or later column
		interfaceIdx := -1
		for i, field := range fields {
			if field == nm.InterfaceName {
				interfaceIdx = i
				break
			}
		}
		if interfaceIdx == -1 {
			continue
		}

		cidr := fields[0]
		gateway := fields[1]

		// Skip if gateway is not an IP (e.g., "link#N" for direct routes)
		if !isIPAddress(gateway) {
			continue
		}

		// Normalize CIDR - netstat might show just IP without /32
		if !strings.Contains(cidr, "/") {
			cidr = cidr + "/32"
		}

		if peerCIDRs[gateway] == nil {
			peerCIDRs[gateway] = make(map[string]struct{})
		}
		peerCIDRs[gateway][cidr] = struct{}{}
	}

	wg := &sync.WaitGroup{}
	for peerIP := range peerCIDRs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			nm.peerIPListMu.Lock()
			peer, ok := nm.peerIPList[peerIP]
			if !ok {
				nm.log.Info("peer ip detected in routes but not in internal peer map", "peerIP", peerIP)
				nm.peerIPListMu.Unlock()
				return
			}
			nm.peerIPListMu.Unlock()
			allowedIpCidrs := make([]string, len(peerCIDRs[peerIP])+1)
			allowedIpCidrs[0] = peer.WireguardIP + "/32"
			i := 1
			for cidr := range peerCIDRs[peerIP] {
				allowedIpCidrs[i] = cidr
				i++
			}
			allowedIpsStr := strings.Join(allowedIpCidrs, ",")
			out, err := exec.CommandContext(ctx, "wg", "set", nm.InterfaceName,
				"peer", peer.PublicKey,
				"endpoint", peer.Endpoint,
				"allowed-ips", allowedIpsStr,
			).CombinedOutput()
			if err != nil {
				nm.log.Info("failed to update peer allowed IPs", "peerIP", peerIP, "err", string(out))
				return
			}
			nm.log.Debug("updated peer allowed IPs", "peerIP", peerIP, "allowedIPs", allowedIpsStr)
		}()
	}
	wg.Wait()
}

// isIPAddress checks if a string looks like an IP address
func isIPAddress(s string) bool {
	// Simple check - starts with digit and contains dots
	if len(s) == 0 {
		return false
	}
	if s[0] < '0' || s[0] > '9' {
		return false
	}
	return strings.Contains(s, ".")
}

// setMTU sets the MTU on the WireGuard interface.
// Like wg-quick, it calculates MTU as (default interface MTU - 80) to account for WireGuard overhead.
func (nm *DarwinNetworkManager) setMTU() error {
	// Find the default route's interface
	out, err := exec.Command("netstat", "-nr", "-f", "inet").Output()
	if err != nil {
		return fmt.Errorf("failed to get routing table: %w", err)
	}

	var defaultIface string
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[0] == "default" {
			// On macOS netstat -nr -f inet output:
			// Destination        Gateway            Flags               Netif Expire
			// default            192.168.1.1        UGScg                 en0
			defaultIface = fields[3]
			break
		}
	}

	if defaultIface == "" {
		return fmt.Errorf("could not find default interface")
	}

	// Get the MTU of the default interface
	out, err = exec.Command("ifconfig", defaultIface).Output()
	if err != nil {
		return fmt.Errorf("failed to get default interface info: %w", err)
	}

	mtuRegex := regexp.MustCompile(`mtu\s+(\d+)`)
	matches := mtuRegex.FindStringSubmatch(string(out))
	mtu := 1500 // Default fallback
	if len(matches) >= 2 {
		if parsed, err := strconv.Atoi(matches[1]); err == nil && parsed > 0 {
			mtu = parsed
		}
	}

	// Subtract 80 bytes for WireGuard overhead (same as wg-quick)
	wgMTU := mtu - 80

	// Set MTU on our interface
	if out, err := exec.Command("ifconfig", nm.InterfaceName, "mtu", strconv.Itoa(wgMTU)).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set MTU: %s: %w", string(out), err)
	}

	nm.log.Info("set MTU", "interface", nm.InterfaceName, "mtu", wgMTU, "basedOn", defaultIface, "originalMTU", mtu)
	return nil
}
