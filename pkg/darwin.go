//go:build darwin

package limguard

import (
	"context"
	"fmt"
	"os/exec"
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
func (nm *DarwinNetworkManager) SetWireguardIP(ip string) error {
	// On macOS, we use ifconfig to set the address
	// Format: ifconfig <interface> inet <local_ip> <remote_ip> netmask 255.255.255.255
	// For point-to-point interfaces, we set the same IP for both local and remote

	// First check if the address is already set
	out, err := exec.Command("ifconfig", nm.InterfaceName).Output()
	if err != nil {
		return fmt.Errorf("failed to get interface info: %w", err)
	}

	// Check if our IP is already configured
	if strings.Contains(string(out), ip) {
		return nil // Already set, idempotent success
	}

	// Set the address using ifconfig
	// For WireGuard on macOS, we set it as a point-to-point interface
	if out, err := exec.Command("ifconfig", nm.InterfaceName, "inet", ip, ip, "netmask", "255.255.255.255").CombinedOutput(); err != nil {
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
	if out, err := exec.Command("route", "-n", "get", wireguardIp).CombinedOutput(); err != nil || !strings.Contains(string(out), wireguardIp) {
		// Route doesn't exist or lookup failed, add it
		if out, err := exec.Command("route", "-n", "add", "-host", wireguardIp, "-interface", nm.InterfaceName).CombinedOutput(); err != nil {
			outStr := string(out)
			// Ignore "route already exists" errors (race condition)
			if !strings.Contains(strings.ToLower(outStr), "exists") {
				return fmt.Errorf("failed to add route: %s: %w", outStr, err)
			}
		}
		nm.log.Info("added route for peer", "peerIP", wireguardIp)
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
