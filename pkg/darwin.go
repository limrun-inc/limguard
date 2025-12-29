//go:build darwin

package limguard

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/crossplane/crossplane-runtime/pkg/logging"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// DarwinNetworkManager implements NetworkManager for macOS using ifconfig, route, and wgctrl.
type DarwinNetworkManager struct {
	InterfaceName string
	WireguardIP   string

	wgClient *wgctrl.Client

	peerIPList   map[string]*Peer
	peerIPListMu *sync.RWMutex

	log logging.Logger
}

// NewNetworkManager creates a new DarwinNetworkManager.
// It creates the WireGuard interface using wireguard-go, configures it with the private key and listen port,
// and brings it up. This should be called once at startup.
func NewNetworkManager(interfaceName, privateKeyPath string, listenPort int, wireguardIp string, log logging.Logger) (*DarwinNetworkManager, error) {
	if _, err := exec.Command("ifconfig", interfaceName).Output(); err != nil {
		// Interface doesn't exist, create it with wireguard-go
		// wireguard-go creates utun interfaces on macOS
		if out, err := exec.Command("/opt/homebrew/bin/wireguard-go", interfaceName).CombinedOutput(); err != nil {
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
	if out, err := exec.Command("ifconfig", interfaceName, "inet", wireguardIp+"/32", wireguardIp, "alias").CombinedOutput(); err != nil {
		outStr := string(out)
		if !strings.Contains(strings.ToLower(outStr), "exists") &&
			!strings.Contains(strings.ToLower(outStr), "already") {
			return nil, fmt.Errorf("failed to set address: %s: %w", outStr, err)
		}
	}

	// Read private key from file
	privateKeyBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}
	privateKey, err := wgtypes.ParseKey(strings.TrimSpace(string(privateKeyBytes)))
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Create wgctrl client
	wgClient, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create wgctrl client: %w", err)
	}

	// Configure WireGuard interface
	if err := wgClient.ConfigureDevice(interfaceName, wgtypes.Config{
		PrivateKey: &privateKey,
		ListenPort: &listenPort,
	}); err != nil {
		wgClient.Close()
		return nil, fmt.Errorf("failed to configure WireGuard: %w", err)
	}

	// Set MTU like wg-quick: default interface MTU minus 80 bytes for WireGuard overhead
	if err := setMTU(interfaceName); err != nil {
		wgClient.Close()
		return nil, fmt.Errorf("failed to set MTU: %w", err)
	}
	if out, err := exec.Command("ifconfig", interfaceName, "up").CombinedOutput(); err != nil {
		wgClient.Close()
		return nil, fmt.Errorf("failed to bring interface up: %s: %w", string(out), err)
	}
	nm := &DarwinNetworkManager{
		InterfaceName: interfaceName,
		wgClient:      wgClient,
		peerIPList:    make(map[string]*Peer),
		peerIPListMu:  &sync.RWMutex{},
		WireguardIP:   wireguardIp,
		log:           log,
	}
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		for range ticker.C {
			nm.syncAllowedIPs()
		}
	}()
	return nm, nil
}

// SetPeer configures a WireGuard peer and adds a route for its allowed IPs.
func (nm *DarwinNetworkManager) SetPeer(ctx context.Context, publicKey, endpoint, wireguardIp string) error {
	pubKey, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	// Check if peer already exists
	device, err := nm.wgClient.Device(nm.InterfaceName)
	if err != nil {
		return fmt.Errorf("failed to get device: %w", err)
	}

	peerExists := false
	for _, peer := range device.Peers {
		if peer.PublicKey == pubKey {
			peerExists = true
			break
		}
	}

	if !peerExists {
		// The first time we add this peer, so we configure only its own peer IP.
		udpAddr, err := net.ResolveUDPAddr("udp", endpoint)
		if err != nil {
			return fmt.Errorf("failed to resolve endpoint: %w", err)
		}

		_, allowedIPNet, err := net.ParseCIDR(wireguardIp + "/32")
		if err != nil {
			return fmt.Errorf("failed to parse allowed IP: %w", err)
		}

		keepalive := 25 * time.Second
		if err := nm.wgClient.ConfigureDevice(nm.InterfaceName, wgtypes.Config{
			Peers: []wgtypes.PeerConfig{
				{
					PublicKey:                   pubKey,
					Endpoint:                    udpAddr,
					AllowedIPs:                  []net.IPNet{*allowedIPNet},
					PersistentKeepaliveInterval: &keepalive,
				},
			},
		}); err != nil {
			return fmt.Errorf("failed to set peer: %w", err)
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
		if !isIPAddress(gateway) || gateway == nm.WireguardIP {
			continue
		}

		// netstat on macOS may abbreviate IPv4 CIDRs, e.g. "10.96.0.0/12" as "10.96/12".
		// Expand those so wg receives a valid CIDR string.
		cidr = expandAbbreviatedNetstatCIDR(cidr)

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

			pubKey, err := wgtypes.ParseKey(peer.PublicKey)
			if err != nil {
				nm.log.Info("failed to parse public key", "peerIP", peerIP, "err", err)
				return
			}

			udpAddr, err := net.ResolveUDPAddr("udp", peer.Endpoint)
			if err != nil {
				nm.log.Info("failed to resolve endpoint", "peerIP", peerIP, "err", err)
				return
			}

			// Build allowed IPs list
			allowedIPs := make([]net.IPNet, 0, len(peerCIDRs[peerIP])+1)
			_, peerIPNet, err := net.ParseCIDR(peer.WireguardIP + "/32")
			if err != nil {
				nm.log.Info("failed to parse peer wireguard IP", "peerIP", peerIP, "err", err)
				return
			}
			allowedIPs = append(allowedIPs, *peerIPNet)

			allowedIPStrs := []string{peer.WireguardIP + "/32"}
			for cidr := range peerCIDRs[peerIP] {
				_, ipNet, err := net.ParseCIDR(cidr)
				if err != nil {
					nm.log.Info("failed to parse CIDR", "cidr", cidr, "err", err)
					continue
				}
				allowedIPs = append(allowedIPs, *ipNet)
				allowedIPStrs = append(allowedIPStrs, cidr)
			}

			if err := nm.wgClient.ConfigureDevice(nm.InterfaceName, wgtypes.Config{
				Peers: []wgtypes.PeerConfig{
					{
						PublicKey:         pubKey,
						UpdateOnly:        true,
						Endpoint:          udpAddr,
						ReplaceAllowedIPs: true,
						AllowedIPs:        allowedIPs,
					},
				},
			}); err != nil {
				nm.log.Info("failed to update peer allowed IPs", "peerIP", peerIP, "err", err)
				return
			}
			nm.log.Debug("updated peer allowed IPs", "peerIP", peerIP, "allowedIPs", strings.Join(allowedIPStrs, ","))
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

// expandAbbreviatedNetstatCIDR expands macOS netstat abbreviated IPv4 CIDRs.
// Example: "10.96/12" -> "10.96.0.0/12", "10/8" -> "10.0.0.0/8".
// If the input doesn't look like an abbreviated IPv4 CIDR, it is returned unchanged.
func expandAbbreviatedNetstatCIDR(cidr string) string {
	parts := strings.Split(cidr, "/")
	if len(parts) != 2 {
		return cidr
	}
	ipPart, maskPart := parts[0], parts[1]
	// Only handle IPv4 here. IPv6 routes in netstat output are different.
	if strings.Contains(ipPart, ":") {
		return cidr
	}
	dots := strings.Count(ipPart, ".")
	if dots >= 3 {
		return cidr
	}
	// Append ".0" until it's a full dotted quad.
	for dots < 3 {
		ipPart += ".0"
		dots++
	}
	return ipPart + "/" + maskPart
}

// setMTU sets the MTU on the WireGuard interface.
// Like wg-quick, it calculates MTU as (default interface MTU - 80) to account for WireGuard overhead.
func setMTU(interfaceName string) error {
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
	if out, err := exec.Command("ifconfig", interfaceName, "mtu", strconv.Itoa(wgMTU)).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set MTU: %s: %w", string(out), err)
	}
	return nil
}
