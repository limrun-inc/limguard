//go:build linux

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

// LinuxNetworkManager implements NetworkManager for Linux using ip and wg commands.
type LinuxNetworkManager struct {
	// InterfaceName is the WireGuard interface name (e.g., "wg0")
	InterfaceName string

	peerIPList   map[string]*Peer
	peerIPListMu *sync.RWMutex

	log logging.Logger
}

// NewNetworkManager creates a new LinuxNetworkManager.
// It creates the WireGuard interface, configures it with the private key and listen port,
// and brings it up. This should be called once at startup.
func NewNetworkManager(interfaceName, privateKeyPath string, listenPort int, log logging.Logger) (*LinuxNetworkManager, error) {
	nm := &LinuxNetworkManager{
		InterfaceName: interfaceName,
		peerIPList:    make(map[string]*Peer),
		peerIPListMu:  &sync.RWMutex{},
		log:           log,
	}

	// Create interface if it doesn't exist
	if _, err := exec.Command("ip", "link", "show", interfaceName).Output(); err != nil {
		if out, err := exec.Command("ip", "link", "add", interfaceName, "type", "wireguard").CombinedOutput(); err != nil {
			return nil, fmt.Errorf("failed to create interface: %s: %w", string(out), err)
		}
	}

	// Configure with private key and listen port
	if out, err := exec.Command("wg", "set", interfaceName,
		"listen-port", fmt.Sprintf("%d", listenPort),
		"private-key", privateKeyPath,
	).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to configure WireGuard: %s: %w", string(out), err)
	}

	// Bring interface up
	if out, err := exec.Command("ip", "link", "set", interfaceName, "up").CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to bring interface up: %s: %w", string(out), err)
	}

	go func() {
		ticker := time.NewTicker(5 * time.Second)
		for range ticker.C {
			nm.syncAllowedIPs()
		}
	}()

	return nm, nil
}

// SetAddress sets the IP address on the WireGuard interface.
func (nm *LinuxNetworkManager) SetWireguardIP(ip string) error {
	expectedAddr := fmt.Sprintf("%s/32", ip)

	// Try to add the address - if it already exists, that's fine
	out, err := exec.Command("ip", "addr", "add", expectedAddr, "dev", nm.InterfaceName).CombinedOutput()
	if err != nil {
		outStr := string(out)
		// Handle both error formats for "address already exists"
		if strings.Contains(strings.ToLower(outStr), "exists") ||
			strings.Contains(strings.ToLower(outStr), "already assigned") {
			return nil // Already set, idempotent success
		}
		return fmt.Errorf("failed to add address: %s: %w", outStr, err)
	}

	return nil
}

// SetPeer configures a WireGuard peer and adds a route for its allowed IPs.
func (nm *LinuxNetworkManager) SetPeer(ctx context.Context, publicKey, endpoint, wireguardIp string) error {
	if out, err := exec.CommandContext(ctx, "wg", "show", "wg0", "peers").CombinedOutput(); err == nil && !strings.Contains(string(out), publicKey) {
		// First time we add this peer so we configure only its own peer IP.
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
	// Add route for the peer's allowed IPs
	if out, err := exec.Command("ip", "route", "replace", wireguardIp+"/32", "dev", nm.InterfaceName).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to add route: %s: %w", string(out), err)
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
func (nm *LinuxNetworkManager) syncAllowedIPs() {
	ctx := context.Background()
	out, err := exec.Command("ip", "route", "show", "dev", nm.InterfaceName).Output()
	if err != nil {
		return
	}

	// Example line returned from ip tool:
	// 10.244.23.0/26 via 10.200.0.18 proto bird
	peerCIDRs := make(map[string]map[string]struct{})
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "via") {
			continue
		}
		fields := strings.Split(line, " ")
		if len(fields) < 3 {
			continue
		}
		cidr := fields[0]
		peerIP := fields[2]
		if peerCIDRs[peerIP] == nil {
			peerCIDRs[peerIP] = make(map[string]struct{})
		}
		peerCIDRs[peerIP][cidr] = struct{}{}
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
