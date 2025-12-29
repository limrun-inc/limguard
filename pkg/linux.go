//go:build linux

package limguard

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/crossplane/crossplane-runtime/pkg/logging"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// LinuxNetworkManager implements NetworkManager for Linux using ip command and wgctrl.
type LinuxNetworkManager struct {
	// InterfaceName is the WireGuard interface name (e.g., "wg0")
	InterfaceName string
	WireguardIP   string

	wgClient *wgctrl.Client

	peerIPList   map[string]*Peer
	peerIPListMu *sync.RWMutex

	log logging.Logger
}

// NewNetworkManager creates a new LinuxNetworkManager.
// It creates the WireGuard interface, configures it with the private key and listen port,
// and brings it up. This should be called once at startup.
func NewNetworkManager(interfaceName, privateKeyPath string, listenPort int, wireguardIp string, log logging.Logger) (*LinuxNetworkManager, error) {
	if _, err := exec.Command("ip", "link", "show", interfaceName).Output(); err != nil {
		if out, err := exec.Command("ip", "link", "add", interfaceName, "type", "wireguard").CombinedOutput(); err != nil {
			return nil, fmt.Errorf("failed to create interface: %s: %w", string(out), err)
		}
	}
	expectedAddr := fmt.Sprintf("%s/32", wireguardIp)
	out, err := exec.Command("ip", "addr", "add", expectedAddr, "dev", interfaceName).CombinedOutput()
	if err != nil {
		outStr := string(out)
		if !strings.Contains(strings.ToLower(outStr), "exists") &&
			!strings.Contains(strings.ToLower(outStr), "already assigned") {
			return nil, fmt.Errorf("failed to add address: %s: %w", outStr, err)
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

	if out, err := exec.Command("ip", "link", "set", interfaceName, "up").CombinedOutput(); err != nil {
		wgClient.Close()
		return nil, fmt.Errorf("failed to bring interface up: %s: %w", string(out), err)
	}
	nm := &LinuxNetworkManager{
		InterfaceName: interfaceName,
		WireguardIP:   wireguardIp,
		wgClient:      wgClient,
		peerIPList:    make(map[string]*Peer),
		peerIPListMu:  &sync.RWMutex{},
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
func (nm *LinuxNetworkManager) SetPeer(ctx context.Context, publicKey, endpoint, wireguardIp string) error {
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
		// First time we add this peer so we configure only its own peer IP.
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
