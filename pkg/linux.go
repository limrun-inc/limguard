//go:build linux

package limguard

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/crossplane/crossplane-runtime/pkg/logging"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// LinuxNetworkManager implements NetworkManager for Linux using netlink and wgctrl.
type LinuxNetworkManager struct {
	// InterfaceName is the WireGuard interface name (e.g., "wg0")
	InterfaceName string
	WireguardIP   string

	wgClient *wgctrl.Client
	link     netlink.Link

	peerIPList   map[string]*Peer
	peerIPListMu *sync.RWMutex

	log logging.Logger
}

// NewNetworkManager creates a new LinuxNetworkManager.
// It creates the WireGuard interface, configures it with the private key and listen port,
// and brings it up. This should be called once at startup.
func NewNetworkManager(interfaceName, privateKeyPath string, listenPort int, wireguardIp string, log logging.Logger) (*LinuxNetworkManager, error) {
	// Check if interface exists, create if not
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		// Interface doesn't exist, create it
		wgLink := &netlink.Wireguard{
			LinkAttrs: netlink.LinkAttrs{
				Name: interfaceName,
			},
		}
		if err := netlink.LinkAdd(wgLink); err != nil {
			return nil, fmt.Errorf("failed to create interface: %w", err)
		}
		link, err = netlink.LinkByName(interfaceName)
		if err != nil {
			return nil, fmt.Errorf("failed to get interface after creation: %w", err)
		}
	}

	// Add IP address to interface
	ip := net.ParseIP(wireguardIp)
	if ip == nil {
		return nil, fmt.Errorf("failed to parse wireguard IP: %s", wireguardIp)
	}
	addr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(32, 32),
		},
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		if !strings.Contains(err.Error(), "exists") {
			return nil, fmt.Errorf("failed to add address: %w", err)
		}
	}
	privateKeyBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}
	privateKey, err := wgtypes.ParseKey(strings.TrimSpace(string(privateKeyBytes)))
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	wgClient, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create wgctrl client: %w", err)
	}
	if err := wgClient.ConfigureDevice(interfaceName, wgtypes.Config{
		PrivateKey: &privateKey,
		ListenPort: &listenPort,
	}); err != nil {
		wgClient.Close()
		return nil, fmt.Errorf("failed to configure WireGuard: %w", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		wgClient.Close()
		return nil, fmt.Errorf("failed to bring interface up: %w", err)
	}
	nm := &LinuxNetworkManager{
		InterfaceName: interfaceName,
		WireguardIP:   wireguardIp,
		wgClient:      wgClient,
		link:          link,
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

	// Add route for the peer's allowed IPs using netlink
	dstIP := net.ParseIP(wireguardIp)
	if dstIP == nil {
		return fmt.Errorf("failed to parse peer IP: %s", wireguardIp)
	}
	route := &netlink.Route{
		LinkIndex: nm.link.Attrs().Index,
		Dst: &net.IPNet{
			IP:   dstIP,
			Mask: net.CIDRMask(32, 32),
		},
		Protocol: unix.RTPROT_STATIC,
	}
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("failed to add route: %w", err)
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
	// Get routes for our interface using netlink
	routes, err := netlink.RouteList(nm.link, netlink.FAMILY_V4)
	if err != nil {
		nm.log.Debug("failed to list routes", "error", err)
		return
	}

	// Build a map of gateway IP to CIDRs
	// Example route: 10.244.23.0/26 via 10.200.0.18
	peerCIDRs := make(map[string]map[string]struct{})
	for _, route := range routes {
		// Skip routes without a gateway (direct routes)
		if route.Gw == nil {
			continue
		}
		if route.Dst == nil {
			continue
		}

		gateway := route.Gw.String()
		cidr := route.Dst.String()

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
