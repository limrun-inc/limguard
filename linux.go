//go:build linux

package limguard

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// NetworkManager handles WireGuard interface and peer management on Linux.
type NetworkManager struct {
	iface    string
	wgIP     string
	wgClient *wgctrl.Client
	link     netlink.Link
	peers    map[string]string // wireguardIP -> publicKey
	mu       sync.RWMutex
	log      *slog.Logger
	done     chan struct{}
}

// NewNetworkManager creates the WireGuard interface and configures it.
func NewNetworkManager(iface, privateKeyPath string, listenPort int, wireguardIP string, log *slog.Logger) (*NetworkManager, error) {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		wgLink := &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: iface}}
		if err := netlink.LinkAdd(wgLink); err != nil {
			return nil, fmt.Errorf("create interface: %w", err)
		}
		link, err = netlink.LinkByName(iface)
		if err != nil {
			return nil, fmt.Errorf("get interface: %w", err)
		}
	}

	ip := net.ParseIP(wireguardIP)
	if ip == nil {
		return nil, fmt.Errorf("invalid wireguard IP: %s", wireguardIP)
	}
	addr := &netlink.Addr{IPNet: &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}}
	if err := netlink.AddrAdd(link, addr); err != nil && !strings.Contains(err.Error(), "exists") {
		return nil, fmt.Errorf("add address: %w", err)
	}

	keyData, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	privateKey, err := wgtypes.ParseKey(strings.TrimSpace(string(keyData)))
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	wgClient, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("create wgctrl client: %w", err)
	}

	if err := wgClient.ConfigureDevice(iface, wgtypes.Config{
		PrivateKey: &privateKey,
		ListenPort: &listenPort,
	}); err != nil {
		wgClient.Close()
		return nil, fmt.Errorf("configure wireguard: %w", err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		wgClient.Close()
		return nil, fmt.Errorf("bring interface up: %w", err)
	}

	nm := &NetworkManager{
		iface:    iface,
		wgIP:     wireguardIP,
		wgClient: wgClient,
		link:     link,
		peers:    make(map[string]string),
		log:      log,
		done:     make(chan struct{}),
	}

	go nm.syncAllowedIPsLoop()
	return nm, nil
}

// Close stops the NetworkManager and releases resources.
func (nm *NetworkManager) Close() error {
	close(nm.done)
	return nm.wgClient.Close()
}

// SetPeer adds or updates a WireGuard peer.
func (nm *NetworkManager) SetPeer(ctx context.Context, publicKey, endpoint, wireguardIP string) error {
	pubKey, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}

	device, err := nm.wgClient.Device(nm.iface)
	if err != nil {
		return fmt.Errorf("get device: %w", err)
	}

	exists := false
	for _, p := range device.Peers {
		if p.PublicKey.String() == publicKey {
			exists = true
			break
		}
	}

	if !exists {
		udpAddr, err := net.ResolveUDPAddr("udp", endpoint)
		if err != nil {
			return fmt.Errorf("resolve endpoint: %w", err)
		}
		_, allowedIP, _ := net.ParseCIDR(wireguardIP + "/32")
		keepalive := 25 * time.Second

		if err := nm.wgClient.ConfigureDevice(nm.iface, wgtypes.Config{
			Peers: []wgtypes.PeerConfig{{
				PublicKey:                   pubKey,
				Endpoint:                    udpAddr,
				AllowedIPs:                  []net.IPNet{*allowedIP},
				PersistentKeepaliveInterval: &keepalive,
			}},
		}); err != nil {
			return fmt.Errorf("add peer: %w", err)
		}
		nm.log.Info("added peer", "publicKey", publicKey, "endpoint", endpoint)
	}

	// Add route
	dstIP := net.ParseIP(wireguardIP)
	route := &netlink.Route{
		LinkIndex: nm.link.Attrs().Index,
		Dst:       &net.IPNet{IP: dstIP, Mask: net.CIDRMask(32, 32)},
		Scope:     unix.RT_SCOPE_LINK,
	}
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("add route for %s: %w", wireguardIP, err)
	}

	nm.mu.Lock()
	nm.peers[wireguardIP] = publicKey
	nm.mu.Unlock()
	return nil
}

// RemovePeer removes a WireGuard peer.
func (nm *NetworkManager) RemovePeer(ctx context.Context, publicKey string) error {
	pubKey, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}

	if err := nm.wgClient.ConfigureDevice(nm.iface, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{PublicKey: pubKey, Remove: true}},
	}); err != nil {
		return fmt.Errorf("remove peer: %w", err)
	}

	nm.mu.Lock()
	for ip, pk := range nm.peers {
		if pk == publicKey {
			dstIP := net.ParseIP(ip)
			route := &netlink.Route{
				LinkIndex: nm.link.Attrs().Index,
				Dst:       &net.IPNet{IP: dstIP, Mask: net.CIDRMask(32, 32)},
			}
			if err := netlink.RouteDel(route); err != nil {
				nm.mu.Unlock()
				return fmt.Errorf("delete route for %s: %w", ip, err)
			}
			delete(nm.peers, ip)
			break
		}
	}
	nm.mu.Unlock()

	nm.log.Info("removed peer", "publicKey", publicKey)
	return nil
}

// CurrentPeers returns the current peer public keys.
func (nm *NetworkManager) CurrentPeers() map[string]string {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	result := make(map[string]string)
	for ip, pk := range nm.peers {
		result[ip] = pk
	}
	return result
}

func (nm *NetworkManager) syncAllowedIPsLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-nm.done:
			return
		case <-ticker.C:
			nm.syncAllowedIPs()
		}
	}
}

func (nm *NetworkManager) syncAllowedIPs() {
	routes, err := netlink.RouteList(nm.link, netlink.FAMILY_V4)
	if err != nil {
		return
	}

	// Map gateway -> CIDRs
	peerCIDRs := make(map[string][]string)
	for _, route := range routes {
		if route.Gw == nil || route.Dst == nil {
			continue
		}
		gw := route.Gw.String()
		peerCIDRs[gw] = append(peerCIDRs[gw], route.Dst.String())
	}

	nm.mu.RLock()
	defer nm.mu.RUnlock()

	for peerIP, publicKey := range nm.peers {
		cidrs, ok := peerCIDRs[peerIP]
		if !ok {
			continue
		}

		pubKey, _ := wgtypes.ParseKey(publicKey)
		allowedIPs := []net.IPNet{}
		_, peerNet, _ := net.ParseCIDR(peerIP + "/32")
		allowedIPs = append(allowedIPs, *peerNet)

		for _, cidr := range cidrs {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err == nil {
				allowedIPs = append(allowedIPs, *ipNet)
			}
		}

		if err := nm.wgClient.ConfigureDevice(nm.iface, wgtypes.Config{
			Peers: []wgtypes.PeerConfig{{
				PublicKey:         pubKey,
				UpdateOnly:        true,
				ReplaceAllowedIPs: true,
				AllowedIPs:        allowedIPs,
			}},
		}); err != nil {
			nm.log.Error("failed to sync allowed IPs", "peer", peerIP, "error", err)
		}
	}
}
