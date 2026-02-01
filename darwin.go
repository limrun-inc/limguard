//go:build darwin

package limguard

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// NetworkManager handles WireGuard interface and peer management on macOS.
type NetworkManager struct {
	iface    string
	wgIP     string
	wgClient *wgctrl.Client
	peers    map[string]string // wireguardIP -> publicKey
	mu       sync.RWMutex
	log      *slog.Logger
	ctx      context.Context
	cancel   context.CancelFunc
}

// NewNetworkManager creates the WireGuard interface and configures it.
func NewNetworkManager(iface, privateKeyPath string, listenPort int, wireguardIP string, log *slog.Logger) (*NetworkManager, error) {
	// On macOS, interface name must be utun[0-9]+ (e.g., utun9)
	if !strings.HasPrefix(iface, "utun") {
		return nil, fmt.Errorf("macOS interface name must start with 'utun' (e.g., utun9), got: %s", iface)
	}

	// Create a context for background operations
	ctx, cancel := context.WithCancel(context.Background())
	success := false
	defer func() {
		if !success {
			cancel()
		}
	}()

	// Create interface if needed
	if _, err := exec.CommandContext(ctx, "ifconfig", iface).Output(); err != nil {
		out, err := exec.CommandContext(ctx, "/opt/homebrew/bin/wireguard-go", iface).CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("create interface: %s: %w", out, err)
		}

		// Wait for interface to become available (cancellable)
		available := false
		for i := 0; i < 20; i++ {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if _, err := exec.CommandContext(ctx, "ifconfig", iface).Output(); err == nil {
				available = true
				break
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(500 * time.Millisecond):
			}
		}
		if !available {
			return nil, fmt.Errorf("interface %s not available after wireguard-go started", iface)
		}

	}

	// Add IP address
	if out, err := exec.CommandContext(ctx, "ifconfig", iface, "inet", wireguardIP+"/32", wireguardIP, "alias").CombinedOutput(); err != nil {
		outStr := strings.ToLower(string(out))
		if !strings.Contains(outStr, "exists") && !strings.Contains(outStr, "already") {
			return nil, fmt.Errorf("set address: %s: %w", out, err)
		}
	}

	// Read private key
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

	// Set MTU
	if err := setMTU(ctx, iface); err != nil {
		wgClient.Close()
		return nil, fmt.Errorf("set MTU: %w", err)
	}

	if out, err := exec.CommandContext(ctx, "ifconfig", iface, "up").CombinedOutput(); err != nil {
		wgClient.Close()
		return nil, fmt.Errorf("bring interface up: %s: %w", out, err)
	}

	nm := &NetworkManager{
		iface:    iface,
		wgIP:     wireguardIP,
		wgClient: wgClient,
		peers:    make(map[string]string),
		log:      log,
		ctx:      ctx,
		cancel:   cancel,
	}

	go nm.syncAllowedIPsLoop()
	success = true
	return nm, nil
}

// Close stops the NetworkManager and releases resources.
func (nm *NetworkManager) Close() error {
	nm.cancel()
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
		// Resolve endpoint if provided (empty for NAT'd peers that initiate connections)
		var udpAddr *net.UDPAddr
		if endpoint != "" {
			host, port, err := net.SplitHostPort(endpoint)
			if err != nil {
				return fmt.Errorf("parse endpoint: %w", err)
			}
			// Use context-aware DNS resolution
			ips, err := net.DefaultResolver.LookupHost(ctx, host)
			if err != nil {
				return fmt.Errorf("resolve endpoint host: %w", err)
			}
			if len(ips) == 0 {
				return fmt.Errorf("no addresses found for %s", host)
			}
			portNum, _ := net.LookupPort("udp", port)
			udpAddr = &net.UDPAddr{IP: net.ParseIP(ips[0]), Port: portNum}
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
		if endpoint == "" {
			nm.log.Info("added peer (no endpoint - will accept incoming)", "publicKey", publicKey)
		} else {
			nm.log.Info("added peer", "publicKey", publicKey, "endpoint", endpoint)
		}
	}

	// Add route if needed
	ifaceRe := regexp.MustCompile(`interface:\s*` + regexp.QuoteMeta(nm.iface) + `(\s|$)`)
	out, err := exec.CommandContext(ctx, "route", "-n", "get", wireguardIP).CombinedOutput()
	if err != nil || !ifaceRe.Match(out) {
		if routeOut, routeErr := exec.CommandContext(ctx, "route", "-n", "add", "-host", wireguardIP, "-interface", nm.iface).CombinedOutput(); routeErr != nil {
			// Ignore "route already exists" errors - can happen due to race conditions
			// between the check (route -n get) and add (route -n add). Unlike Linux's
			// netlink.RouteReplace which is idempotent, macOS route add fails if the route exists.
			outStr := strings.ToLower(string(routeOut))
			if !strings.Contains(outStr, "exists") {
				return fmt.Errorf("add route for %s: %s: %w", wireguardIP, routeOut, routeErr)
			}
		}
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
			if out, err := exec.CommandContext(ctx, "route", "-n", "delete", "-host", ip).CombinedOutput(); err != nil {
				nm.mu.Unlock()
				return fmt.Errorf("delete route for %s: %s: %w", ip, out, err)
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
		case <-nm.ctx.Done():
			return
		case <-ticker.C:
			nm.syncAllowedIPs()
		}
	}
}

func (nm *NetworkManager) syncAllowedIPs() {
	out, err := exec.CommandContext(nm.ctx, "netstat", "-rn").Output()
	if err != nil {
		return
	}

	// Map gateway -> CIDRs
	peerCIDRs := make(map[string][]string)
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		// Check if route uses our interface
		hasIface := false
		for _, f := range fields {
			if f == nm.iface {
				hasIface = true
				break
			}
		}
		if !hasIface {
			continue
		}

		cidr := fields[0]
		gateway := fields[1]
		if !isIPv4(gateway) || gateway == nm.wgIP {
			continue
		}

		cidr = expandCIDR(cidr)
		if !strings.Contains(cidr, "/") {
			cidr = cidr + "/32"
		}
		peerCIDRs[gateway] = append(peerCIDRs[gateway], cidr)
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

func isIPv4(s string) bool {
	return len(s) > 0 && s[0] >= '0' && s[0] <= '9' && strings.Contains(s, ".")
}

// expandCIDR expands abbreviated macOS netstat CIDRs like "10.96/12" -> "10.96.0.0/12"
func expandCIDR(cidr string) string {
	parts := strings.Split(cidr, "/")
	if len(parts) != 2 || strings.Contains(parts[0], ":") {
		return cidr
	}
	ip := parts[0]
	for strings.Count(ip, ".") < 3 {
		ip += ".0"
	}
	return ip + "/" + parts[1]
}

func setMTU(ctx context.Context, iface string) error {
	out, err := exec.CommandContext(ctx, "netstat", "-nr", "-f", "inet").Output()
	if err != nil {
		return err
	}
	var defaultIface string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[0] == "default" {
			defaultIface = fields[3]
			break
		}
	}
	if defaultIface == "" {
		return fmt.Errorf("no default interface")
	}

	out, err = exec.CommandContext(ctx, "ifconfig", defaultIface).Output()
	if err != nil {
		return err
	}

	mtu := 1500
	if matches := regexp.MustCompile(`mtu\s+(\d+)`).FindStringSubmatch(string(out)); len(matches) >= 2 {
		if n, err := strconv.Atoi(matches[1]); err == nil && n > 0 {
			mtu = n
		}
	}

	_, err = exec.CommandContext(ctx, "ifconfig", iface, "mtu", strconv.Itoa(mtu-80)).CombinedOutput()
	return err
}
