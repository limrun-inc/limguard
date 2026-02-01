package limguard

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gopkg.in/yaml.v3"
)

// Default configuration values.
const (
	DefaultPrivateKeyPath = "/etc/limguard/privatekey"
	DefaultConfigPath     = "/etc/limguard/limguard.yaml"
	DefaultBinaryPath     = "/usr/local/bin/limguard"
	DefaultListenPort     = 51820
)

// DefaultLinuxInterfaceName is the default WireGuard interface name on Linux.
const DefaultLinuxInterfaceName = "wg0"

// DefaultDarwinInterfaceName is the default WireGuard interface name on macOS.
// Must be a specific utun interface (e.g., utun9).
const DefaultDarwinInterfaceName = "utun9"

// SSH holds SSH connection details for a node (used only by deploy command).
type SSH struct {
	Host         string `yaml:"host"`
	Port         int    `yaml:"port,omitempty"`
	User         string `yaml:"user,omitempty"`
	IdentityFile string `yaml:"identityFile,omitempty"`
}

// NodeAction represents the desired action for a node.
type NodeAction string

const (
	// NodeActionApply is the default action - ensure the node is configured and running.
	NodeActionApply NodeAction = "Apply"
	// NodeActionDelete removes the node from peers and stops/uninstalls the service.
	NodeActionDelete NodeAction = "Delete"
)

// Node represents a node in the WireGuard mesh.
type Node struct {
	Action          NodeAction `yaml:"action,omitempty"`          // Apply (default) or Delete
	WireguardIP     string     `yaml:"wireguardIP"`
	Endpoint        string     `yaml:"endpoint"`                  // Must be host:port format
	PublicKey       string     `yaml:"publicKey,omitempty"`       // Filled in after bootstrap
	InterfaceName   string     `yaml:"interfaceName,omitempty"`   // Per-node override
	LocalBinaryPath string     `yaml:"localBinaryPath,omitempty"` // Local binary to use instead of downloading
	SSH             *SSH       `yaml:"ssh,omitempty"`             // Used only by deploy command
}

// IsDelete returns true if the node is marked for deletion.
func (n Node) IsDelete() bool {
	return n.Action == NodeActionDelete
}

// IsLocal returns true if this is a local node (ssh.host: self).
func (n Node) IsLocal() bool {
	return n.SSH != nil && strings.EqualFold(n.SSH.Host, "self")
}

// Config is the unified configuration for limguard.
// The same file is used for deployment and runtime on all nodes.
type Config struct {
	LinuxInterfaceName  string          `yaml:"linuxInterfaceName,omitempty"`  // Default for Linux nodes
	DarwinInterfaceName string          `yaml:"darwinInterfaceName,omitempty"` // Default for macOS nodes
	Version             string          `yaml:"version,omitempty"`             // GitHub release tag (e.g., v1.0.0); resolved to latest if empty
	Nodes               map[string]Node `yaml:"nodes"`
}

// LoadConfig reads and parses a config file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDefaults()
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.LinuxInterfaceName == "" {
		c.LinuxInterfaceName = DefaultLinuxInterfaceName
	}
	if c.DarwinInterfaceName == "" {
		c.DarwinInterfaceName = DefaultDarwinInterfaceName
	}
	for name, node := range c.Nodes {
		if node.SSH != nil {
			if node.SSH.Port == 0 {
				node.SSH.Port = 22
			}
			if node.SSH.User == "" {
				node.SSH.User = "root"
			}
			c.Nodes[name] = node
		}
	}
}

// InterfaceName returns the WireGuard interface name for a node on the current platform.
// If the node has a per-node override, that is used. Otherwise, the platform default is used.
func (c *Config) InterfaceName(nodeName string) string {
	if node, ok := c.Nodes[nodeName]; ok && node.InterfaceName != "" {
		return node.InterfaceName
	}
	if runtime.GOOS == "darwin" {
		return c.DarwinInterfaceName
	}
	return c.LinuxInterfaceName
}

// NodeListenPort parses and returns the WireGuard listen port from a node's endpoint.
// Returns DefaultListenPort if endpoint is empty (for local nodes behind NAT).
func (c *Config) NodeListenPort(nodeName string) (int, error) {
	node, ok := c.Nodes[nodeName]
	if !ok {
		return 0, fmt.Errorf("node %q not found", nodeName)
	}
	// Local nodes can omit endpoint - use default port
	if node.Endpoint == "" {
		return DefaultListenPort, nil
	}
	_, portStr, err := net.SplitHostPort(node.Endpoint)
	if err != nil {
		return 0, fmt.Errorf("invalid endpoint %q: must be host:port format", node.Endpoint)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, fmt.Errorf("invalid port in endpoint %q: %w", node.Endpoint, err)
	}
	return port, nil
}

// Validate checks the config for runtime use.
// Empty publicKeys are allowed (used during bootstrap for self node).
func (c *Config) Validate() error {
	if len(c.Nodes) == 0 {
		return fmt.Errorf("no nodes defined")
	}
	seenIPs := make(map[string]string)
	for name, node := range c.Nodes {
		if node.WireguardIP == "" {
			return fmt.Errorf("node %q: wireguardIP required", name)
		}
		if net.ParseIP(node.WireguardIP) == nil {
			return fmt.Errorf("node %q: invalid wireguardIP", name)
		}
		if other, ok := seenIPs[node.WireguardIP]; ok {
			return fmt.Errorf("duplicate wireguardIP %q: %q and %q", node.WireguardIP, other, name)
		}
		seenIPs[node.WireguardIP] = name
		// Endpoint is optional (for NAT'd nodes that initiate connections to peers).
		// If provided, validate it's in host:port format.
		if node.Endpoint != "" {
			if _, _, err := net.SplitHostPort(node.Endpoint); err != nil {
				return fmt.Errorf("node %q: endpoint must be host:port format (got %q)", name, node.Endpoint)
			}
		}
		// Skip publicKey validation if empty (bootstrap mode for self node)
		// Non-empty publicKeys must be valid
		if node.PublicKey != "" {
			if _, err := wgtypes.ParseKey(node.PublicKey); err != nil {
				return fmt.Errorf("node %q: invalid publicKey: %w", name, err)
			}
		}
	}
	return nil
}

// ValidateForDeploy checks the config for deployment (SSH info required, public keys optional).
func (c *Config) ValidateForDeploy() error {
	if err := c.Validate(); err != nil {
		return err
	}
	for name, node := range c.Nodes {
		if node.SSH == nil || node.SSH.Host == "" {
			return fmt.Errorf("node %q: ssh.host required for deploy", name)
		}
		// Endpoint is required for non-local nodes (we need to reach them and configure peers).
		// Local nodes can omit endpoint - they're behind NAT and initiate connections.
		if node.Endpoint == "" && !node.IsLocal() {
			return fmt.Errorf("node %q: endpoint required (only local nodes can omit endpoint)", name)
		}
	}
	return nil
}

// GetSelf returns the node config for the given name.
func (c *Config) GetSelf(name string) (Node, bool) {
	node, ok := c.Nodes[name]
	return node, ok
}

// GetPeers returns all nodes except the given name, excluding nodes marked for deletion.
func (c *Config) GetPeers(selfName string) map[string]Node {
	peers := make(map[string]Node)
	for name, node := range c.Nodes {
		if name != selfName && !node.IsDelete() {
			peers[name] = node
		}
	}
	return peers
}

// PeerEndpoint returns the endpoint (host:port) for a peer node.
func (c *Config) PeerEndpoint(peerName string) string {
	return c.Nodes[peerName].Endpoint
}

// Save writes the config back to the given path.
func (c *Config) Save(path string) error {
	data, err := c.ToYAML()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// ToYAML serializes the config to YAML.
func (c *Config) ToYAML() ([]byte, error) {
	return yaml.Marshal(c)
}

// EnsurePrivateKey reads or generates a WireGuard private key.
// Returns an error if the file exists but cannot be read or parsed.
func EnsurePrivateKey(keyPath string) (wgtypes.Key, error) {
	data, err := os.ReadFile(keyPath)
	if err == nil {
		return wgtypes.ParseKey(strings.TrimSpace(string(data)))
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return wgtypes.Key{}, fmt.Errorf("read private key: %w", err)
	}

	// File doesn't exist, generate new key
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("generate private key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		return wgtypes.Key{}, fmt.Errorf("create key directory: %w", err)
	}
	if err := os.WriteFile(keyPath, []byte(key.String()), 0600); err != nil {
		return wgtypes.Key{}, fmt.Errorf("write private key: %w", err)
	}
	return key, nil
}
