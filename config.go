package limguard

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gopkg.in/yaml.v3"
)

// Default configuration values.
const (
	DefaultListenPort     = 51820
	DefaultPrivateKeyPath = "/etc/limguard/privatekey"
	DefaultConfigPath     = "/etc/limguard/limguard.yaml"
	DefaultBinaryPath     = "/usr/local/bin/limguard"
)

// DefaultInterfaceName returns the default WireGuard interface name for the current platform.
func DefaultInterfaceName() string {
	if runtime.GOOS == "darwin" {
		return "utun5"
	}
	return "wg0"
}

// SSH holds SSH connection details for a node (used only by deploy command).
type SSH struct {
	Host         string `yaml:"host"`
	Port         int    `yaml:"port,omitempty"`
	User         string `yaml:"user,omitempty"`
	IdentityFile string `yaml:"identityFile,omitempty"`
}

// Node represents a node in the WireGuard mesh.
type Node struct {
	WireguardIP string `yaml:"wireguardIP"`
	Endpoint    string `yaml:"endpoint"`
	PublicKey   string `yaml:"publicKey,omitempty"` // Filled in after bootstrap
	SSH         *SSH   `yaml:"ssh,omitempty"`       // Used only by deploy command
}

// Config is the unified configuration for limguard.
// The same file is used for deployment and runtime on all nodes.
type Config struct {
	InterfaceName  string          `yaml:"interfaceName,omitempty"`
	ListenPort     int             `yaml:"listenPort,omitempty"`
	PrivateKeyPath string          `yaml:"privateKeyPath,omitempty"`
	BinaryPath     string          `yaml:"binaryPath,omitempty"`  // Used by deploy
	ArtifactDir    string          `yaml:"artifactDir,omitempty"` // Used by deploy (local binaries)
	Nodes          map[string]Node `yaml:"nodes"`
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
	if c.InterfaceName == "" {
		c.InterfaceName = DefaultInterfaceName()
	}
	if c.ListenPort == 0 {
		c.ListenPort = DefaultListenPort
	}
	if c.PrivateKeyPath == "" {
		c.PrivateKeyPath = DefaultPrivateKeyPath
	}
	if c.BinaryPath == "" {
		c.BinaryPath = DefaultBinaryPath
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
		if node.Endpoint == "" {
			return fmt.Errorf("node %q: endpoint required", name)
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
	if c.ArtifactDir == "" {
		return fmt.Errorf("artifactDir required for deploy")
	}
	for name, node := range c.Nodes {
		if node.SSH == nil || node.SSH.Host == "" {
			return fmt.Errorf("node %q: ssh.host required for deploy", name)
		}
	}
	return nil
}

// GetSelf returns the node config for the given name.
func (c *Config) GetSelf(name string) (Node, bool) {
	node, ok := c.Nodes[name]
	return node, ok
}

// GetPeers returns all nodes except the given name.
func (c *Config) GetPeers(selfName string) map[string]Node {
	peers := make(map[string]Node)
	for name, node := range c.Nodes {
		if name != selfName {
			peers[name] = node
		}
	}
	return peers
}

// EndpointWithPort returns endpoint with port appended if not present.
// Handles both IPv4 and IPv6 addresses correctly.
func (c *Config) EndpointWithPort(endpoint string) string {
	// Try to split as host:port first
	if _, _, err := net.SplitHostPort(endpoint); err == nil {
		// Already has port
		return endpoint
	}
	// No port, add default
	return net.JoinHostPort(endpoint, fmt.Sprintf("%d", c.ListenPort))
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
