package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gopkg.in/yaml.v3"
)

const (
	DefaultListenPort     = 51820
	DefaultPrivateKeyPath = "/etc/limguard/privatekey"
	DefaultConfigPath     = "/etc/limguard/limguard.yaml"
	DefaultBinaryPath     = "/usr/local/bin/limguard"
)

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

// Load reads and validates a config file.
func Load(path string) (*Config, error) {
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

// Validate checks the config for runtime use (requires public keys).
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
		if node.PublicKey == "" {
			return fmt.Errorf("node %q: publicKey required (run deploy first)", name)
		}
		if _, err := wgtypes.ParseKey(node.PublicKey); err != nil {
			return fmt.Errorf("node %q: invalid publicKey: %w", name, err)
		}
	}
	return nil
}

// ValidateForDeploy checks the config for deployment (SSH info required, public keys optional).
func (c *Config) ValidateForDeploy() error {
	if len(c.Nodes) == 0 {
		return fmt.Errorf("no nodes defined")
	}
	if c.ArtifactDir == "" {
		return fmt.Errorf("artifactDir required for deploy")
	}
	for name, node := range c.Nodes {
		if node.WireguardIP == "" {
			return fmt.Errorf("node %q: wireguardIP required", name)
		}
		if node.Endpoint == "" {
			return fmt.Errorf("node %q: endpoint required", name)
		}
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
func (c *Config) EndpointWithPort(endpoint string) string {
	if strings.Contains(endpoint, ":") {
		return endpoint
	}
	return fmt.Sprintf("%s:%d", endpoint, c.ListenPort)
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
func EnsurePrivateKey(keyPath string) (wgtypes.Key, error) {
	if data, err := os.ReadFile(keyPath); err == nil {
		return wgtypes.ParseKey(strings.TrimSpace(string(data)))
	}
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return wgtypes.Key{}, err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		return wgtypes.Key{}, err
	}
	if err := os.WriteFile(keyPath, []byte(key.String()), 0600); err != nil {
		return wgtypes.Key{}, err
	}
	return key, nil
}
