package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/limrun-inc/limguard"
	"github.com/limrun-inc/limguard/config"
	"github.com/limrun-inc/limguard/version"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "run":
		cmdRun(os.Args[2:])
	case "bootstrap":
		cmdBootstrap(os.Args[2:])
	case "deploy":
		cmdDeploy(os.Args[2:])
	case "version":
		fmt.Println(version.Version)
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Println(`limguard - WireGuard mesh network manager

Commands:
  run        Run the daemon
  bootstrap  Bootstrap interface and print public key
  deploy     Deploy to nodes via SSH
  version    Print version`)
}

// --- run command ---

func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultConfigPath, "Config file path")
	nodeName := fs.String("node-name", "", "Node name (default: hostname)")
	healthAddr := fs.String("health-addr", ":8081", "Health server address")
	debug := fs.Bool("debug", false, "Debug logging")
	fs.Parse(args)

	log := newLogger(*debug)
	name := *nodeName
	if name == "" {
		name, _ = os.Hostname()
	}

	log.Info("starting", "version", version.Version, "node", name)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Error("load config", "error", err)
		os.Exit(1)
	}
	if err := cfg.Validate(); err != nil {
		log.Error("invalid config", "error", err)
		os.Exit(1)
	}

	self, ok := cfg.GetSelf(name)
	if !ok {
		log.Error("node not in config", "node", name)
		os.Exit(1)
	}

	nm, err := limguard.NewNetworkManager(cfg.InterfaceName, cfg.PrivateKeyPath, cfg.ListenPort, self.WireguardIP, log)
	if err != nil {
		log.Error("init network", "error", err)
		os.Exit(1)
	}

	// Initial peer sync
	appliedPeers := reconcilePeers(context.Background(), nm, cfg, name, log)

	// Health server
	go func() {
		http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
		http.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
		http.ListenAndServe(*healthAddr, nil)
	}()

	// Watch config
	watcher, _ := fsnotify.NewWatcher()
	defer watcher.Close()
	watcher.Add(*cfgPath)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	var debounce *time.Timer
	for {
		select {
		case <-sigCh:
			log.Info("shutting down")
			return
		case ev := <-watcher.Events:
			if ev.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				if debounce != nil {
					debounce.Stop()
				}
				debounce = time.AfterFunc(500*time.Millisecond, func() {
					newCfg, err := config.Load(*cfgPath)
					if err != nil {
						log.Error("reload config", "error", err)
						return
					}
					if err := newCfg.Validate(); err != nil {
						log.Error("invalid config", "error", err)
						return
					}
					cfg = newCfg
					appliedPeers = reconcilePeers(context.Background(), nm, cfg, name, log)
					log.Info("config reloaded", "peers", len(appliedPeers))
				})
			}
		}
	}
}

func reconcilePeers(ctx context.Context, nm *limguard.NetworkManager, cfg *config.Config, selfName string, log *slog.Logger) map[string]bool {
	peers := cfg.GetPeers(selfName)
	desired := make(map[string]bool)

	for _, node := range peers {
		desired[node.PublicKey] = true
		endpoint := cfg.EndpointWithPort(node.Endpoint)
		if err := nm.SetPeer(ctx, node.PublicKey, endpoint, node.WireguardIP); err != nil {
			log.Error("set peer", "error", err)
		}
	}

	// Remove old peers
	for _, pk := range nm.CurrentPeers() {
		if !desired[pk] {
			nm.RemovePeer(ctx, pk)
		}
	}

	return desired
}

// --- bootstrap command ---

func cmdBootstrap(args []string) {
	fs := flag.NewFlagSet("bootstrap", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultConfigPath, "Config file path")
	nodeName := fs.String("node-name", "", "Node name (default: hostname)")
	debug := fs.Bool("debug", false, "Debug logging")
	fs.Parse(args)

	// Log to stderr so stdout is reserved for public key
	log := newLoggerStderr(*debug)

	name := *nodeName
	if name == "" {
		name, _ = os.Hostname()
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Error("load config", "error", err)
		os.Exit(1)
	}

	self, ok := cfg.GetSelf(name)
	if !ok {
		log.Error("node not in config", "node", name)
		os.Exit(1)
	}

	privateKey, err := config.EnsurePrivateKey(cfg.PrivateKeyPath)
	if err != nil {
		log.Error("ensure private key", "error", err)
		os.Exit(1)
	}

	_, err = limguard.NewNetworkManager(cfg.InterfaceName, cfg.PrivateKeyPath, cfg.ListenPort, self.WireguardIP, log)
	if err != nil {
		log.Error("init network", "error", err)
		os.Exit(1)
	}

	fmt.Println(privateKey.PublicKey().String())
}

// --- deploy command ---

func cmdDeploy(args []string) {
	fs := flag.NewFlagSet("deploy", flag.ExitOnError)
	cfgPath := fs.String("config", "limguard.yaml", "Config file path")
	sshKey := fs.String("ssh-key", "", "SSH private key path")
	debug := fs.Bool("debug", false, "Debug logging")
	fs.Parse(args)

	log := newLogger(*debug)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Error("load config", "error", err)
		os.Exit(1)
	}
	if err := cfg.ValidateForDeploy(); err != nil {
		log.Error("invalid config", "error", err)
		os.Exit(1)
	}

	// Pass 1: Bootstrap each node
	log.Info("pass 1: bootstrapping nodes")
	publicKeys := make(map[string]string)

	for name, node := range cfg.Nodes {
		log.Info("bootstrapping", "node", name, "host", node.SSH.Host)

		client, err := sshConnect(node.SSH, *sshKey)
		if err != nil {
			log.Error("ssh connect", "node", name, "error", err)
			os.Exit(1)
		}

		osName, arch := detectPlatform(client)
		binaryName := fmt.Sprintf("limguard-%s-%s", osName, arch)
		binaryPath := filepath.Join(cfg.ArtifactDir, binaryName)

		// Copy binary
		if err := scpFile(client, binaryPath, cfg.BinaryPath, 0755); err != nil {
			log.Error("copy binary", "node", name, "error", err)
			os.Exit(1)
		}

		// Create directories
		sshRun(client, fmt.Sprintf("mkdir -p %s %s",
			filepath.Dir(config.DefaultConfigPath),
			filepath.Dir(cfg.PrivateKeyPath)))

		// Write minimal config for this node
		minCfg := &config.Config{
			InterfaceName:  cfg.InterfaceName,
			ListenPort:     cfg.ListenPort,
			PrivateKeyPath: cfg.PrivateKeyPath,
			Nodes:          map[string]config.Node{name: {WireguardIP: node.WireguardIP, Endpoint: node.Endpoint, PublicKey: "placeholder"}},
		}
		tmpCfg := "/tmp/limguard-bootstrap.yaml"
		writeRemoteFile(client, tmpCfg, mustMarshal(minCfg))
		sshRun(client, fmt.Sprintf("mv %s %s", tmpCfg, config.DefaultConfigPath))

		// Bootstrap
		out, err := sshRun(client, fmt.Sprintf("%s bootstrap --config %s --node-name %s",
			cfg.BinaryPath, config.DefaultConfigPath, name))
		if err != nil {
			log.Error("bootstrap", "node", name, "error", err, "output", out)
			os.Exit(1)
		}

		pubKey := strings.TrimSpace(out)
		publicKeys[name] = pubKey
		log.Info("bootstrapped", "node", name, "publicKey", pubKey[:8]+"...")

		client.Close()
	}

	// Update config with public keys
	for name, pk := range publicKeys {
		node := cfg.Nodes[name]
		node.PublicKey = pk
		cfg.Nodes[name] = node
	}

	// Save updated config locally
	if err := cfg.Save(*cfgPath); err != nil {
		log.Error("save config", "error", err)
		os.Exit(1)
	}
	log.Info("updated local config with public keys")

	// Pass 2: Distribute config and start daemons
	log.Info("pass 2: distributing config and starting daemons")
	cfgYAML := mustMarshal(cfg)

	for name, node := range cfg.Nodes {
		log.Info("configuring", "node", name)

		client, err := sshConnect(node.SSH, *sshKey)
		if err != nil {
			log.Error("ssh connect", "node", name, "error", err)
			os.Exit(1)
		}

		// Write final config
		tmpCfg := "/tmp/limguard.yaml"
		writeRemoteFile(client, tmpCfg, cfgYAML)
		sshRun(client, fmt.Sprintf("mv %s %s", tmpCfg, config.DefaultConfigPath))

		// Install and start service
		osName, _ := detectPlatform(client)
		if osName == "linux" {
			installLinuxService(client, cfg, name)
		} else {
			installDarwinService(client, cfg, name)
		}

		client.Close()
		log.Info("started", "node", name)
	}

	log.Info("deployment complete")
}

// SSH helpers

func sshConnect(s *config.SSH, keyPath string) (*ssh.Client, error) {
	authMethods := []ssh.AuthMethod{}

	// SSH agent
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if conn, err := net.Dial("unix", sock); err == nil {
			authMethods = append(authMethods, ssh.PublicKeysCallback(agent.NewClient(conn).Signers))
		}
	}

	// Explicit key
	if keyPath != "" {
		if key, err := os.ReadFile(keyPath); err == nil {
			if signer, err := ssh.ParsePrivateKey(key); err == nil {
				authMethods = append(authMethods, ssh.PublicKeys(signer))
			}
		}
	}
	if s.IdentityFile != "" {
		if key, err := os.ReadFile(s.IdentityFile); err == nil {
			if signer, err := ssh.ParsePrivateKey(key); err == nil {
				authMethods = append(authMethods, ssh.PublicKeys(signer))
			}
		}
	}

	// Default keys
	if home, _ := os.UserHomeDir(); home != "" {
		for _, name := range []string{"id_ed25519", "id_rsa"} {
			if key, err := os.ReadFile(filepath.Join(home, ".ssh", name)); err == nil {
				if signer, err := ssh.ParsePrivateKey(key); err == nil {
					authMethods = append(authMethods, ssh.PublicKeys(signer))
				}
			}
		}
	}

	sshCfg := &ssh.ClientConfig{
		User:            s.User,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
	}
	return ssh.Dial("tcp", fmt.Sprintf("%s:%d", s.Host, s.Port), sshCfg)
}

func sshRun(client *ssh.Client, cmd string) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr
	err = sess.Run(cmd)
	if err != nil {
		return stdout.String(), fmt.Errorf("%w: %s", err, stderr.String())
	}
	return stdout.String(), nil
}

func detectPlatform(client *ssh.Client) (string, string) {
	osOut, _ := sshRun(client, "uname -s")
	archOut, _ := sshRun(client, "uname -m")
	osName := strings.ToLower(strings.TrimSpace(osOut))
	arch := strings.TrimSpace(archOut)
	switch arch {
	case "x86_64":
		arch = "amd64"
	case "aarch64", "arm64":
		arch = "arm64"
	}
	return osName, arch
}

func writeRemoteFile(client *ssh.Client, path string, data []byte) error {
	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	go func() {
		stdin, _ := sess.StdinPipe()
		io.Copy(stdin, bytes.NewReader(data))
		stdin.Close()
	}()
	return sess.Run(fmt.Sprintf("cat > %s", path))
}

func scpFile(client *ssh.Client, localPath, remotePath string, mode os.FileMode) error {
	data, err := os.ReadFile(localPath)
	if err != nil {
		return err
	}
	if err := writeRemoteFile(client, remotePath, data); err != nil {
		return err
	}
	sshRun(client, fmt.Sprintf("chmod %o %s", mode, remotePath))
	return nil
}

func installLinuxService(client *ssh.Client, cfg *config.Config, nodeName string) {
	service := fmt.Sprintf(`[Unit]
Description=limguard
After=network-online.target
Before=kubelet.service

[Service]
ExecStartPre=/sbin/modprobe wireguard || true
ExecStart=%s run --config %s --node-name %s
Restart=always
AmbientCapabilities=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
`, cfg.BinaryPath, config.DefaultConfigPath, nodeName)

	writeRemoteFile(client, "/etc/systemd/system/limguard.service", []byte(service))
	sshRun(client, "systemctl daemon-reload")
	sshRun(client, "systemctl enable limguard")
	sshRun(client, "systemctl restart limguard")
}

func installDarwinService(client *ssh.Client, cfg *config.Config, nodeName string) {
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.limrun.limguard</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>run</string>
        <string>--config</string>
        <string>%s</string>
        <string>--node-name</string>
        <string>%s</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
`, cfg.BinaryPath, config.DefaultConfigPath, nodeName)

	plistPath := "/Library/LaunchDaemons/com.limrun.limguard.plist"
	sshRun(client, fmt.Sprintf("launchctl unload %s 2>/dev/null || true", plistPath))
	writeRemoteFile(client, plistPath, []byte(plist))
	sshRun(client, fmt.Sprintf("launchctl load %s", plistPath))
}

func mustMarshal(cfg *config.Config) []byte {
	// Use yaml.Marshal via Save to temp, but we'll just marshal directly
	data, _ := cfg.ToYAML()
	return data
}

func newLogger(debug bool) *slog.Logger {
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
}

func newLoggerStderr(debug bool) *slog.Logger {
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}
