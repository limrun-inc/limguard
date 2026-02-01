package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/limrun-inc/limguard"
	"github.com/limrun-inc/limguard/config"
	"github.com/limrun-inc/limguard/version"
	"github.com/pkg/sftp"
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
	case "apply":
		cmdApply(os.Args[2:])
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
  run        Run the daemon (bootstraps if needed)
  apply      Deploy to nodes via SSH
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

	// Bootstrap: ensure private key exists (generate if needed)
	privateKey, err := config.EnsurePrivateKey(cfg.PrivateKeyPath)
	if err != nil {
		log.Error("ensure private key", "error", err)
		os.Exit(1)
	}

	// Verify self's publicKey matches local key (if YAML has one)
	derivedPubKey := privateKey.PublicKey().String()
	if self.PublicKey != "" && self.PublicKey != derivedPubKey {
		log.Error("publicKey mismatch", "yaml", self.PublicKey, "derived", derivedPubKey)
		os.Exit(1)
	}

	// Write pubkey to file for apply command to read
	pubkeyPath := cfg.PrivateKeyPath + ".pub"
	if err := os.WriteFile(pubkeyPath, []byte(derivedPubKey+"\n"), 0644); err != nil {
		log.Error("write public key file", "error", err)
		os.Exit(1)
	}

	// Print public key to stdout
	fmt.Printf("LIMGUARD_PUBKEY=%s\n", derivedPubKey)

	nm, err := limguard.NewNetworkManager(cfg.InterfaceName, cfg.PrivateKeyPath, cfg.ListenPort, self.WireguardIP, log)
	if err != nil {
		log.Error("init network", "error", err)
		os.Exit(1)
	}

	// Mutex to protect cfg during reload
	var cfgMu sync.Mutex

	// Initial peer sync
	reconcilePeers(context.Background(), nm, cfg, name, log)

	// Health server
	go func() {
		http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
		http.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
		http.ListenAndServe(*healthAddr, nil)
	}()

	// Watch config
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Error("create file watcher", "error", err)
		os.Exit(1)
	}
	defer watcher.Close()

	if err := watcher.Add(*cfgPath); err != nil {
		log.Error("watch config file", "error", err)
		os.Exit(1)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Channel to signal reload (avoids timer race)
	reloadCh := make(chan struct{}, 1)

	// Reload goroutine
	go func() {
		for range reloadCh {
			cfgMu.Lock()
			newCfg, err := config.Load(*cfgPath)
			if err != nil {
				log.Error("reload config", "error", err)
				cfgMu.Unlock()
				continue
			}
			if err := newCfg.Validate(); err != nil {
				log.Error("invalid config", "error", err)
				cfgMu.Unlock()
				continue
			}
			cfg = newCfg
			reconcilePeers(context.Background(), nm, cfg, name, log)
			cfgMu.Unlock()
			log.Info("config reloaded")
		}
	}()

	var debounce *time.Timer
	for {
		select {
		case <-sigCh:
			log.Info("shutting down")
			return
		case ev, ok := <-watcher.Events:
			if !ok {
				return
			}
			if ev.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				if debounce != nil {
					debounce.Stop()
				}
				debounce = time.AfterFunc(500*time.Millisecond, func() {
					select {
					case reloadCh <- struct{}{}:
					default: // reload already pending
					}
				})
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Error("watcher error", "error", err)
		}
	}
}

func reconcilePeers(ctx context.Context, nm *limguard.NetworkManager, cfg *config.Config, selfName string, log *slog.Logger) map[string]bool {
	peers := cfg.GetPeers(selfName)
	desired := make(map[string]bool)

	for name, node := range peers {
		// Skip peers without publicKey (not yet bootstrapped)
		if node.PublicKey == "" {
			log.Warn("skipping peer without publicKey", "peer", name)
			continue
		}
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

// --- apply command ---

func cmdApply(args []string) {
	fs := flag.NewFlagSet("apply", flag.ExitOnError)
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

	// Connect to all nodes and keep connections open
	type nodeConn struct {
		ssh    *ssh.Client
		sftp   *sftp.Client
		osName string
		arch   string
		isRoot bool
	}
	clients := make(map[string]*nodeConn)
	defer func() {
		for _, nc := range clients {
			nc.sftp.Close()
			nc.ssh.Close()
		}
	}()

	log.Info("connecting to nodes")
	for name, node := range cfg.Nodes {
		sshClient, err := sshConnect(node.SSH, *sshKey)
		if err != nil {
			log.Error("ssh connect", "node", name, "error", err)
			os.Exit(1)
		}
		sftpClient, err := sftp.NewClient(sshClient)
		if err != nil {
			log.Error("sftp connect", "node", name, "error", err)
			os.Exit(1)
		}
		osName, arch := detectPlatform(sshClient)
		// Check if already root (uid 0)
		uidOut, _ := sshRun(sshClient, "id -u")
		isRoot := strings.TrimSpace(uidOut) == "0"
		clients[name] = &nodeConn{ssh: sshClient, sftp: sftpClient, osName: osName, arch: arch, isRoot: isRoot}
		log.Info("connected", "node", name, "os", osName, "arch", arch, "root", isRoot)
	}

	// Pass 1: Bootstrap each node
	log.Info("pass 1: bootstrapping nodes")
	publicKeys := make(map[string]string)

	for name, node := range cfg.Nodes {
		nc := clients[name]
		log.Info("bootstrapping", "node", name)

		binaryName := fmt.Sprintf("limguard-%s-%s", nc.osName, nc.arch)
		localBinaryPath := filepath.Join(cfg.ArtifactDir, binaryName)

		// Check if binary needs to be copied (compare SHA256 hashes)
		localHash, err := fileSHA256(localBinaryPath)
		if err != nil {
			log.Error("compute local binary hash", "node", name, "error", err)
			os.Exit(1)
		}
		remoteHash, _ := remoteFileSHA256(nc.ssh, nc.sftp, cfg.BinaryPath)

		if localHash != remoteHash {
			log.Info("copying binary", "node", name, "localHash", localHash[:8], "remoteHash", remoteHash[:min(8, len(remoteHash))])
			// Copy binary to temp location via SFTP
			tmpBinary := "/tmp/limguard-binary"
			if err := sftpCopyFile(nc.sftp, localBinaryPath, tmpBinary); err != nil {
				log.Error("copy binary", "node", name, "error", err)
				os.Exit(1)
			}
		} else {
			log.Info("binary unchanged", "node", name, "sha256", localHash[:8])
		}

		// Write minimal config for this node (empty publicKey to skip validation during bootstrap)
		minCfg := &config.Config{
			InterfaceName:  cfg.InterfaceName,
			ListenPort:     cfg.ListenPort,
			PrivateKeyPath: cfg.PrivateKeyPath,
			Nodes:          map[string]config.Node{name: {WireguardIP: node.WireguardIP, Endpoint: node.Endpoint, PublicKey: ""}},
		}
		tmpCfg := "/tmp/limguard-bootstrap.yaml"
		if err := sftpWriteFile(nc.sftp, tmpCfg, mustMarshal(minCfg)); err != nil {
			log.Error("write config", "node", name, "error", err)
			os.Exit(1)
		}

		// Run all privileged operations in a single bash session (elevated if needed)
		setupScript := fmt.Sprintf(`
mkdir -p %s %s
if [ -f /tmp/limguard-binary ]; then mv /tmp/limguard-binary %s && chmod 755 %s; fi
mv %s %s
`, filepath.Dir(config.DefaultConfigPath), filepath.Dir(cfg.PrivateKeyPath),
			cfg.BinaryPath, cfg.BinaryPath,
			tmpCfg, config.DefaultConfigPath)

		if _, err := runAsRoot(nc.ssh, nc.isRoot, setupScript); err != nil {
			log.Error("setup node", "node", name, "error", err)
			os.Exit(1)
		}

		// Install and start service (runs limguard run, which bootstraps if needed)
		if nc.osName == "linux" {
			installLinuxService(nc.ssh, nc.sftp, nc.isRoot, cfg, name)
		} else {
			installDarwinService(nc.ssh, nc.sftp, nc.isRoot, cfg, name)
		}

		// Poll for pubkey file (written by limguard run on startup)
		pubkeyPath := cfg.PrivateKeyPath + ".pub"
		pubKey, err := waitForPubkey(nc.ssh, nc.sftp, nc.isRoot, pubkeyPath, 3*time.Second)
		if err != nil {
			// Fetch service logs to show what went wrong
			var serviceLogs string
			if nc.osName == "linux" {
				serviceLogs, _ = runAsRoot(nc.ssh, nc.isRoot, "journalctl -u limguard -n 50 --no-pager 2>&1")
			} else {
				serviceLogs, _ = runAsRoot(nc.ssh, nc.isRoot, "cat /var/log/system.log | grep limguard | tail -50 2>&1")
			}
			log.Error("wait for pubkey", "node", name, "error", err, "serviceLogs", serviceLogs)
			os.Exit(1)
		}
		publicKeys[name] = pubKey
		log.Info("bootstrapped", "node", name, "publicKey", truncateKey(pubKey))
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

	// Pass 2: Distribute full config and restart services (reuse connections)
	log.Info("pass 2: distributing full config")
	cfgYAML := mustMarshal(cfg)

	for name := range cfg.Nodes {
		nc := clients[name]
		log.Info("updating config", "node", name)

		// Write final config via SFTP
		tmpCfg := "/tmp/limguard.yaml"
		if err := sftpWriteFile(nc.sftp, tmpCfg, cfgYAML); err != nil {
			log.Error("write config", "node", name, "error", err)
			os.Exit(1)
		}

		// Move config and restart service in single elevated session
		if nc.osName == "linux" {
			runAsRoot(nc.ssh, nc.isRoot, fmt.Sprintf("mv %s %s && systemctl restart limguard", tmpCfg, config.DefaultConfigPath))
		} else {
			plistPath := "/Library/LaunchDaemons/com.limrun.limguard.plist"
			runAsRoot(nc.ssh, nc.isRoot, fmt.Sprintf("mv %s %s && launchctl unload %s && launchctl load %s",
				tmpCfg, config.DefaultConfigPath, plistPath, plistPath))
		}

		log.Info("configured", "node", name)
	}

	log.Info("deployment complete")
}

// SSH helpers

func sshConnect(s *config.SSH, keyPath string) (*ssh.Client, error) {
	authMethods := []ssh.AuthMethod{}

	// Get home directory early for path expansion
	home, _ := os.UserHomeDir()

	// SSH agent
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if conn, err := net.Dial("unix", sock); err == nil {
			authMethods = append(authMethods, ssh.PublicKeysCallback(agent.NewClient(conn).Signers))
		}
	}

	// Explicit key from command line
	if keyPath != "" {
		if key, err := os.ReadFile(keyPath); err == nil {
			if signer, err := ssh.ParsePrivateKey(key); err == nil {
				authMethods = append(authMethods, ssh.PublicKeys(signer))
			}
		}
	}

	// Identity file from config (expand ~ to home directory)
	if s.IdentityFile != "" {
		identityPath := s.IdentityFile
		if strings.HasPrefix(identityPath, "~/") {
			identityPath = filepath.Join(home, identityPath[2:])
		}
		if key, err := os.ReadFile(identityPath); err == nil {
			if signer, err := ssh.ParsePrivateKey(key); err == nil {
				authMethods = append(authMethods, ssh.PublicKeys(signer))
			}
		}
	}

	// Default keys
	if home != "" {
		for _, name := range []string{"id_ed25519", "id_rsa"} {
			keyPath := filepath.Join(home, ".ssh", name)
			if key, err := os.ReadFile(keyPath); err == nil {
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

func waitForPubkey(sshClient *ssh.Client, sftpClient *sftp.Client, isRoot bool, path string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		// Try SFTP first (works if file is readable by ssh user)
		if data, err := sftpReadFile(sftpClient, path); err == nil && len(data) > 0 {
			return strings.TrimSpace(string(data)), nil
		}
		// Fall back to shell with sudo if needed (file might be root-owned)
		if out, err := runAsRoot(sshClient, isRoot, fmt.Sprintf("cat %s 2>/dev/null", path)); err == nil && strings.TrimSpace(out) != "" {
			return strings.TrimSpace(out), nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return "", fmt.Errorf("timeout waiting for %s", path)
}

// runAsRoot runs a shell script as root. If already root, runs directly.
// If not root, uses sudo to elevate privileges.
func runAsRoot(client *ssh.Client, isRoot bool, script string) (string, error) {
	if isRoot {
		return sshRun(client, fmt.Sprintf("sh -c '%s'", script))
	}
	return sshRun(client, fmt.Sprintf("sudo sh -c '%s'", script))
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

func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

// SFTP file operations

func sftpWriteFile(client *sftp.Client, path string, data []byte) error {
	f, err := client.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}

func sftpReadFile(client *sftp.Client, path string) ([]byte, error) {
	f, err := client.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

func sftpCopyFile(client *sftp.Client, localPath, remotePath string) error {
	local, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer local.Close()

	remote, err := client.Create(remotePath)
	if err != nil {
		return err
	}
	defer remote.Close()

	_, err = io.Copy(remote, local)
	if err != nil {
		return err
	}

	// Preserve executable permission
	localStat, err := local.Stat()
	if err != nil {
		return err
	}
	return client.Chmod(remotePath, localStat.Mode())
}

func sftpFileSHA256(client *sftp.Client, path string) (string, error) {
	data, err := sftpReadFile(client, path)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

// remoteFileSHA256 computes SHA256 of a remote file.
// Tries sha256sum command first (faster, no download), falls back to SFTP.
func remoteFileSHA256(sshClient *ssh.Client, sftpClient *sftp.Client, path string) (string, error) {
	// Try sha256sum command first (available on most Linux systems, some macOS)
	if out, err := sshRun(sshClient, fmt.Sprintf("sha256sum '%s' 2>/dev/null | cut -d' ' -f1", path)); err == nil {
		hash := strings.TrimSpace(out)
		if len(hash) == 64 { // valid SHA256 hex string
			return hash, nil
		}
	}
	// Fall back to SFTP (download and hash locally)
	return sftpFileSHA256(sftpClient, path)
}

func installLinuxService(sshClient *ssh.Client, sftpClient *sftp.Client, isRoot bool, cfg *config.Config, nodeName string) {
	service := fmt.Sprintf(`[Unit]
Description=limguard WireGuard mesh network manager
After=network-online.target
Wants=network-online.target
Before=kubelet.service

[Service]
Type=simple
ExecStartPre=-/sbin/modprobe wireguard
ExecStart=%s run --config %s --node-name %s
Restart=always
RestartSec=5

# Security
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
NoNewPrivileges=true

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=limguard

[Install]
WantedBy=multi-user.target
`, cfg.BinaryPath, config.DefaultConfigPath, nodeName)

	tmpService := "/tmp/limguard.service"
	sftpWriteFile(sftpClient, tmpService, []byte(service))
	runAsRoot(sshClient, isRoot, fmt.Sprintf("mv %s /etc/systemd/system/limguard.service && systemctl daemon-reload && systemctl enable limguard && systemctl restart limguard", tmpService))
}

func installDarwinService(sshClient *ssh.Client, sftpClient *sftp.Client, isRoot bool, cfg *config.Config, nodeName string) {
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
	tmpPlist := "/tmp/com.limrun.limguard.plist"
	sftpWriteFile(sftpClient, tmpPlist, []byte(plist))
	runAsRoot(sshClient, isRoot, fmt.Sprintf("launchctl unload %s 2>/dev/null || true; mv %s %s && launchctl load %s", plistPath, tmpPlist, plistPath, plistPath))
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

// truncateKey returns a truncated version of a public key for logging.
func truncateKey(key string) string {
	if len(key) > 8 {
		return key[:8] + "..."
	}
	return key
}
