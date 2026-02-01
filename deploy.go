package limguard

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
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/sync/errgroup"
)

// ApplyOptions holds options for the Apply command.
type ApplyOptions struct {
	ConfigPath string
	SSHKeyPath string
	Debug      bool
}

// nodeConn holds connection info for a node during deployment.
type nodeConn struct {
	ssh    *ssh.Client
	sftp   *sftp.Client
	osName string
	arch   string
	isRoot bool
	local  bool // true if this is the local machine (ssh.host: self)
}

// Apply deploys limguard to remote nodes via SSH.
func Apply(ctx context.Context, args []string, log *slog.Logger) error {
	opts, err := parseApplyArgs(args)
	if err != nil {
		return err
	}

	if log == nil {
		log = newLogger(opts.Debug)
	}

	cfg, err := LoadConfig(opts.ConfigPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if err := cfg.ValidateForDeploy(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	// Check for local nodes (ssh.host: self)
	var localNodeName string
	for name, node := range cfg.Nodes {
		if isLocalNode(node) {
			if localNodeName != "" {
				return fmt.Errorf("multiple local nodes not allowed: %q and %q both have ssh.host: self", localNodeName, name)
			}
			localNodeName = name
		}
	}

	// If a local node exists, require root privileges
	if localNodeName != "" && os.Geteuid() != 0 {
		return fmt.Errorf("local node %q requires root privileges; re-run: sudo limguard apply ...", localNodeName)
	}

	// Connect to all nodes and keep connections open (in parallel)
	clients := make(map[string]*nodeConn)
	var clientsMu sync.Mutex
	defer func() {
		for _, nc := range clients {
			if nc.sftp != nil {
				nc.sftp.Close()
			}
			if nc.ssh != nil {
				nc.ssh.Close()
			}
		}
	}()

	log.Info("connecting to nodes")
	gConnect, _ := errgroup.WithContext(ctx)
	for name, node := range cfg.Nodes {
		name, node := name, node // capture loop variables

		gConnect.Go(func() error {
			// Handle local node (ssh.host: self)
			if isLocalNode(node) {
				osName, arch := localDetectPlatform()
				isRoot := os.Geteuid() == 0

				clientsMu.Lock()
				clients[name] = &nodeConn{osName: osName, arch: arch, isRoot: isRoot, local: true}
				clientsMu.Unlock()

				log.Info("local node", "node", name, "os", osName, "arch", arch, "root", isRoot)
				return nil
			}

			// Remote node - connect via SSH
			sshClient, err := sshConnect(node.SSH, opts.SSHKeyPath)
			if err != nil {
				return fmt.Errorf("ssh connect to %s: %w", name, err)
			}
			sftpClient, err := sftp.NewClient(sshClient)
			if err != nil {
				sshClient.Close()
				return fmt.Errorf("sftp connect to %s: %w", name, err)
			}
			osName, arch := detectPlatform(sshClient)
			// Check if already root (uid 0)
			uidOut, _ := sshRun(sshClient, "id -u")
			isRoot := strings.TrimSpace(uidOut) == "0"

			clientsMu.Lock()
			clients[name] = &nodeConn{ssh: sshClient, sftp: sftpClient, osName: osName, arch: arch, isRoot: isRoot}
			clientsMu.Unlock()

			log.Info("connected", "node", name, "os", osName, "arch", arch, "root", isRoot)
			return nil
		})
	}

	if err := gConnect.Wait(); err != nil {
		return err
	}

	// Pass 1: Bootstrap each node (in parallel)
	log.Info("pass 1: bootstrapping nodes")
	publicKeys := make(map[string]string)
	var pkMu sync.Mutex

	g, _ := errgroup.WithContext(ctx)
	for name, node := range cfg.Nodes {
		name, node := name, node // capture loop variables
		nc := clients[name]

		g.Go(func() error {
			log.Info("bootstrapping", "node", name)

			binaryName := fmt.Sprintf("limguard-%s-%s", nc.osName, nc.arch)
			srcBinaryPath := filepath.Join(cfg.ArtifactDir, binaryName)

			// Check if binary needs to be copied (compare SHA256 hashes)
			srcHash, err := fileSHA256(srcBinaryPath)
			if err != nil {
				return fmt.Errorf("compute source binary hash for %s: %w", name, err)
			}

			var installedHash string
			if nc.local {
				installedHash, _ = fileSHA256(cfg.BinaryPath)
			} else {
				installedHash, _ = remoteFileSHA256(nc.ssh, nc.sftp, cfg.BinaryPath)
			}

			if srcHash != installedHash {
				log.Info("copying binary", "node", name, "srcHash", srcHash[:8], "installedHash", installedHash[:min(8, len(installedHash))])
				tmpBinary := "/tmp/limguard-binary"
				if nc.local {
					if err := localCopyFile(srcBinaryPath, tmpBinary); err != nil {
						return fmt.Errorf("copy binary to %s: %w", name, err)
					}
				} else {
					if err := sftpCopyFile(nc.sftp, srcBinaryPath, tmpBinary); err != nil {
						return fmt.Errorf("copy binary to %s: %w", name, err)
					}
				}
			} else {
				log.Info("binary unchanged", "node", name, "sha256", srcHash[:8])
			}

			// Write minimal config for this node (empty publicKey to skip validation during bootstrap)
			minCfg := &Config{
				LinuxInterfaceName:  cfg.LinuxInterfaceName,
				DarwinInterfaceName: cfg.DarwinInterfaceName,
				PrivateKeyPath:      cfg.PrivateKeyPath,
				Nodes:               map[string]Node{name: {WireguardIP: node.WireguardIP, Endpoint: node.Endpoint, PublicKey: "", InterfaceName: node.InterfaceName}},
			}
			tmpCfg := "/tmp/limguard-bootstrap.yaml"
			cfgData, err := minCfg.ToYAML()
			if err != nil {
				return fmt.Errorf("marshal config for %s: %w", name, err)
			}
			if nc.local {
				if err := os.WriteFile(tmpCfg, cfgData, 0644); err != nil {
					return fmt.Errorf("write config to %s: %w", name, err)
				}
			} else {
				if err := sftpWriteFile(nc.sftp, tmpCfg, cfgData); err != nil {
					return fmt.Errorf("write config to %s: %w", name, err)
				}
			}

			// Run all privileged operations in a single bash session (elevated if needed)
			setupScript := fmt.Sprintf(`
mkdir -p %s %s
if [ -f /tmp/limguard-binary ]; then mv /tmp/limguard-binary %s && chmod 755 %s; fi
mv %s %s
`, filepath.Dir(DefaultConfigPath), filepath.Dir(cfg.PrivateKeyPath),
				cfg.BinaryPath, cfg.BinaryPath,
				tmpCfg, DefaultConfigPath)

			if nc.local {
				if _, err := localRunAsRoot(setupScript); err != nil {
					return fmt.Errorf("setup node %s: %w", name, err)
				}
			} else {
				if _, err := runAsRoot(nc.ssh, nc.isRoot, setupScript); err != nil {
					return fmt.Errorf("setup node %s: %w", name, err)
				}
			}

			// Install and start service (runs limguard run, which bootstraps if needed)
			if nc.osName == "linux" {
				if err := installLinuxService(nc.ssh, nc.sftp, nc.isRoot, nc.local, cfg, name); err != nil {
					return fmt.Errorf("install linux service on %s: %w", name, err)
				}
			} else {
				if err := installDarwinService(nc.ssh, nc.sftp, nc.isRoot, nc.local, cfg, name); err != nil {
					return fmt.Errorf("install darwin service on %s: %w", name, err)
				}
			}

			// Poll for pubkey file (written by limguard run on startup)
			pubkeyPath := cfg.PrivateKeyPath + ".pub"
			var pubKey string
			if nc.local {
				pubKey, err = waitForLocalPubkey(pubkeyPath, 3*time.Second)
			} else {
				pubKey, err = waitForPubkey(nc.ssh, nc.sftp, nc.isRoot, pubkeyPath, 3*time.Second)
			}
			if err != nil {
				// Fetch service logs to show what went wrong
				var serviceLogs string
				if nc.local {
					if nc.osName == "linux" {
						serviceLogs, _ = localRunAsRoot("journalctl -u limguard -n 50 --no-pager 2>&1")
					} else {
						serviceLogs, _ = localRunAsRoot("cat /var/log/system.log | grep limguard | tail -50 2>&1")
					}
				} else {
					if nc.osName == "linux" {
						serviceLogs, _ = runAsRoot(nc.ssh, nc.isRoot, "journalctl -u limguard -n 50 --no-pager 2>&1")
					} else {
						serviceLogs, _ = runAsRoot(nc.ssh, nc.isRoot, "cat /var/log/system.log | grep limguard | tail -50 2>&1")
					}
				}
				return fmt.Errorf("wait for pubkey on %s: %w\nservice logs:\n%s", name, err, serviceLogs)
			}

			pkMu.Lock()
			publicKeys[name] = pubKey
			pkMu.Unlock()

			log.Info("bootstrapped", "node", name, "publicKey", pubKey)
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return err
	}

	// Update config with public keys
	for name, pk := range publicKeys {
		node := cfg.Nodes[name]
		node.PublicKey = pk
		cfg.Nodes[name] = node
	}

	// Save updated config locally
	if err := cfg.Save(opts.ConfigPath); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	log.Info("updated local config with public keys")

	// Pass 2: Distribute full config (in parallel)
	// If service is running, limguard will pick up the config change via file watcher.
	// If not running, start the service.
	log.Info("pass 2: distributing full config")
	cfgYAML, err := cfg.ToYAML()
	if err != nil {
		return fmt.Errorf("marshal final config: %w", err)
	}

	g2, _ := errgroup.WithContext(ctx)
	for name := range cfg.Nodes {
		name := name // capture loop variable
		nc := clients[name]

		g2.Go(func() error {
			log.Info("updating config", "node", name)

			// Write final config
			tmpCfg := "/tmp/limguard.yaml"
			if nc.local {
				if err := os.WriteFile(tmpCfg, cfgYAML, 0644); err != nil {
					return fmt.Errorf("write final config to %s: %w", name, err)
				}
			} else {
				if err := sftpWriteFile(nc.sftp, tmpCfg, cfgYAML); err != nil {
					return fmt.Errorf("write final config to %s: %w", name, err)
				}
			}

			// Move config and restart service to pick up new config
			var out string
			var ensureErr error
			if nc.osName == "linux" {
				script := fmt.Sprintf(`
mv %s %s
if systemctl is-active --quiet limguard; then
    systemctl restart limguard
    echo "RESTARTED"
else
    systemctl start limguard
    echo "STARTED"
fi
`, tmpCfg, DefaultConfigPath)
				if nc.local {
					out, ensureErr = localRunAsRoot(script)
				} else {
					out, ensureErr = runAsRoot(nc.ssh, nc.isRoot, script)
				}
			} else {
				plistPath := "/Library/LaunchDaemons/com.limrun.limguard.plist"
				script := fmt.Sprintf(`
mv %s %s
if launchctl list | grep -q com.limrun.limguard; then
    launchctl kickstart -k system/com.limrun.limguard
    echo "RESTARTED"
else
    launchctl load %s
    echo "STARTED"
fi
`, tmpCfg, DefaultConfigPath, plistPath)
				if nc.local {
					out, ensureErr = localRunAsRoot(script)
				} else {
					out, ensureErr = runAsRoot(nc.ssh, nc.isRoot, script)
				}
			}
			if ensureErr != nil {
				return fmt.Errorf("update config on %s: %w", name, ensureErr)
			}

			status := strings.TrimSpace(out)
			if status == "RESTARTED" {
				log.Info("configured", "node", name, "action", "service restarted")
			} else {
				log.Info("configured", "node", name, "action", "service started")
			}
			return nil
		})
	}

	if err := g2.Wait(); err != nil {
		return err
	}

	// Pass 3: Validate mesh connectivity (in parallel)
	log.Info("pass 3: validating mesh connectivity")

	// Wait for config to be picked up by file watcher
	time.Sleep(2 * time.Second)

	g3, _ := errgroup.WithContext(ctx)
	for name := range cfg.Nodes {
		name := name // capture loop variable
		nc := clients[name]
		node := cfg.Nodes[name]

		g3.Go(func() error {
			// Ping all peers from this node
			for peerName, peer := range cfg.Nodes {
				if peerName == name {
					continue // skip self
				}

				// Ping peer's WireGuard IP
				pingCmd := fmt.Sprintf("ping -c 3 -W 2 %s", peer.WireguardIP)
				var out string
				var err error
				if nc.local {
					out, err = localRunAsRoot(pingCmd)
				} else {
					out, err = runAsRoot(nc.ssh, nc.isRoot, pingCmd)
				}
				if err != nil {
					// Gather debug info on ping failure
					debugInfo := gatherPingDebugInfo(clients, name, peerName, log)
					return fmt.Errorf("ping from %s (%s) to %s (%s) failed: %w\n\n%s",
						name, node.WireguardIP, peerName, peer.WireguardIP, err, debugInfo)
				}

				// Parse latency from ping output (e.g., "rtt min/avg/max/mdev = 0.1/0.2/0.3/0.0 ms")
				latency := parsePingLatency(out)
				log.Info("ping ok", "from", name, "to", peerName, "ip", peer.WireguardIP, "latency", latency)
			}
			return nil
		})
	}

	if err := g3.Wait(); err != nil {
		return err
	}

	log.Info("deployment complete - mesh connectivity verified")
	return nil
}

func parseApplyArgs(args []string) (*ApplyOptions, error) {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	opts := &ApplyOptions{}
	fs.StringVar(&opts.ConfigPath, "config", "limguard.yaml", "Config file path")
	fs.StringVar(&opts.SSHKeyPath, "ssh-key", "", "SSH private key path")
	fs.BoolVar(&opts.Debug, "debug", false, "Debug logging")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return opts, nil
}

// SSH helpers

func sshConnect(s *SSH, keyPath string) (*ssh.Client, error) {
	var authMethods []ssh.AuthMethod
	var signers []ssh.Signer

	// Get home directory early for path expansion
	home, _ := os.UserHomeDir()

	// Explicit key from command line (error if specified but can't be used)
	if keyPath != "" {
		signer, err := loadPrivateKey(keyPath)
		if err != nil {
			return nil, fmt.Errorf("load SSH key %s: %w", keyPath, err)
		}
		signers = append(signers, signer)
	}

	// Identity file from config (error if specified but can't be used)
	if s.IdentityFile != "" {
		identityPath := s.IdentityFile
		if strings.HasPrefix(identityPath, "~/") {
			identityPath = filepath.Join(home, identityPath[2:])
		}
		signer, err := loadPrivateKey(identityPath)
		if err != nil {
			return nil, fmt.Errorf("load SSH key %s: %w", identityPath, err)
		}
		signers = append(signers, signer)
	}

	// Default keys (silently skip if not available)
	if home != "" {
		for _, name := range []string{"id_ed25519", "id_rsa"} {
			kp := filepath.Join(home, ".ssh", name)
			if signer, err := loadPrivateKey(kp); err == nil {
				signers = append(signers, signer)
			}
		}
	}

	// Add explicit signers first (higher priority than agent)
	if len(signers) > 0 {
		authMethods = append(authMethods, ssh.PublicKeys(signers...))
	}

	// SSH agent as fallback
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if conn, err := net.Dial("unix", sock); err == nil {
			authMethods = append(authMethods, ssh.PublicKeysCallback(agent.NewClient(conn).Signers))
		}
	}

	if len(authMethods) == 0 {
		return nil, fmt.Errorf("no SSH authentication methods available")
	}

	sshCfg := &ssh.ClientConfig{
		User:            s.User,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
	}
	return ssh.Dial("tcp", net.JoinHostPort(s.Host, fmt.Sprintf("%d", s.Port)), sshCfg)
}

// loadPrivateKey reads and parses an SSH private key file.
// Returns a helpful error if the key is passphrase-protected.
func loadPrivateKey(path string) (ssh.Signer, error) {
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		if strings.Contains(err.Error(), "cannot decode encrypted private key") {
			return nil, fmt.Errorf("key is passphrase-protected (add to ssh-agent with: ssh-add %s)", path)
		}
		return nil, err
	}
	return signer, nil
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

// runAsRoot runs a shell script as root by piping the script to stdin.
// This avoids shell quoting issues with the script content.
func runAsRoot(client *ssh.Client, isRoot bool, script string) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()

	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr
	sess.Stdin = strings.NewReader(script)

	cmd := "sh -s"
	if !isRoot {
		cmd = "sudo sh -s"
	}

	if err := sess.Run(cmd); err != nil {
		return stdout.String(), fmt.Errorf("%w: %s", err, stderr.String())
	}
	return stdout.String(), nil
}

// parsePingLatency extracts the average latency from ping output.
// Returns the avg latency string (e.g., "1.234 ms") or "unknown" if parsing fails.
func parsePingLatency(output string) string {
	// Linux format: rtt min/avg/max/mdev = 0.123/0.456/0.789/0.012 ms
	// macOS format: round-trip min/avg/max/stddev = 0.123/0.456/0.789/0.012 ms
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "min/avg/max") {
			// Find the = and parse the values after it
			parts := strings.Split(line, "=")
			if len(parts) < 2 {
				continue
			}
			stats := strings.TrimSpace(parts[1])
			// stats is like "0.123/0.456/0.789/0.012 ms"
			fields := strings.Fields(stats)
			if len(fields) < 2 {
				continue
			}
			values := strings.Split(fields[0], "/")
			unit := fields[1]
			if len(values) >= 2 {
				return values[1] + " " + unit // avg value
			}
		}
	}
	return "unknown"
}

// gatherPingDebugInfo collects debug information when a ping fails
func gatherPingDebugInfo(clients map[string]*nodeConn, srcNode, dstNode string, log *slog.Logger) string {
	var sb strings.Builder
	sb.WriteString("=== DEBUG INFO ===\n")

	// Gather info from source node
	if nc, ok := clients[srcNode]; ok {
		sb.WriteString(fmt.Sprintf("\n--- %s (source) ---\n", srcNode))

		// WireGuard status (sudo needed on macOS)
		wgCmd := "wg show 2>&1 || echo '(wg command not found or failed)'"
		var wgOut string
		if nc.local {
			wgOut, _ = localRunAsRoot(wgCmd)
		} else if nc.ssh != nil {
			wgOut, _ = runAsRoot(nc.ssh, nc.isRoot, wgCmd)
		}
		sb.WriteString("WireGuard status:\n")
		sb.WriteString(wgOut)
		sb.WriteString("\n")

		// Network interfaces (to see if wg0 exists)
		var ifCmd string
		if nc.osName == "linux" {
			ifCmd = "ip addr show wg0 2>&1 || echo '(wg0 interface not found)'"
		} else {
			ifCmd = "ifconfig utun0 2>&1 || ifconfig utun1 2>&1 || ifconfig utun2 2>&1 || echo '(no utun interface found)'"
		}
		var ifOut string
		if nc.local {
			ifOut, _ = localRunAsRoot(ifCmd)
		} else if nc.ssh != nil {
			ifOut, _ = runAsRoot(nc.ssh, nc.isRoot, ifCmd)
		}
		sb.WriteString("WireGuard interface:\n")
		sb.WriteString(ifOut)
		sb.WriteString("\n")

		// Service logs (last 30 lines)
		var logsCmd string
		if nc.osName == "linux" {
			logsCmd = "journalctl -u limguard --no-pager -n 30 2>&1"
		} else {
			logsCmd = "cat /var/log/limguard.log 2>&1 | tail -30 || echo '(no log file found)'"
		}
		var logsOut string
		if nc.local {
			logsOut, _ = localRunAsRoot(logsCmd)
		} else if nc.ssh != nil {
			logsOut, _ = runAsRoot(nc.ssh, nc.isRoot, logsCmd)
		}
		sb.WriteString("Service logs:\n")
		sb.WriteString(logsOut)
		sb.WriteString("\n")
	}

	// Gather info from destination node
	if nc, ok := clients[dstNode]; ok {
		sb.WriteString(fmt.Sprintf("\n--- %s (destination) ---\n", dstNode))

		// WireGuard status
		wgCmd := "wg show 2>&1 || echo '(wg command not found or failed)'"
		var wgOut string
		if nc.local {
			wgOut, _ = localRunAsRoot(wgCmd)
		} else if nc.ssh != nil {
			wgOut, _ = runAsRoot(nc.ssh, nc.isRoot, wgCmd)
		}
		sb.WriteString("WireGuard status:\n")
		sb.WriteString(wgOut)
		sb.WriteString("\n")

		// Network interfaces
		var ifCmd string
		if nc.osName == "linux" {
			ifCmd = "ip addr show wg0 2>&1 || echo '(wg0 interface not found)'"
		} else {
			ifCmd = "ifconfig utun0 2>&1 || ifconfig utun1 2>&1 || ifconfig utun2 2>&1 || echo '(no utun interface found)'"
		}
		var ifOut string
		if nc.local {
			ifOut, _ = localRunAsRoot(ifCmd)
		} else if nc.ssh != nil {
			ifOut, _ = runAsRoot(nc.ssh, nc.isRoot, ifCmd)
		}
		sb.WriteString("WireGuard interface:\n")
		sb.WriteString(ifOut)
		sb.WriteString("\n")
	}

	sb.WriteString("\n=== END DEBUG INFO ===\n")
	return sb.String()
}

func waitForPubkey(sshClient *ssh.Client, sftpClient *sftp.Client, isRoot bool, path string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		// Try SFTP first (works if file is readable by ssh user)
		if data, err := sftpReadFile(sftpClient, path); err == nil && len(data) > 0 {
			return strings.TrimSpace(string(data)), nil
		}
		// Fall back to shell with sudo if needed (file might be root-owned)
		if out, err := runAsRoot(sshClient, isRoot, fmt.Sprintf("cat %q 2>/dev/null", path)); err == nil && strings.TrimSpace(out) != "" {
			return strings.TrimSpace(out), nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return "", fmt.Errorf("timeout waiting for %s", path)
}

// waitForLocalPubkey polls for the pubkey file locally.
func waitForLocalPubkey(path string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
			return strings.TrimSpace(string(data)), nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return "", fmt.Errorf("timeout waiting for %s", path)
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

// fileSHA256 computes SHA256 of a local file using streaming.
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
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

	if _, err := io.Copy(remote, local); err != nil {
		return err
	}

	// Preserve executable permission
	localStat, err := local.Stat()
	if err != nil {
		return err
	}
	return client.Chmod(remotePath, localStat.Mode())
}

// sftpFileSHA256 computes SHA256 of a remote file using streaming.
func sftpFileSHA256(client *sftp.Client, path string) (string, error) {
	f, err := client.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// remoteFileSHA256 computes SHA256 of a remote file.
// Tries sha256sum command first (faster, no download), then shasum -a 256, falls back to SFTP.
func remoteFileSHA256(sshClient *ssh.Client, sftpClient *sftp.Client, path string) (string, error) {
	// Try sha256sum command first (available on most Linux systems)
	if out, err := sshRun(sshClient, fmt.Sprintf("sha256sum %q 2>/dev/null | cut -d' ' -f1", path)); err == nil {
		hash := strings.TrimSpace(out)
		if len(hash) == 64 { // valid SHA256 hex string
			return hash, nil
		}
	}
	// Try shasum -a 256 (available on macOS)
	if out, err := sshRun(sshClient, fmt.Sprintf("shasum -a 256 %q 2>/dev/null | cut -d' ' -f1", path)); err == nil {
		hash := strings.TrimSpace(out)
		if len(hash) == 64 {
			return hash, nil
		}
	}
	// Fall back to SFTP (download and hash locally)
	return sftpFileSHA256(sftpClient, path)
}

func installLinuxService(sshClient *ssh.Client, sftpClient *sftp.Client, isRoot bool, local bool, cfg *Config, nodeName string) error {
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
`, cfg.BinaryPath, DefaultConfigPath, nodeName)

	tmpService := "/tmp/limguard.service"
	if local {
		if err := os.WriteFile(tmpService, []byte(service), 0644); err != nil {
			return fmt.Errorf("write service file: %w", err)
		}
		_, err := localRunAsRoot(fmt.Sprintf("mv %s /etc/systemd/system/limguard.service && systemctl daemon-reload && systemctl enable limguard && systemctl restart limguard", tmpService))
		return err
	}

	if err := sftpWriteFile(sftpClient, tmpService, []byte(service)); err != nil {
		return fmt.Errorf("write service file: %w", err)
	}
	_, err := runAsRoot(sshClient, isRoot, fmt.Sprintf("mv %s /etc/systemd/system/limguard.service && systemctl daemon-reload && systemctl enable limguard && systemctl restart limguard", tmpService))
	return err
}

func installDarwinService(sshClient *ssh.Client, sftpClient *sftp.Client, isRoot bool, local bool, cfg *Config, nodeName string) error {
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
    <key>StandardOutPath</key>
    <string>/var/log/limguard.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/limguard.log</string>
</dict>
</plist>
`, cfg.BinaryPath, DefaultConfigPath, nodeName)

	plistPath := "/Library/LaunchDaemons/com.limrun.limguard.plist"
	tmpPlist := "/tmp/com.limrun.limguard.plist"

	if local {
		if err := os.WriteFile(tmpPlist, []byte(plist), 0644); err != nil {
			return fmt.Errorf("write plist file: %w", err)
		}
		_, err := localRunAsRoot(fmt.Sprintf("launchctl unload %s 2>/dev/null || true; mv %s %s && launchctl load %s", plistPath, tmpPlist, plistPath, plistPath))
		return err
	}

	if err := sftpWriteFile(sftpClient, tmpPlist, []byte(plist)); err != nil {
		return fmt.Errorf("write plist file: %w", err)
	}
	_, err := runAsRoot(sshClient, isRoot, fmt.Sprintf("launchctl unload %s 2>/dev/null || true; mv %s %s && launchctl load %s", plistPath, tmpPlist, plistPath, plistPath))
	return err
}

// isLocalNode returns true if the node is marked as local (ssh.host: self).
func isLocalNode(node Node) bool {
	return node.SSH != nil && strings.EqualFold(node.SSH.Host, "self")
}

// localRunAsRoot runs a shell script locally as root.
// If already root, runs directly; otherwise uses sudo.
func localRunAsRoot(script string) (string, error) {
	var cmd *exec.Cmd
	if os.Geteuid() == 0 {
		cmd = exec.Command("sh", "-s")
	} else {
		cmd = exec.Command("sudo", "sh", "-s")
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Stdin = strings.NewReader(script)

	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("%w: %s", err, stderr.String())
	}
	return stdout.String(), nil
}

// localCopyFile copies a file from src to dst locally.
func localCopyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return err
	}

	// Preserve executable permission
	srcStat, err := srcFile.Stat()
	if err != nil {
		return err
	}
	return os.Chmod(dst, srcStat.Mode())
}

// localDetectPlatform returns the OS and architecture of the local machine.
func localDetectPlatform() (string, string) {
	osName := runtime.GOOS
	arch := runtime.GOARCH
	return osName, arch
}
