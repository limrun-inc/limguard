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
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// ApplyOptions holds options for the Apply command.
type ApplyOptions struct {
	ConfigPath string
	SSHKeyPath string
	Debug      bool
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
			return fmt.Errorf("compute local binary hash for %s: %w", name, err)
		}
		remoteHash, _ := remoteFileSHA256(nc.ssh, nc.sftp, cfg.BinaryPath)

		if localHash != remoteHash {
			log.Info("copying binary", "node", name, "localHash", localHash[:8], "remoteHash", remoteHash[:min(8, len(remoteHash))])
			// Copy binary to temp location via SFTP
			tmpBinary := "/tmp/limguard-binary"
			if err := sftpCopyFile(nc.sftp, localBinaryPath, tmpBinary); err != nil {
				return fmt.Errorf("copy binary to %s: %w", name, err)
			}
		} else {
			log.Info("binary unchanged", "node", name, "sha256", localHash[:8])
		}

		// Write minimal config for this node (empty publicKey to skip validation during bootstrap)
		minCfg := &Config{
			InterfaceName:  cfg.InterfaceName,
			ListenPort:     cfg.ListenPort,
			PrivateKeyPath: cfg.PrivateKeyPath,
			Nodes:          map[string]Node{name: {WireguardIP: node.WireguardIP, Endpoint: node.Endpoint, PublicKey: ""}},
		}
		tmpCfg := "/tmp/limguard-bootstrap.yaml"
		cfgData, err := minCfg.ToYAML()
		if err != nil {
			return fmt.Errorf("marshal config for %s: %w", name, err)
		}
		if err := sftpWriteFile(nc.sftp, tmpCfg, cfgData); err != nil {
			return fmt.Errorf("write config to %s: %w", name, err)
		}

		// Run all privileged operations in a single bash session (elevated if needed)
		setupScript := fmt.Sprintf(`
mkdir -p %s %s
if [ -f /tmp/limguard-binary ]; then mv /tmp/limguard-binary %s && chmod 755 %s; fi
mv %s %s
`, filepath.Dir(DefaultConfigPath), filepath.Dir(cfg.PrivateKeyPath),
			cfg.BinaryPath, cfg.BinaryPath,
			tmpCfg, DefaultConfigPath)

		if _, err := runAsRoot(nc.ssh, nc.isRoot, setupScript); err != nil {
			return fmt.Errorf("setup node %s: %w", name, err)
		}

		// Install and start service (runs limguard run, which bootstraps if needed)
		if nc.osName == "linux" {
			if err := installLinuxService(nc.ssh, nc.sftp, nc.isRoot, cfg, name); err != nil {
				return fmt.Errorf("install linux service on %s: %w", name, err)
			}
		} else {
			if err := installDarwinService(nc.ssh, nc.sftp, nc.isRoot, cfg, name); err != nil {
				return fmt.Errorf("install darwin service on %s: %w", name, err)
			}
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
			return fmt.Errorf("wait for pubkey on %s: %w\nservice logs:\n%s", name, err, serviceLogs)
		}
		publicKeys[name] = pubKey
		log.Info("bootstrapped", "node", name, "publicKey", pubKey)
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

	// Pass 2: Distribute full config and restart services (reuse connections)
	log.Info("pass 2: distributing full config")
	cfgYAML, err := cfg.ToYAML()
	if err != nil {
		return fmt.Errorf("marshal final config: %w", err)
	}

	for name := range cfg.Nodes {
		nc := clients[name]
		log.Info("updating config", "node", name)

		// Write final config via SFTP
		tmpCfg := "/tmp/limguard.yaml"
		if err := sftpWriteFile(nc.sftp, tmpCfg, cfgYAML); err != nil {
			return fmt.Errorf("write final config to %s: %w", name, err)
		}

		// Move config and restart service in single elevated session
		var restartErr error
		if nc.osName == "linux" {
			_, restartErr = runAsRoot(nc.ssh, nc.isRoot, fmt.Sprintf("mv %s %s && systemctl restart limguard", tmpCfg, DefaultConfigPath))
		} else {
			plistPath := "/Library/LaunchDaemons/com.limrun.limguard.plist"
			_, restartErr = runAsRoot(nc.ssh, nc.isRoot, fmt.Sprintf("mv %s %s && launchctl unload %s && launchctl load %s",
				tmpCfg, DefaultConfigPath, plistPath, plistPath))
		}
		if restartErr != nil {
			return fmt.Errorf("restart service on %s: %w", name, restartErr)
		}

		log.Info("configured", "node", name)
	}

	log.Info("deployment complete")
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
			kp := filepath.Join(home, ".ssh", name)
			if key, err := os.ReadFile(kp); err == nil {
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
	return ssh.Dial("tcp", net.JoinHostPort(s.Host, fmt.Sprintf("%d", s.Port)), sshCfg)
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

func installLinuxService(sshClient *ssh.Client, sftpClient *sftp.Client, isRoot bool, cfg *Config, nodeName string) error {
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
	if err := sftpWriteFile(sftpClient, tmpService, []byte(service)); err != nil {
		return fmt.Errorf("write service file: %w", err)
	}
	_, err := runAsRoot(sshClient, isRoot, fmt.Sprintf("mv %s /etc/systemd/system/limguard.service && systemctl daemon-reload && systemctl enable limguard && systemctl restart limguard", tmpService))
	return err
}

func installDarwinService(sshClient *ssh.Client, sftpClient *sftp.Client, isRoot bool, cfg *Config, nodeName string) error {
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
`, cfg.BinaryPath, DefaultConfigPath, nodeName)

	plistPath := "/Library/LaunchDaemons/com.limrun.limguard.plist"
	tmpPlist := "/tmp/com.limrun.limguard.plist"
	if err := sftpWriteFile(sftpClient, tmpPlist, []byte(plist)); err != nil {
		return fmt.Errorf("write plist file: %w", err)
	}
	_, err := runAsRoot(sshClient, isRoot, fmt.Sprintf("launchctl unload %s 2>/dev/null || true; mv %s %s && launchctl load %s", plistPath, tmpPlist, plistPath, plistPath))
	return err
}
