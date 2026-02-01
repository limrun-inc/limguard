//go:build integration

package limguard_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/limrun-inc/limguard"
)

const (
	node1Name = "limguard-test-1"
	node2Name = "limguard-test-2"

	wgIP1 = "10.200.0.1"
	wgIP2 = "10.200.0.2"
)

// TestIntegration runs the full Lima VM integration test.
// Run with: go test -tags=integration -v -timeout=10m
func TestIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Check prerequisites
	checkPrerequisites(t)

	// Get current user for SSH config
	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("get current user: %v", err)
	}

	// Find SSH key
	sshKeyPath := findSSHKey(t)

	// Create temp directory for test artifacts
	tmpDir, err := os.MkdirTemp("", "limguard-integration-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Ensure VMs are cleaned up at the end
	defer cleanupVMs(t)

	// Step 1: Create and start Lima VMs
	t.Log("Creating Lima VMs...")
	createVM(t, node1Name)
	createVM(t, node2Name)

	// Step 2: Get VM information
	t.Log("Getting VM information...")
	sshPort1 := getSSHPort(t, node1Name)
	sshPort2 := getSSHPort(t, node2Name)
	endpoint1 := getVMIP(t, node1Name)
	endpoint2 := getVMIP(t, node2Name)

	t.Logf("Node 1: SSH port=%s, endpoint=%s", sshPort1, endpoint1)
	t.Logf("Node 2: SSH port=%s, endpoint=%s", sshPort2, endpoint2)

	// Step 3: Enable SSH access
	t.Log("Enabling SSH access...")
	enableSSHAccess(t, node1Name, sshKeyPath)
	enableSSHAccess(t, node2Name, sshKeyPath)

	// Step 4: Build limguard binaries
	t.Log("Building limguard binaries...")
	distDir := filepath.Join(tmpDir, "dist")
	if err := os.MkdirAll(distDir, 0755); err != nil {
		t.Fatalf("create dist dir: %v", err)
	}
	buildBinary(t, distDir)

	// Step 5: Create test config
	t.Log("Creating test config...")
	configPath := filepath.Join(tmpDir, "limguard.yaml")
	createTestConfig(t, configPath, distDir, currentUser.Username, sshKeyPath,
		sshPort1, sshPort2, endpoint1, endpoint2)

	// Step 6: Run apply
	t.Log("Running limguard apply...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := limguard.Apply(ctx, []string{"--config", configPath}, nil); err != nil {
		t.Fatalf("apply failed: %v", err)
	}

	// Wait for services to stabilize
	time.Sleep(3 * time.Second)

	// Step 7: Verify the mesh
	t.Log("Verifying mesh connectivity...")
	verifyPing(t, node1Name, wgIP2)
	verifyPing(t, node2Name, wgIP1)

	// Step 8: Check service status
	t.Log("Checking service status...")
	checkServiceStatus(t, node1Name)
	checkServiceStatus(t, node2Name)

	t.Log("Integration test passed!")
}

func checkPrerequisites(t *testing.T) {
	t.Helper()

	// Check limactl is installed
	if _, err := exec.LookPath("limactl"); err != nil {
		t.Skip("limactl not found, skipping integration test (install with: brew install lima)")
	}

	// Check Go is available for cross-compilation
	if _, err := exec.LookPath("go"); err != nil {
		t.Fatalf("go not found: %v", err)
	}
}

func findSSHKey(t *testing.T) string {
	t.Helper()

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("get home dir: %v", err)
	}

	for _, name := range []string{"id_ed25519", "id_rsa"} {
		keyPath := filepath.Join(home, ".ssh", name)
		if _, err := os.Stat(keyPath); err == nil {
			pubKeyPath := keyPath + ".pub"
			if _, err := os.Stat(pubKeyPath); err == nil {
				return keyPath
			}
		}
	}

	t.Skip("no SSH key found at ~/.ssh/id_ed25519 or ~/.ssh/id_rsa, skipping integration test")
	return ""
}

func createVM(t *testing.T, name string) {
	t.Helper()

	// Check if VM already exists
	cmd := exec.Command("limactl", "list", "--format", "{{.Name}}")
	out, _ := cmd.Output()
	if strings.Contains(string(out), name) {
		// VM exists, ensure it's running
		t.Logf("VM %s already exists, ensuring it's started...", name)
		startVM(t, name)
		return
	}

	// Create new VM
	cmd = exec.Command("limactl", "create",
		"--name="+name,
		"template://ubuntu-lts",
		"--cpus=1",
		"--memory=1",
		"--vm-type=vz",
		"--network=lima:user-v2",
		"--yes",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("create VM %s: %v", name, err)
	}

	startVM(t, name)
}

func startVM(t *testing.T, name string) {
	t.Helper()

	// Check if already running
	cmd := exec.Command("limactl", "list", "--format", "{{.Name}}\t{{.Status}}")
	out, _ := cmd.Output()
	for _, line := range strings.Split(string(out), "\n") {
		parts := strings.Split(line, "\t")
		if len(parts) >= 2 && parts[0] == name && parts[1] == "Running" {
			return // Already running
		}
	}

	cmd = exec.Command("limactl", "start", name)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("start VM %s: %v", name, err)
	}

	// Wait for VM to be ready
	for i := 0; i < 30; i++ {
		cmd := exec.Command("limactl", "shell", name, "--", "echo", "ready")
		if err := cmd.Run(); err == nil {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("VM %s did not become ready", name)
}

func getSSHPort(t *testing.T, name string) string {
	t.Helper()

	cmd := exec.Command("limactl", "show-ssh", name)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("get SSH port for %s: %v", name, err)
	}

	re := regexp.MustCompile(`Port=(\d+)`)
	matches := re.FindStringSubmatch(string(out))
	if len(matches) < 2 {
		t.Fatalf("could not find SSH port in output: %s", out)
	}
	return matches[1]
}

func getVMIP(t *testing.T, name string) string {
	t.Helper()

	cmd := exec.Command("limactl", "shell", name, "--",
		"ip", "addr", "show", "eth0")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("get VM IP for %s: %v", name, err)
	}

	re := regexp.MustCompile(`inet (\d+\.\d+\.\d+\.\d+)/`)
	matches := re.FindStringSubmatch(string(out))
	if len(matches) < 2 {
		t.Fatalf("could not find IP in output: %s", out)
	}
	return matches[1]
}

func enableSSHAccess(t *testing.T, name, sshKeyPath string) {
	t.Helper()

	pubKeyPath := sshKeyPath + ".pub"
	pubKey, err := os.ReadFile(pubKeyPath)
	if err != nil {
		t.Fatalf("read public key: %v", err)
	}

	// Add SSH key to authorized_keys (idempotent - checks if already present)
	script := fmt.Sprintf(`
mkdir -p ~/.ssh
chmod 700 ~/.ssh
touch ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
grep -qF %q ~/.ssh/authorized_keys || echo %q >> ~/.ssh/authorized_keys
`, strings.TrimSpace(string(pubKey)), strings.TrimSpace(string(pubKey)))

	cmd := exec.Command("limactl", "shell", name, "--", "bash", "-c", script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("enable SSH access for %s: %v\noutput: %s", name, err, out)
	}

	// Enable passwordless sudo (idempotent)
	sudoScript := `sudo bash -c 'echo "$(whoami) ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/lima-user && chmod 440 /etc/sudoers.d/lima-user'`
	cmd = exec.Command("limactl", "shell", name, "--", "bash", "-c", sudoScript)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("enable passwordless sudo for %s: %v\noutput: %s", name, err, out)
	}
}

func buildBinary(t *testing.T, distDir string) {
	t.Helper()

	// Determine architecture
	arch := "arm64" // Default for Apple Silicon
	cmd := exec.Command("uname", "-m")
	if out, err := cmd.Output(); err == nil {
		if strings.Contains(string(out), "x86_64") {
			arch = "amd64"
		}
	}

	binaryName := fmt.Sprintf("limguard-linux-%s", arch)
	binaryPath := filepath.Join(distDir, binaryName)

	// Find the module root (where go.mod is)
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}

	// Build the binary
	cmd = exec.Command("go", "build", "-o", binaryPath, "./cmd/limguard/")
	cmd.Dir = wd
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build binary: %v\nstderr: %s", err, stderr.String())
	}

	t.Logf("Built %s", binaryPath)
}

func createTestConfig(t *testing.T, configPath, distDir, username, sshKeyPath,
	sshPort1, sshPort2, endpoint1, endpoint2 string) {
	t.Helper()

	config := fmt.Sprintf(`interfaceName: wg0
listenPort: 51820
privateKeyPath: /etc/limguard/privatekey
binaryPath: /usr/local/bin/limguard
artifactDir: %s

nodes:
  %s:
    wireguardIP: %q
    endpoint: %q
    publicKey: ""
    ssh:
      host: "127.0.0.1"
      port: %s
      user: %q
      identityFile: %s

  %s:
    wireguardIP: %q
    endpoint: %q
    publicKey: ""
    ssh:
      host: "127.0.0.1"
      port: %s
      user: %q
      identityFile: %s
`, distDir,
		node1Name, wgIP1, endpoint1, sshPort1, username, sshKeyPath,
		node2Name, wgIP2, endpoint2, sshPort2, username, sshKeyPath)

	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func verifyPing(t *testing.T, fromNode, toIP string) {
	t.Helper()

	// Retry a few times as WireGuard may need a moment to establish
	var lastErr error
	for i := 0; i < 5; i++ {
		cmd := exec.Command("limactl", "shell", fromNode, "--",
			"ping", "-c", "3", "-W", "2", toIP)
		if out, err := cmd.CombinedOutput(); err == nil {
			t.Logf("Ping from %s to %s succeeded", fromNode, toIP)
			return
		} else {
			lastErr = fmt.Errorf("%v: %s", err, out)
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("ping from %s to %s failed after retries: %v", fromNode, toIP, lastErr)
}

func checkServiceStatus(t *testing.T, name string) {
	t.Helper()

	cmd := exec.Command("limactl", "shell", name, "--",
		"sudo", "systemctl", "is-active", "limguard")
	out, err := cmd.Output()
	if err != nil {
		// Get logs for debugging
		logCmd := exec.Command("limactl", "shell", name, "--",
			"sudo", "journalctl", "-u", "limguard", "-n", "20", "--no-pager")
		logs, _ := logCmd.Output()
		t.Fatalf("service not active on %s: %v\nlogs:\n%s", name, err, logs)
	}

	status := strings.TrimSpace(string(out))
	if status != "active" {
		t.Fatalf("service status on %s: %s (expected: active)", name, status)
	}
	t.Logf("Service on %s is active", name)
}

func cleanupVMs(t *testing.T) {
	t.Helper()

	// Only cleanup if LIMGUARD_TEST_CLEANUP is set (to allow debugging)
	if os.Getenv("LIMGUARD_TEST_NO_CLEANUP") != "" {
		t.Log("Skipping cleanup (LIMGUARD_TEST_NO_CLEANUP is set)")
		return
	}

	t.Log("Cleaning up VMs...")
	for _, name := range []string{node1Name, node2Name} {
		// Stop VM
		cmd := exec.Command("limactl", "stop", name)
		cmd.Run() // Ignore errors

		// Delete VM
		cmd = exec.Command("limactl", "delete", name)
		cmd.Run() // Ignore errors
	}
}
