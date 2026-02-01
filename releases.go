package limguard

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// GitHubRepo is the repository to download releases from.
const GitHubRepo = "limrun-inc/limguard"

// releaseAsset represents a GitHub release asset.
type releaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// releaseInfo represents a GitHub release.
type releaseInfo struct {
	TagName string         `json:"tag_name"`
	Assets  []releaseAsset `json:"assets"`
}

// ReleaseDownloader handles downloading binaries from GitHub Releases.
type ReleaseDownloader struct {
	cacheDir string
	client   *http.Client

	mu        sync.Mutex
	releases  map[string]*releaseInfo   // cache by tag
	checksums map[string]map[string]string // version -> (filename -> sha256)
}

// NewReleaseDownloader creates a new downloader with a temporary cache directory.
func NewReleaseDownloader() (*ReleaseDownloader, error) {
	cacheDir, err := os.MkdirTemp("", "limguard-releases-")
	if err != nil {
		return nil, fmt.Errorf("create cache dir: %w", err)
	}
	return &ReleaseDownloader{
		cacheDir:  cacheDir,
		// Use a timeout so we don't hang forever on stalled downloads.
		// Context cancellation (Ctrl+C) will still abort immediately.
		client:    &http.Client{Timeout: 5 * time.Minute},
		releases:  make(map[string]*releaseInfo),
		checksums: make(map[string]map[string]string),
	}, nil
}

// Cleanup removes the cache directory.
func (d *ReleaseDownloader) Cleanup() {
	os.RemoveAll(d.cacheDir)
}

// ResolveLatestVersion fetches the latest release tag from GitHub.
func (d *ReleaseDownloader) ResolveLatestVersion(ctx context.Context) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", GitHubRepo)
	release, err := d.fetchRelease(ctx, url)
	if err != nil {
		return "", fmt.Errorf("fetch latest release: %w", err)
	}

	d.mu.Lock()
	d.releases[release.TagName] = release
	d.mu.Unlock()

	return release.TagName, nil
}

// DownloadBinary downloads the binary for the given version, OS, and architecture.
// Returns the local path to the downloaded binary.
// The binary is cached locally and verified against SHA256 checksums from the release.
func (d *ReleaseDownloader) DownloadBinary(ctx context.Context, version, osName, arch string) (string, error) {
	release, err := d.getRelease(ctx, version)
	if err != nil {
		return "", err
	}

	assetName := fmt.Sprintf("limguard-%s-%s", osName, arch)

	// Check if already downloaded and verified
	localPath := filepath.Join(d.cacheDir, version, assetName)
	if _, err := os.Stat(localPath); err == nil {
		return localPath, nil
	}

	// Find the binary asset
	var asset *releaseAsset
	for i := range release.Assets {
		if release.Assets[i].Name == assetName {
			asset = &release.Assets[i]
			break
		}
	}
	if asset == nil {
		return "", fmt.Errorf("asset %q not found in release %s", assetName, version)
	}

	// Get expected checksum
	checksums, err := d.getChecksums(ctx, version, release)
	if err != nil {
		return "", fmt.Errorf("get checksums: %w", err)
	}
	expectedHash, ok := checksums[assetName]
	if !ok {
		return "", fmt.Errorf("no checksum found for %s in release %s", assetName, version)
	}

	// Create cache directory
	if err := os.MkdirAll(filepath.Dir(localPath), 0755); err != nil {
		return "", fmt.Errorf("create cache subdir: %w", err)
	}

	// Download the asset
	if err := d.downloadAsset(ctx, asset.BrowserDownloadURL, localPath); err != nil {
		return "", fmt.Errorf("download asset %s: %w", assetName, err)
	}

	// Verify checksum
	actualHash, err := fileSHA256(localPath)
	if err != nil {
		os.Remove(localPath)
		return "", fmt.Errorf("compute checksum: %w", err)
	}
	if actualHash != expectedHash {
		os.Remove(localPath)
		return "", fmt.Errorf("checksum mismatch for %s: expected %s, got %s", assetName, expectedHash, actualHash)
	}

	return localPath, nil
}

// getChecksums fetches and parses the checksums.txt file for a release.
func (d *ReleaseDownloader) getChecksums(ctx context.Context, version string, release *releaseInfo) (map[string]string, error) {
	d.mu.Lock()
	if checksums, ok := d.checksums[version]; ok {
		d.mu.Unlock()
		return checksums, nil
	}
	d.mu.Unlock()

	// Find checksums.txt asset
	var checksumAsset *releaseAsset
	for i := range release.Assets {
		if release.Assets[i].Name == "checksums.txt" {
			checksumAsset = &release.Assets[i]
			break
		}
	}
	if checksumAsset == nil {
		return nil, fmt.Errorf("checksums.txt not found in release %s", version)
	}

	// Download checksums.txt
	checksumPath := filepath.Join(d.cacheDir, version, "checksums.txt")
	if err := os.MkdirAll(filepath.Dir(checksumPath), 0755); err != nil {
		return nil, fmt.Errorf("create cache subdir: %w", err)
	}
	if err := d.downloadAsset(ctx, checksumAsset.BrowserDownloadURL, checksumPath); err != nil {
		return nil, fmt.Errorf("download checksums.txt: %w", err)
	}

	// Parse checksums.txt (format: "sha256hash  filename")
	checksums, err := parseChecksums(checksumPath)
	if err != nil {
		return nil, fmt.Errorf("parse checksums: %w", err)
	}

	d.mu.Lock()
	d.checksums[version] = checksums
	d.mu.Unlock()

	return checksums, nil
}

// parseChecksums reads a checksums file in sha256sum format.
func parseChecksums(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	checksums := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Format: "sha256hash  filename" (two spaces)
		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}
		hash := parts[0]
		filename := parts[1]
		// Handle *filename prefix from binary mode
		filename = strings.TrimPrefix(filename, "*")
		checksums[filename] = hash
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return checksums, nil
}

func (d *ReleaseDownloader) getRelease(ctx context.Context, version string) (*releaseInfo, error) {
	d.mu.Lock()
	if release, ok := d.releases[version]; ok {
		d.mu.Unlock()
		return release, nil
	}
	d.mu.Unlock()

	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/tags/%s", GitHubRepo, version)
	release, err := d.fetchRelease(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("fetch release %s: %w", version, err)
	}

	d.mu.Lock()
	d.releases[version] = release
	d.mu.Unlock()

	return release, nil
}

func (d *ReleaseDownloader) fetchRelease(ctx context.Context, url string) (*releaseInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	d.addAuthHeader(req)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode, string(body))
	}

	var release releaseInfo
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &release, nil
}

func (d *ReleaseDownloader) downloadAsset(ctx context.Context, url, destPath string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	d.addAuthHeader(req)
	req.Header.Set("Accept", "application/octet-stream")

	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned %d", resp.StatusCode)
	}

	f, err := os.Create(destPath)
	if err != nil {
		return err
	}

	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(destPath)
		return err
	}
	f.Close()

	// Make executable
	if err := os.Chmod(destPath, 0755); err != nil {
		return err
	}

	return nil
}

func (d *ReleaseDownloader) addAuthHeader(req *http.Request) {
	// Check for GitHub token in environment
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		token = os.Getenv("GH_TOKEN")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
}

