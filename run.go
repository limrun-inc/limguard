package limguard

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/fsnotify/fsnotify"
)

// RunOptions holds options for the Run command.
type RunOptions struct {
	ConfigPath string
	NodeName   string
	Debug      bool
}

// Run starts the limguard daemon.
// It returns an error if the daemon fails to start or encounters a fatal error.
func Run(ctx context.Context, args []string, log *slog.Logger) error {
	opts, err := parseRunArgs(args)
	if err != nil {
		return err
	}

	if log == nil {
		log = newLogger(opts.Debug)
	}

	name := opts.NodeName
	if name == "" {
		name, _ = os.Hostname()
	}

	log.Info("starting", "version", Version, "node", name)

	cfg, err := LoadConfig(opts.ConfigPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	self, ok := cfg.GetSelf(name)
	if !ok {
		return fmt.Errorf("node %q not in config", name)
	}

	// Bootstrap: ensure private key exists (generate if needed)
	privateKey, err := EnsurePrivateKey(cfg.PrivateKeyPath)
	if err != nil {
		return fmt.Errorf("ensure private key: %w", err)
	}

	// Verify self's publicKey matches local key (if YAML has one)
	derivedPubKey := privateKey.PublicKey().String()
	if self.PublicKey != "" && self.PublicKey != derivedPubKey {
		return fmt.Errorf("publicKey mismatch: yaml=%s derived=%s", self.PublicKey, derivedPubKey)
	}

	// Write pubkey to file for apply command to read
	pubkeyPath := cfg.PrivateKeyPath + ".pub"
	if err := os.WriteFile(pubkeyPath, []byte(derivedPubKey+"\n"), 0644); err != nil {
		return fmt.Errorf("write public key file: %w", err)
	}

	// Print public key to stdout
	fmt.Printf("LIMGUARD_PUBKEY=%s\n", derivedPubKey)

	nm, err := NewNetworkManager(cfg.InterfaceName, cfg.PrivateKeyPath, cfg.ListenPort, self.WireguardIP, log)
	if err != nil {
		return fmt.Errorf("init network: %w", err)
	}
	defer nm.Close()

	// Initial peer sync
	reconcilePeers(ctx, nm, cfg, name, log)

	// Watch config
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("create file watcher: %w", err)
	}
	defer watcher.Close()

	if err := watcher.Add(opts.ConfigPath); err != nil {
		return fmt.Errorf("watch config file: %w", err)
	}

	var debounce *time.Timer
	for {
		select {
		case <-ctx.Done():
			log.Info("shutting down")
			return nil
		case ev, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			if ev.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				if debounce != nil {
					debounce.Stop()
				}
				debounce = time.AfterFunc(500*time.Millisecond, func() {
					newCfg, err := LoadConfig(opts.ConfigPath)
					if err != nil {
						log.Error("reload config", "error", err)
						return
					}
					if err := newCfg.Validate(); err != nil {
						log.Error("invalid config", "error", err)
						return
					}
					cfg = newCfg
					reconcilePeers(ctx, nm, cfg, name, log)
					log.Info("config reloaded")
				})
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			log.Error("watcher error", "error", err)
		}
	}
}

func parseRunArgs(args []string) (*RunOptions, error) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	opts := &RunOptions{}
	fs.StringVar(&opts.ConfigPath, "config", DefaultConfigPath, "Config file path")
	fs.StringVar(&opts.NodeName, "node-name", "", "Node name (default: hostname)")
	fs.BoolVar(&opts.Debug, "debug", false, "Debug logging")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return opts, nil
}

func reconcilePeers(ctx context.Context, nm *NetworkManager, cfg *Config, selfName string, log *slog.Logger) {
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
			if err := nm.RemovePeer(ctx, pk); err != nil {
				log.Error("remove peer", "error", err)
			}
		}
	}
}

func newLogger(debug bool) *slog.Logger {
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
}
