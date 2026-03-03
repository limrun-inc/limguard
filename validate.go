package limguard

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"
)

// ValidateOptions holds options for the Validate command.
type ValidateOptions struct {
	ConfigPath string
	SSHKeyPath string
	Debug      bool
}

// Validate checks mesh connectivity by running peer-to-peer pings across remote nodes.
func Validate(ctx context.Context, args []string, log *slog.Logger) error {
	opts, err := parseValidateArgs(args)
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
	gConnect, gCtx := errgroup.WithContext(ctx)
	for name, node := range cfg.Nodes {
		name, node := name, node

		gConnect.Go(func() error {
			if node.IsDelete() {
				return nil
			}
			if isLocalNode(node) {
				clientsMu.Lock()
				clients[name] = &nodeConn{local: true}
				clientsMu.Unlock()
				return nil
			}

			sshClient, err := sshConnect(gCtx, node.SSH, opts.SSHKeyPath)
			if err != nil {
				return fmt.Errorf("ssh connect to %s: %w", name, err)
			}

			osName, arch := detectPlatform(sshClient)
			uidOut, _ := sshRun(sshClient, "id -u")
			isRoot := strings.TrimSpace(uidOut) == "0"

			var sudoPass string
			if node.SSH != nil && node.SSH.SudoPassword != nil {
				sudoPass = *node.SSH.SudoPassword
			}

			clientsMu.Lock()
			clients[name] = &nodeConn{ssh: sshClient, osName: osName, arch: arch, isRoot: isRoot, sudoPassword: sudoPass}
			clientsMu.Unlock()

			log.Info("connected", "node", name, "os", osName, "arch", arch, "root", isRoot)
			return nil
		})
	}
	if err := gConnect.Wait(); err != nil {
		return err
	}

	log.Info("validating mesh connectivity")
	if err := validateMeshConnectivity(ctx, cfg, clients, log); err != nil {
		return err
	}

	log.Info("validating wireguard allowed-ips")
	if err := validateAllowedIPs(ctx, cfg, clients); err != nil {
		return err
	}

	log.Info("mesh connectivity verified")
	return nil
}

func parseValidateArgs(args []string) (*ValidateOptions, error) {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	opts := &ValidateOptions{}
	fs.StringVar(&opts.ConfigPath, "config", "limguard.yaml", "Config file path")
	fs.StringVar(&opts.SSHKeyPath, "ssh-key", "", "SSH private key path")
	fs.BoolVar(&opts.Debug, "debug", false, "Debug logging")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return opts, nil
}
