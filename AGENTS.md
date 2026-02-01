# limguard

WireGuard mesh network daemon. Single YAML config used for both deployment and runtime.

## Files

- `cmd/limguard/main.go` - CLI entrypoint (thin wrapper)
- `config.go` - YAML config loading/validation, constants
- `version.go` - Version variable (set at build time)
- `run.go` - Run command: daemon lifecycle, peer reconciliation
- `deploy.go` - Apply command: SSH/SFTP helpers, service installation
- `releases.go` - GitHub Releases download support (fetch binaries)
- `linux.go` / `darwin.go` - Platform-specific WireGuard NetworkManager

## Call Flow

```mermaid
flowchart TD
    subgraph main[cmd/limguard/main.go]
        M[main] --> limguard.Run
        M --> limguard.Apply
    end

    subgraph run_command[Run - run.go]
        limguard.Run --> LoadConfig
        limguard.Run --> Config.Validate
        limguard.Run --> Config.GetSelf
        limguard.Run --> EnsurePrivateKey
        EnsurePrivateKey -->|writes| PubkeyFile[privatekey.pub]
        limguard.Run --> verifyPubkey[verify self pubkey matches]
        limguard.Run --> NewNetworkManager
        limguard.Run --> reconcilePeers
        limguard.Run --> waitForShutdown[wait for shutdown]
        reconcilePeers --> Config.GetPeers
        reconcilePeers -->|skip if no pubkey| nm.SetPeer
        reconcilePeers --> nm.RemovePeer
    end

    subgraph apply_command[Apply - deploy.go + releases.go]
        limguard.Apply --> LoadConfig
        limguard.Apply --> Config.ValidateForDeploy
        limguard.Apply --> ResolveVersion[Resolve version if empty]
        ResolveVersion --> Config.Save
        limguard.Apply --> DownloadBinaries[Download binaries from GitHub]
        DownloadBinaries --> ReleaseDownloader

        limguard.Apply --> Pass1[Pass1: Start services]
        Pass1 --> sshConnect
        Pass1 --> detectPlatform
        Pass1 --> fileSHA256[SHA256 hash check]
        fileSHA256 -->|if changed| sftpCopyFile
        Pass1 --> sftpWriteFile
        Pass1 --> installLinuxService
        Pass1 --> installDarwinService
        Pass1 --> waitForPubkey
        waitForPubkey -->|reads| PubkeyFile

        limguard.Apply --> Config.Save
        
        limguard.Apply --> Pass2[Pass2: Distribute and restart]
        Pass2 --> sftpWriteFile
        Pass2 --> runAsRoot[runAsRoot - stdin piped]
    end

    subgraph network_manager[NetworkManager linux.go/darwin.go]
        NewNetworkManager --> wgctrl.New
        NewNetworkManager --> ConfigureDevice
        nm.SetPeer --> ConfigureDevice
        nm.RemovePeer --> ConfigureDevice
        NewNetworkManager --> syncAllowedIPsLoop
        syncAllowedIPsLoop --> syncAllowedIPs
        nm.Close --> wgClient.Close
    end
```

## Deploy Sequence

```mermaid
sequenceDiagram
    participant Operator
    participant GitHub
    participant LocalYAML
    participant Node1
    participant Node2

    Operator->>LocalYAML: Read config
    Operator->>GitHub: Resolve version (latest if not set)
    GitHub-->>Operator: version tag
    Operator->>LocalYAML: Save resolved version
    Operator->>GitHub: Download binaries for each platform
    GitHub-->>Operator: limguard binaries
    
    Note over Operator,Node2: Pass 1: Start services
    Operator->>Node1: SSH + copy binary + minimal config
    Operator->>Node1: Install and start service
    Node1->>Node1: limguard run (bootstraps, writes pubkey file)
    Operator->>Node1: Poll for pubkey file
    Node1-->>Operator: public key
    Operator->>Node2: SSH + copy binary + minimal config
    Operator->>Node2: Install and start service
    Node2->>Node2: limguard run (bootstraps, writes pubkey file)
    Operator->>Node2: Poll for pubkey file
    Node2-->>Operator: public key
    
    Operator->>LocalYAML: Update with public keys
    
    Note over Operator,Node2: Pass 2: Distribute config and restart
    Operator->>Node1: Copy full YAML + restart service
    Operator->>Node2: Copy full YAML + restart service
    
    Node1->>Node2: WireGuard peers configured
    Node2->>Node1: WireGuard peers configured
```

## Local Nodes (WireGuard GUI Clients)

Nodes with `ssh.host: self` are treated as local WireGuard clients:
- No daemon or service is installed
- Private key is generated in `~/.limguard/privatekey`
- Public key is distributed to all remote nodes as a peer
- A WireGuard INI config is written to `<node-name>-peer.conf` (customizable via `--local-wireguard-conf-path`)

Example config entry:
```yaml
nodes:
    ops-laptop:
        wireguardIP: 10.200.0.50
        ssh:
            host: self
```

After `limguard apply`, import the generated `.conf` file into the WireGuard app on macOS, Windows, iOS, or Android.
