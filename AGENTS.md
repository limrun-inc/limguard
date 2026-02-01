# limguard

WireGuard mesh network daemon. Single YAML config used for both deployment and runtime.

## Files

- `cmd/main.go` - CLI: run, apply commands
- `config/config.go` - YAML config loading/validation
- `linux.go` / `darwin.go` - Platform-specific WireGuard management

## Call Flow

```mermaid
flowchart TD
    subgraph main
        M[main] --> cmdRun
        M --> cmdApply
    end

    subgraph run_command[run command - idempotent]
        cmdRun --> config.Load
        cmdRun --> config.Validate
        cmdRun --> config.GetSelf
        cmdRun --> config.EnsurePrivateKey
        config.EnsurePrivateKey -->|writes| PubkeyFile[privatekey.pub]
        cmdRun --> verifyPubkey[verify self pubkey matches]
        cmdRun --> NewNetworkManager
        cmdRun --> reconcilePeers
        cmdRun --> fsnotify[fsnotify.Watcher]
        fsnotify -->|on_change| config.Load
        fsnotify -->|on_change| reconcilePeers
        reconcilePeers --> config.GetPeers
        reconcilePeers -->|skip if no pubkey| nm.SetPeer
        reconcilePeers --> nm.RemovePeer
    end

    subgraph apply_command
        cmdApply --> config.Load
        cmdApply --> config.ValidateForDeploy

        cmdApply --> Pass1[Pass1: Start services]
        Pass1 --> sshConnect
        Pass1 --> detectPlatform
        Pass1 --> fileSHA256[SHA256 hash check]
        fileSHA256 -->|if changed| scpFile
        Pass1 --> writeRemoteFile
        Pass1 --> installLinuxService
        Pass1 --> installDarwinService
        Pass1 --> waitForPubkey
        waitForPubkey -->|reads| PubkeyFile

        cmdApply --> config.Save
        
        cmdApply --> Pass2[Pass2: Distribute and restart]
        Pass2 --> sshConnect
        Pass2 --> writeRemoteFile
        Pass2 --> restartService[systemctl restart]
    end

    subgraph network_manager[NetworkManager linux.go/darwin.go]
        NewNetworkManager --> wgctrl.New
        NewNetworkManager --> ConfigureDevice
        nm.SetPeer --> ConfigureDevice
        nm.RemovePeer --> ConfigureDevice
        NewNetworkManager --> syncAllowedIPsLoop
        syncAllowedIPsLoop --> syncAllowedIPs
    end
```

## Deploy Sequence

```mermaid
sequenceDiagram
    participant Operator
    participant LocalYAML
    participant Node1
    participant Node2

    Operator->>LocalYAML: Read config
    
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
