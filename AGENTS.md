# limguard

WireGuard mesh network daemon. Single YAML config used for both deployment and runtime.

## Files

- `cmd/main.go` - CLI: run, bootstrap, deploy commands
- `config/config.go` - YAML config loading/validation
- `linux.go` / `darwin.go` - Platform-specific WireGuard management

## Call Flow

```mermaid
flowchart TD
    subgraph main
        M[main] --> cmdRun
        M --> cmdBootstrap
        M --> cmdDeploy
    end

    subgraph run_command
        cmdRun --> config.Load
        cmdRun --> config.Validate
        cmdRun --> config.GetSelf
        cmdRun --> NewNetworkManager
        cmdRun --> reconcilePeers
        cmdRun --> fsnotify[fsnotify.Watcher]
        fsnotify -->|on_change| config.Load
        fsnotify -->|on_change| reconcilePeers
        reconcilePeers --> config.GetPeers
        reconcilePeers --> nm.SetPeer
        reconcilePeers --> nm.RemovePeer
    end

    subgraph bootstrap_command
        cmdBootstrap --> config.Load
        cmdBootstrap --> config.GetSelf
        cmdBootstrap --> config.EnsurePrivateKey
        cmdBootstrap --> NewNetworkManager
        cmdBootstrap -->|stdout| PublicKey
    end

    subgraph deploy_command
        cmdDeploy --> config.Load
        cmdDeploy --> config.ValidateForDeploy

        cmdDeploy --> Pass1[Pass1: Bootstrap]
        Pass1 --> sshConnect
        Pass1 --> detectPlatform
        Pass1 --> scpFile
        Pass1 --> writeRemoteFile
        Pass1 --> sshRun
        sshRun -->|remote| cmdBootstrap

        cmdDeploy --> config.Save
        
        cmdDeploy --> Pass2[Pass2: Distribute]
        Pass2 --> sshConnect
        Pass2 --> writeRemoteFile
        Pass2 --> installLinuxService
        Pass2 --> installDarwinService
        installLinuxService --> sshRun
        installDarwinService --> sshRun
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
    
    Note over Operator,Node2: Pass 1: Bootstrap
    Operator->>Node1: SSH + copy binary
    Operator->>Node1: limguard bootstrap
    Node1-->>Operator: public key
    Operator->>Node2: SSH + copy binary
    Operator->>Node2: limguard bootstrap
    Node2-->>Operator: public key
    
    Operator->>LocalYAML: Update with public keys
    
    Note over Operator,Node2: Pass 2: Distribute
    Operator->>Node1: Copy full YAML
    Operator->>Node1: Start daemon
    Operator->>Node2: Copy full YAML
    Operator->>Node2: Start daemon
    
    Node1->>Node2: WireGuard peers configured
    Node2->>Node1: WireGuard peers configured
```
