# limguard - VPC over Wireguard for Kubernetes

`limguard` is a `DaemonSet` that runs on all Kubernetes nodes to set up wireguard peers and establish
routes between them. You can run `limguard` to provide secure inter-node communication for public nodes
and allow non-Linux peers to join the same network with Pod and Service reachability.

This project is used in production at [lim.run](https://lim.run) to have Linux & macOS nodes to share
a network fabric regardless of their network placement in the world.

You can run `limguard` on both Linux and macOS. PRs are welcome for Windows support.

### Why not use support from CNI?

Calico, Cilium and others do provide built-in Wireguard capabilities and you should use them if they
suit your needs for better integration.

At [lim.run](https://lim.run), we run iOS simulators on macOS in 3 regions across the world with
our `virtual-kubelet` implementation where the macOS nodes are real Kubernetes nodes and participate
in BGP of Calico for routing.
This works fine when all nodes are in the same LAN, which is the case for regions where we own the
racks, but not the regions where we rent the nodes that have public IPs. And sometimes it's a mix of
on-premise and cloud nodes.

To have secure communication between public nodes and still be able to do BGP routing, we needed a
replacement for the physical network and Wireguard seemed like the best option. However, none of the
CNIs would work well when there are external peers; either BGP breaks or CNI itself doesn't allow
peering with external peers at all.

So we built `limguard` to seperate the Wireguard layer from the CNI. When you run `limguard`, all
Calico/Cilium/etc needs to know is that they need to use `wg0` interface and that's it; just as if
you have all those nodes in the same LAN.

## Get Started

For a full cluster example, see [k0s + Calico + Limguard on Public Nodes](./examples/calico-bgp-wireguard)

You can just deploy the Helm chart and the WireGuard network will be established automatically.
You can postpone making your container network interface aware of the `wg0` interface they can
use later on.

All nodes must have the UDP port `51820` reachable from each other.

```bash
helm upgrade --install limguard \
  oci://ghcr.io/limrun-inc/charts/limguard \
  --version 0.7.0 \
  --namespace kube-system \
  --create-namespace \
  --set nodeCIDR: 10.200.0.0/24
```

You can see the IPs assigned to each node from `Node` annotations or the ConfigMap named
`limguard-ip-allocations`.

At this point, you only have the connectivity between the nodes but not between the pods. The BGP
or any other pod CIDR distribution tech you use needs to add routes targeted for `wg0` which is
the case for all kinds of networks.

One thing different with WireGuard is that routing table doesn't suffice for it to match a packet
with a peer, it needs those CIDRs explicitly set on the `wg0` interface as allowed IPs. `limguard`
takes care of that sync by checking routes and adding them to `wg0` automatically.

### Calico Setup with BGP

Calico in BGP mode can use `wg0` as the target of the Pod IP addresses in nodes. Here is example
installation YAMLs.

```yaml
# helm upgrade --install calico projectcalico/tigera-operator --version v3.31.3 --namespace tigera-operator --create-namespace -f calico-values.yaml
installation:
  cni:
    type: Calico
  calicoNetwork:
    bgp: Enabled
    nodeAddressAutodetectionV4:
      interface: wg0
    serviceCIDR: "10.96.0.0/12"
    ipPools:
      - name: default
        cidr: 10.244.0.0/16
        # You can enable encapsulation but it's not needed. "None" allows non-Calico peers to be
        # able to participate.
        encapsulation: None

# In case you're using k0s, you need to set this explicitly.
# kubeletVolumePluginPath: "/var/lib/k0s/kubelet"
```

### Roadmap

* We require peers to be `Node`s but they don't have to be. A `LimguardPeer` CRD would let your laptop
  to join the cluster network just as any peer since we support both macOS and Linux.
* Example with Cilium.
* Tests with CNI modes other than BGP like IP-in-IP.
* Testing with eBPF.

### License

`limguard` is MIT-licensed.
