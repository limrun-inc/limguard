# limguard - VPC over Wireguard for Kubernetes

`limguard` is a `DaemonSet` that runs on all Kubernetes nodes to set up wireguard peers and establish
routes between them. You can also run `limguard` on non-Linux nodes to join the same network.

It's most useful when the nodes must be public, but you still want to keep your cluster communicating
securely.

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


