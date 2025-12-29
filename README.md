# limguard - VPC for Kubernetes using Wireguard

`limguard` is a `DaemonSet` that runs on all Kubernetes nodes to set up wireguard peers and establish
routes between them. You can also run `limguard` on non-Linux nodes to join the same network.

It's most useful when the nodes must be public, but you still want to keep your cluster communicating
securely.

### Why not use support from CNI?

Calico, Cilium and others do provide built-in Wireguard capabilities and you should use them if they
suit your needs for better integration.

We run iOS simulators on macOS with our `virtual-kubelet` implementation where the macOS nodes are
real Kubernetes nodes and participate in BGP of Calico for routing. This works fine when all nodes
are in the same LAN, which is the case for regions where we own the racks, but not the regions where
we rent the nodes that have public IPs.

To have secure communication between public nodes and still do BGP routing, we needed a replacement
for the physical network and Wireguard seemed like the best option. However, none of the CNIs would
work well when there are external peers; either BGP breaks or CNI itself.

So we built `limguard` to seperate the Wireguard layer from the CNI. When you run `limguard`, all
Calico/Cilium/etc needs to know is that they need to use `wg0` interface and that's it.

## Get Started


