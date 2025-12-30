# k0s + Calico + Limguard on Public Nodes

This example shows how to deploy a k0s cluster with Limguard as network fabric and Calico
as container network that runs on top of that fabric.

### Pre-requisites

* All nodes must be able to reach UDP port 51820 of each other.
* `k0sctl` and `helm`
* SSH information of the nodes.

### Deploy the luster

k0s has a CLI tool called `k0sctl` where we can supply a whole YAML declaratively to take care
of spinning up the cluster without any networking.

Edit [`k0sctl.yaml`](./k0sctl.yaml) to specify the SSH details of the nodes.

Then run the following to deploy the cluster.
```bash
k0sctl apply --config k0sctl.yaml
```

### Install Limguard

For inter-node communication, we need to install `limguard`.

```
helm upgrade --install limguard \
  oci://ghcr.io/limrun-inc/charts/limguard \
  --namespace kube-system \
  --create-namespace \
  --set nodeCIDR: 10.200.0.0/24
```

Now the nodes can talk with each other over WireGuard using `wg0` but Kubernetes is not aware of it yet.

### Install Calico with BGP

We install Calico so that it publishes pod CIDRs to the whole network and `limguard` to register them in
the peers.

```bash
helm upgrade --install calico projectcalico/tigera-operator \
  --version v3.31.3 \
  --namespace tigera-operator \
  --create-namespace \
  -f calico-values.yaml
```

At this point, the whole cluster network is functional is flowing through WireGuard!
