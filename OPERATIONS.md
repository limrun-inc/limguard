# Operations Guide

### Bootstrapping issues after degradation

If a control-plane node went down and you had to re-install the OS, that means the private
key is gone and limguard can't run on it because kubernetes scheduler is not running yet.
And kubernetes can't run on it because it can't access other control-plane nodes.

This shows how you can bootstrap the node to join the network and then limguard to take over.

#### Losing the private key

First, you need to remove the peer from all the hosts. Get the public key from Node annotation.

```bash
export OLD_PUB_KEY=$(kubectl get node <nodename> -o jsonpath='{.metadata.annotations.limguard\.limrun\.com/public-key}')
```

Run the following in ALL hosts to remove the old peer.
```bash
wg set wg0 peer ${OLD_PUB_KEY} remove
```

Create a new key in the host.
```bash
mkdir -p /etc/limguard

# Generate new private key (if you don't have the old one)
wg genkey > /etc/limguard/privatekey
chmod 600 /etc/limguard/privatekey

# Get the public key (you'll need to update the Node annotation if it changed)
export PUB_KEY=$(wg pubkey < /etc/limguard/privatekey)
```

In your laptop.

```bash
kubectl annotate <nodename> limguard.limrun.com/public-key=${PUB_KEY} --overwrite
```

#### Bootstrapping peers

In a working host, run the following script that will produce a set of commands to run on
your peer so that it knows about all other peers.

```bash
./generate-bootstrap-from-wg.sh  --target-ip <public ip> --target-wg-ip <wireguard ip>
```

Now you can install your Kubernetes distribution and it'll come up and connect to its known control-plane IPs.
