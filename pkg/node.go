package limguard

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/crossplane/crossplane-runtime/pkg/logging"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	controllerName = "limguard"

	AnnotationKeyWireguardIPV4Address    = "limguard.limrun.com/ipv4"
	AnnotationKeyWireguardPublicKey      = "limguard.limrun.com/public-key"
	AnnotationKeyWireguardPublicEndpoint = "limguard.limrun.com/public-endpoint"

	LabelKeyLimguard = "limguard.limrun.com/managed-by"
	LabelValueTrue   = "limguard"

	// DefaultListenPort is the WireGuard listen port
	DefaultListenPort = 51820

	// leaseRenewThreshold is how old the lease must be before we renew it.
	// This prevents excessive lease updates that trigger reconciliation storms.
	leaseRenewThreshold = 30 * time.Minute
)

type Peer struct {
	PublicKey, Endpoint, WireguardIP string
}

// NetworkManager provides platform-specific network operations for WireGuard.
// One-time setup (interface creation, private key, bringing up) should be done
// before starting the controller.
type NetworkManager interface {
	// SetWireguardIP sets the IP address on the WireGuard interface.
	SetWireguardIP(ip string) error

	// SetPeer configures a WireGuard peer and adds a route for its allowed IPs.
	SetPeer(ctx context.Context, publicKey, endpoint, wireguardIp string) error
}

func SetupWithManager(mgr ctrl.Manager, nm NetworkManager, nodeName, publicKey, nodeIPCidr, leaseNamespace string, log logging.Logger) error {
	_, ipNet, err := net.ParseCIDR(nodeIPCidr)
	if err != nil {
		return fmt.Errorf("failed to parse node IP CIDR: %w", err)
	}
	r := &Reconciler{
		kube:           mgr.GetClient(),
		Scheme:         mgr.GetScheme(),
		log:            log.WithValues("controller", controllerName),
		nm:             nm,
		nodeName:       nodeName,
		publicKey:      publicKey,
		nodeIPNet:      ipNet,
		leaseNamespace: leaseNamespace,
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Node{}).
		Named(controllerName).
		Complete(r)
}

type Reconciler struct {
	kube   client.Client
	Scheme *runtime.Scheme

	nm             NetworkManager
	nodeName       string
	publicKey      string
	nodeIPNet      *net.IPNet
	leaseNamespace string

	log logging.Logger
}

// Reconcile runs for every event on Node resources.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.log.WithValues("node", req.Name)

	// If the event is for another node, just configure that peer
	if req.Name != r.nodeName {
		return r.reconcilePeer(ctx, log.WithValues("reconcile", "peer"), req.Name)
	}

	// Event is for our own node - do full setup
	return r.reconcileSelf(ctx, log.WithValues("reconcile", "self"))
}

// reconcileSelf handles setup for our own node
func (r *Reconciler) reconcileSelf(ctx context.Context, log logging.Logger) (ctrl.Result, error) {
	log.Debug("reconciling self")
	node := &corev1.Node{}
	if err := r.kube.Get(ctx, client.ObjectKey{Name: r.nodeName}, node); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	ip, err := r.ensureIPAllocation(ctx, log, node)
	if err != nil {
		log.Info("failed to allocate IP", "error", err)
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}
	endpoint := r.getNodeEndpoint(node)
	if endpoint == "" {
		log.Info("node has no InternalIP yet, waiting...")
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}
	if err := r.updateNodeAnnotations(ctx, node, ip, r.publicKey, endpoint); err != nil {
		log.Info("failed to update node annotations", "error", err)
		return ctrl.Result{}, nil
	}
	if err := r.nm.SetWireguardIP(ip); err != nil {
		log.Info("failed to set interface address", "error", err)
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}
	if err := r.configureAllPeers(ctx, log); err != nil {
		log.Info("failed to configure peers", "error", err)
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}
	log.Debug("reconciliation complete", "ip", ip, "endpoint", endpoint)
	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

// reconcilePeer handles configuring a single peer when their node changes
func (r *Reconciler) reconcilePeer(ctx context.Context, log logging.Logger, peerNodeName string) (ctrl.Result, error) {
	node := &corev1.Node{}
	if err := r.kube.Get(ctx, client.ObjectKey{Name: peerNodeName}, node); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	annotations := node.GetAnnotations()
	if annotations == nil {
		return ctrl.Result{}, nil
	}
	peerIP := annotations[AnnotationKeyWireguardIPV4Address]
	peerPublicKey := annotations[AnnotationKeyWireguardPublicKey]
	peerEndpoint := annotations[AnnotationKeyWireguardPublicEndpoint]
	if peerIP == "" || peerPublicKey == "" || peerEndpoint == "" {
		log.Info("peer not ready", "peer", peerNodeName, "peerIP", peerIP, "publicKey", peerPublicKey, "endpoint", peerEndpoint)
		return ctrl.Result{}, nil
	}
	endpoint := fmt.Sprintf("%s:%d", peerEndpoint, DefaultListenPort)
	log.Debug("configuring peer", "publicKey", peerPublicKey, "endpoint", endpoint, "peerIP", peerIP)
	if err := r.nm.SetPeer(ctx, peerPublicKey, endpoint, peerIP); err != nil {
		log.Info("failed to configure peer", "error", err)
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}
	return ctrl.Result{}, nil
}

// ensureIPAllocation ensures we have a WireGuard IP via Lease objects
func (r *Reconciler) ensureIPAllocation(ctx context.Context, log logging.Logger, node *corev1.Node) (string, error) {
	// Check if we already have an IP in annotations
	if annotations := node.GetAnnotations(); annotations != nil {
		if ip := annotations[AnnotationKeyWireguardIPV4Address]; ip != "" {
			leaseName := ipToLeaseName(ip)
			lease := &coordinationv1.Lease{}
			err := r.kube.Get(ctx, client.ObjectKey{Name: leaseName, Namespace: r.leaseNamespace}, lease)
			if err == nil && lease.Spec.HolderIdentity != nil && *lease.Spec.HolderIdentity == r.nodeName {
				if err := r.renewLease(ctx, lease); err != nil {
					log.Debug("failed to renew lease", "error", err)
					return "", fmt.Errorf("failed to renew lease: %w", err)
				}
				return ip, nil
			}
		}
	}

	// Try to allocate a new IP by attempting to create leases until one succeeds
	ip := r.firstIP()
	for r.nodeIPNet.Contains(ip) {
		ipStr := ip.String()
		leaseName := ipToLeaseName(ipStr)
		now := metav1.NewMicroTime(time.Now())
		lease := &coordinationv1.Lease{
			ObjectMeta: metav1.ObjectMeta{
				Name:      leaseName,
				Namespace: r.leaseNamespace,
				Labels: map[string]string{
					LabelKeyLimguard: LabelValueTrue,
				},
			},
			Spec: coordinationv1.LeaseSpec{
				HolderIdentity:       ptr.To(r.nodeName),
				LeaseDurationSeconds: ptr.To(int32(3600)), // 1 hour lease duration
				AcquireTime:          &now,
				RenewTime:            &now,
			},
		}
		err := r.kube.Create(ctx, lease)
		if err == nil {
			log.Info("allocated new WireGuard IP", "ip", ipStr)
			return ipStr, nil
		}
		if apierrors.IsAlreadyExists(err) {
			// Check if we own this lease (could be from a previous run)
			existingLease := &coordinationv1.Lease{}
			if getErr := r.kube.Get(ctx, client.ObjectKey{Name: leaseName, Namespace: r.leaseNamespace}, existingLease); getErr == nil {
				if existingLease.Spec.HolderIdentity != nil && *existingLease.Spec.HolderIdentity == r.nodeName {
					// We own this lease, renew and use it
					if renewErr := r.renewLease(ctx, existingLease); renewErr != nil {
						log.Debug("failed to renew lease", "error", renewErr)
					}
					return ipStr, nil
				}
			}
			// Someone else owns it, try next IP
			inc(ip)
			continue
		}
		return "", fmt.Errorf("failed to create lease for %s: %w", ipStr, err)
	}
	return "", fmt.Errorf("no available IPs in range %s", r.nodeIPNet.String())
}

// firstIP returns the first usable IP in the CIDR (skips network address)
func (r *Reconciler) firstIP() net.IP {
	ip := make(net.IP, len(r.nodeIPNet.IP))
	copy(ip, r.nodeIPNet.IP)
	ip = ip.Mask(r.nodeIPNet.Mask)
	inc(ip) // Skip network address
	return ip
}

// inc increments an IP address
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// getNodeEndpoint returns the underlay (non-WireGuard) IP address of the node to be used as the WireGuard endpoint.
// If the node already has the endpoint annotation set, we prefer that (so operators can override it).
func (r *Reconciler) getNodeEndpoint(node *corev1.Node) string {
	if ann := node.GetAnnotations(); ann != nil {
		if ep := strings.TrimSpace(ann[AnnotationKeyWireguardPublicEndpoint]); ep != "" {
			return ep
		}
	}
	for _, addr := range node.Status.Addresses {
		if addr.Type == corev1.NodeInternalIP {
			return addr.Address
		}
	}
	return ""
}

// updateNodeAnnotations updates the node with WireGuard metadata
func (r *Reconciler) updateNodeAnnotations(ctx context.Context, node *corev1.Node, ip, publicKey, endpoint string) error {
	annotations := node.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}

	needsUpdate := false
	if annotations[AnnotationKeyWireguardIPV4Address] != ip {
		annotations[AnnotationKeyWireguardIPV4Address] = ip
		needsUpdate = true
	}
	if annotations[AnnotationKeyWireguardPublicKey] != publicKey {
		annotations[AnnotationKeyWireguardPublicKey] = publicKey
		needsUpdate = true
	}
	if annotations[AnnotationKeyWireguardPublicEndpoint] != endpoint {
		annotations[AnnotationKeyWireguardPublicEndpoint] = endpoint
		needsUpdate = true
	}

	if needsUpdate {
		node.SetAnnotations(annotations)
		return r.kube.Update(ctx, node)
	}
	return nil
}

// configureAllPeers configures WireGuard peers from all other nodes.
// Used on startup and periodic sync.
func (r *Reconciler) configureAllPeers(ctx context.Context, log logging.Logger) error {
	// List all nodes
	nodes := &corev1.NodeList{}
	if err := r.kube.List(ctx, nodes); err != nil {
		return fmt.Errorf("failed to list nodes: %w", err)
	}

	for _, node := range nodes.Items {
		if node.Name == r.nodeName {
			continue
		}

		annotations := node.GetAnnotations()
		if annotations == nil {
			continue
		}

		peerIP := annotations[AnnotationKeyWireguardIPV4Address]
		peerPublicKey := annotations[AnnotationKeyWireguardPublicKey]
		peerEndpoint := annotations[AnnotationKeyWireguardPublicEndpoint]

		if peerIP == "" || peerPublicKey == "" || peerEndpoint == "" {
			log.Debug("peer not ready", "peer", node.Name)
			continue
		}
		endpoint := fmt.Sprintf("%s:%d", peerEndpoint, DefaultListenPort)
		log.Debug("configuring peer", "peer", node.Name, "publicKey", peerPublicKey, "endpoint", endpoint, "peerIP", peerIP)
		if err := r.nm.SetPeer(ctx, peerPublicKey, endpoint, peerIP); err != nil {
			log.Info("failed to configure peer", "peer", node.Name, "error", err)
			continue
		}
	}

	return nil
}

// renewLease updates the RenewTime on the lease to prevent expiration.
// It only updates if the lease hasn't been renewed recently to avoid excessive updates.
func (r *Reconciler) renewLease(ctx context.Context, lease *coordinationv1.Lease) error {
	// Only renew if the lease is getting stale
	if lease.Spec.RenewTime != nil {
		age := time.Since(lease.Spec.RenewTime.Time)
		if age < leaseRenewThreshold {
			return nil // Lease is fresh, no need to renew
		}
	}

	now := metav1.NewMicroTime(time.Now())
	lease.Spec.RenewTime = &now
	return r.kube.Update(ctx, lease)
}

// ipToLeaseName converts an IP address to a lease name
func ipToLeaseName(ip string) string {
	return "wg-" + strings.ReplaceAll(ip, ".", "-")
}

// DerivePublicKey derives the public key from a private key file.
func DerivePublicKey(privateKeyPath string) (string, error) {
	data, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return "", fmt.Errorf("failed to read private key: %w", err)
	}

	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = strings.NewReader(strings.TrimSpace(string(data)))
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to derive public key: %w", err)
	}

	return strings.TrimSpace(string(out)), nil
}

// EnsurePrivateKey reads or generates a WireGuard private key at the given path.
// Returns the path to the key file.
func EnsurePrivateKey(keyPath string) (string, error) {
	// Try to read existing key
	if _, err := os.Stat(keyPath); err == nil {
		return keyPath, nil
	}

	// Generate new key using wg command
	out, err := exec.Command("wg", "genkey").Output()
	if err != nil {
		return "", fmt.Errorf("failed to generate private key: %w", err)
	}

	// Ensure directory exists
	dir := keyPath[:strings.LastIndex(keyPath, "/")]
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("failed to create directory: %w", err)
	}

	// Write key
	if err := os.WriteFile(keyPath, []byte(strings.TrimSpace(string(out))), 0600); err != nil {
		return "", fmt.Errorf("failed to write private key: %w", err)
	}

	return keyPath, nil
}
