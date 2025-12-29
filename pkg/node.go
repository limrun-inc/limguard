package limguard

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/crossplane/crossplane-runtime/pkg/logging"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
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
	// SetPeer configures a WireGuard peer and adds a route for its allowed IPs.
	SetPeer(ctx context.Context, publicKey, endpoint, wireguardIp string) error
}

func SetupWithManager(mgr ctrl.Manager, nm NetworkManager, nodeName, publicKey, wireguardIP string, log logging.Logger) error {
	r := &Reconciler{
		kube:        mgr.GetClient(),
		Scheme:      mgr.GetScheme(),
		log:         log.WithValues("controller", controllerName),
		nm:          nm,
		nodeName:    nodeName,
		publicKey:   publicKey,
		wireguardIP: wireguardIP,
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Node{}).
		Named(controllerName).
		Complete(r)
}

type Reconciler struct {
	kube   client.Client
	Scheme *runtime.Scheme

	nm          NetworkManager
	nodeName    string
	publicKey   string
	wireguardIP string

	log logging.Logger
}

// Reconcile runs for every event on Node resources.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.log.WithValues("node", req.Name)
	log.Debug("reconciling")
	node := &corev1.Node{}
	if err := r.kube.Get(ctx, client.ObjectKey{Name: req.Name}, node); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if r.nodeName == req.Name {
		endpoint := r.getNodeEndpoint(node)
		if endpoint == "" {
			log.Info("node has no InternalIP yet, waiting...")
			return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
		}
		if err := r.updateNodeAnnotations(ctx, node, r.wireguardIP, r.publicKey, endpoint); err != nil {
			log.Info("failed to update node annotations", "error", err)
			return ctrl.Result{}, nil
		}
	}
	annotations := node.GetAnnotations()
	if annotations == nil {
		return ctrl.Result{}, nil
	}
	peerIP := annotations[AnnotationKeyWireguardIPV4Address]
	peerPublicKey := annotations[AnnotationKeyWireguardPublicKey]
	peerEndpoint := annotations[AnnotationKeyWireguardPublicEndpoint]
	if peerIP == "" || peerPublicKey == "" || peerEndpoint == "" {
		log.Info("peer not ready", "peer", req.Name, "peerIP", peerIP, "publicKey", peerPublicKey, "endpoint", peerEndpoint)
		return ctrl.Result{}, nil
	}
	endpoint := fmt.Sprintf("%s:%d", peerEndpoint, DefaultListenPort)
	log.Debug("configuring peer", "publicKey", peerPublicKey, "endpoint", endpoint, "peerIP", peerIP)
	if err := r.nm.SetPeer(ctx, peerPublicKey, endpoint, peerIP); err != nil {
		log.Info("failed to configure peer", "error", err)
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}
	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
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
