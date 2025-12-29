package limguard

import (
	"context"
	"fmt"
	"net"

	"github.com/crossplane/crossplane-runtime/pkg/logging"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// IPAllocationConfigMapName is the name of the ConfigMap used for IP allocation.
	IPAllocationConfigMapName = "limguard-ip-allocations"
)

// EnsureWireguardIPAllocation ensures we have a WireGuard IPv4 allocated via a shared ConfigMap.
// The ConfigMap uses IP addresses as keys and node names as values.
// If an IP is already allocated to another node, we try the next IP in the range.
//
// This is intentionally separated so callers (e.g., cmd/main.go) can learn the WireGuard IP
// before starting the controller-runtime manager.
func EnsureWireguardIPAllocation(
	ctx context.Context,
	kube client.Client,
	nodeName string,
	nodeIPNet string,
	configMapNamespace string,
	log logging.Logger,
) (string, error) {
	_, ipNet, err := net.ParseCIDR(nodeIPNet)
	if err != nil {
		return "", fmt.Errorf("failed to parse node ip cidr %s: %w", nodeIPNet, err)
	}

	// First, check if we already have an IP allocated in the ConfigMap
	cm := &corev1.ConfigMap{}
	cmKey := client.ObjectKey{Name: IPAllocationConfigMapName, Namespace: configMapNamespace}
	err = kube.Get(ctx, cmKey, cm)
	if err != nil && !apierrors.IsNotFound(err) {
		return "", fmt.Errorf("failed to get IP allocation ConfigMap: %w", err)
	}

	// If ConfigMap doesn't exist, create it
	if apierrors.IsNotFound(err) {
		cm = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      IPAllocationConfigMapName,
				Namespace: configMapNamespace,
				Labels: map[string]string{
					LabelKeyLimguard: LabelValueTrue,
				},
			},
			Data: make(map[string]string),
		}
		if err := kube.Create(ctx, cm); err != nil {
			if !apierrors.IsAlreadyExists(err) {
				return "", fmt.Errorf("failed to create IP allocation ConfigMap: %w", err)
			}
			// Someone else created it, fetch it
			if err := kube.Get(ctx, cmKey, cm); err != nil {
				return "", fmt.Errorf("failed to get IP allocation ConfigMap after creation conflict: %w", err)
			}
		}
	}

	// Check if this node already has an IP allocated
	if cm.Data != nil {
		for ip, owner := range cm.Data {
			if owner == nodeName {
				log.Info("found existing IP allocation", "ip", ip)
				return ip, nil
			}
		}
	}

	// Try to allocate a new IP
	ip := firstUsableIP(ipNet)
	for ipNet.Contains(ip) {
		ipStr := ip.String()

		// Re-fetch ConfigMap to get the latest version (optimistic locking)
		if err := kube.Get(ctx, cmKey, cm); err != nil {
			return "", fmt.Errorf("failed to get IP allocation ConfigMap: %w", err)
		}

		if cm.Data == nil {
			cm.Data = make(map[string]string)
		}

		// Check if this IP is already taken
		if owner, exists := cm.Data[ipStr]; exists {
			if owner == nodeName {
				// We already own this IP
				return ipStr, nil
			}
			// IP is taken by another node, try the next one
			incIP(ip)
			continue
		}

		// Try to claim this IP
		cm.Data[ipStr] = nodeName
		if err := kube.Update(ctx, cm); err != nil {
			if apierrors.IsConflict(err) {
				// Someone else updated the ConfigMap, retry from scratch
				log.Debug("conflict updating ConfigMap, retrying", "ip", ipStr)
				continue
			}
			return "", fmt.Errorf("failed to update IP allocation ConfigMap: %w", err)
		}

		log.Info("allocated new WireGuard IP", "ip", ipStr)
		return ipStr, nil
	}

	return "", fmt.Errorf("no available IPs in range %s", nodeIPNet)
}

// firstUsableIP returns the first usable IP in the CIDR (skips network address).
func firstUsableIP(ipNet *net.IPNet) net.IP {
	ip := make(net.IP, len(ipNet.IP))
	copy(ip, ipNet.IP)
	ip = ip.Mask(ipNet.Mask)
	incIP(ip) // Skip network address
	return ip
}

// incIP increments an IP address (in place).
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
