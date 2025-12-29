package limguard

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/crossplane/crossplane-runtime/pkg/logging"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// IPAllocationConfigMapName is the name of the ConfigMap used for IP allocation.
	IPAllocationConfigMapName = "limguard-ip-allocations"

	// legacyLeaseNamespace is where the old Lease-based allocation stored leases.
	legacyLeaseNamespace = "kube-node-lease"
	// legacyLeasePrefix is the prefix used for old Lease names (e.g., "wg-10-200-0-1").
	legacyLeasePrefix = "wg-"
)

// EnsureWireguardIPAllocation ensures we have a WireGuard IPv4 allocated via a shared ConfigMap.
// The ConfigMap uses IP addresses as keys and node names as values.
// If an IP is already allocated to another node, we try the next IP in the range.
//
// This function also handles migration from the old Lease-based allocation system.
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

	// Try to migrate from legacy Lease-based allocation
	migratedIP, err := migrateFromLease(ctx, kube, nodeName, configMapNamespace, log)
	if err != nil {
		log.Info("lease migration check failed, continuing with normal allocation", "error", err)
	}
	if migratedIP != "" {
		return migratedIP, nil
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

// migrateFromLease checks for a legacy Lease in kube-node-lease namespace owned by this node,
// migrates it to the ConfigMap, and deletes the old Lease.
// Returns the migrated IP if successful, empty string if no lease found.
func migrateFromLease(
	ctx context.Context,
	kube client.Client,
	nodeName string,
	configMapNamespace string,
	log logging.Logger,
) (string, error) {
	// List all leases with the limguard label in kube-node-lease namespace
	leaseList := &coordinationv1.LeaseList{}
	if err := kube.List(ctx, leaseList,
		client.InNamespace(legacyLeaseNamespace),
		client.HasLabels{LabelKeyLimguard},
	); err != nil {
		return "", fmt.Errorf("failed to list legacy leases: %w", err)
	}

	// Find a lease owned by this node
	var ownedLease *coordinationv1.Lease
	for i := range leaseList.Items {
		lease := &leaseList.Items[i]
		if lease.Spec.HolderIdentity != nil && *lease.Spec.HolderIdentity == nodeName {
			ownedLease = lease
			break
		}
	}

	if ownedLease == nil {
		return "", nil // No legacy lease found for this node
	}

	// Extract IP from lease name (format: "wg-10-200-0-1" -> "10.200.0.1")
	ip := leaseNameToIP(ownedLease.Name)
	if ip == "" {
		log.Info("could not parse IP from legacy lease name", "leaseName", ownedLease.Name)
		return "", nil
	}

	log.Info("found legacy lease, migrating to ConfigMap", "ip", ip, "leaseName", ownedLease.Name)

	// Ensure the ConfigMap exists and add the IP allocation
	cm := &corev1.ConfigMap{}
	cmKey := client.ObjectKey{Name: IPAllocationConfigMapName, Namespace: configMapNamespace}
	err := kube.Get(ctx, cmKey, cm)
	if apierrors.IsNotFound(err) {
		cm = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      IPAllocationConfigMapName,
				Namespace: configMapNamespace,
				Labels: map[string]string{
					LabelKeyLimguard: LabelValueTrue,
				},
			},
			Data: map[string]string{ip: nodeName},
		}
		if err := kube.Create(ctx, cm); err != nil && !apierrors.IsAlreadyExists(err) {
			return "", fmt.Errorf("failed to create ConfigMap during migration: %w", err)
		}
		if apierrors.IsAlreadyExists(err) {
			// Refetch and update
			if err := kube.Get(ctx, cmKey, cm); err != nil {
				return "", fmt.Errorf("failed to get ConfigMap during migration: %w", err)
			}
		}
	} else if err != nil {
		return "", fmt.Errorf("failed to get ConfigMap during migration: %w", err)
	}

	// Add or verify our IP in the ConfigMap
	if cm.Data == nil {
		cm.Data = make(map[string]string)
	}

	// Check if IP is already allocated to someone else
	if owner, exists := cm.Data[ip]; exists && owner != nodeName {
		log.Info("legacy IP already allocated to different node in ConfigMap, will allocate new IP",
			"ip", ip, "existingOwner", owner)
		// Delete the legacy lease since we can't use this IP anyway
		if err := kube.Delete(ctx, ownedLease); err != nil && !apierrors.IsNotFound(err) {
			log.Info("failed to delete legacy lease", "error", err)
		}
		return "", nil
	}

	// Only update if not already set correctly
	if cm.Data[ip] != nodeName {
		cm.Data[ip] = nodeName
		if err := kube.Update(ctx, cm); err != nil {
			return "", fmt.Errorf("failed to update ConfigMap during migration: %w", err)
		}
	}

	// Delete the legacy lease
	if err := kube.Delete(ctx, ownedLease); err != nil && !apierrors.IsNotFound(err) {
		log.Info("failed to delete legacy lease after migration", "error", err, "leaseName", ownedLease.Name)
		// Don't fail - migration succeeded, lease cleanup is best-effort
	} else {
		log.Info("deleted legacy lease after migration", "leaseName", ownedLease.Name)
	}

	log.Info("successfully migrated IP from legacy lease", "ip", ip)
	return ip, nil
}

// leaseNameToIP converts a legacy lease name back to an IP address.
// Format: "wg-10-200-0-1" -> "10.200.0.1"
func leaseNameToIP(leaseName string) string {
	if !strings.HasPrefix(leaseName, legacyLeasePrefix) {
		return ""
	}
	ipPart := strings.TrimPrefix(leaseName, legacyLeasePrefix)
	ip := strings.ReplaceAll(ipPart, "-", ".")
	// Validate it's a valid IP
	if net.ParseIP(ip) == nil {
		return ""
	}
	return ip
}
