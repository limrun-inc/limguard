package limguard

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/crossplane/crossplane-runtime/pkg/logging"
	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// EnsureWireguardIPAllocation ensures we have a WireGuard IPv4 allocated via Lease objects.
// If existingIP is non-empty, it is validated/renewed first (if we still hold its lease).
//
// This is intentionally separated so callers (e.g., cmd/main.go) can learn the WireGuard IP
// before starting the controller-runtime manager.
func EnsureWireguardIPAllocation(
	ctx context.Context,
	kube client.Client,
	nodeName string,
	nodeIPNet *net.IPNet,
	leaseNamespace string,
	log logging.Logger,
) (string, error) {
	// Allocate by attempting to create leases until one succeeds.
	ip := firstUsableIP(nodeIPNet)
	for nodeIPNet.Contains(ip) {
		ipStr := ip.String()
		leaseName := ipToLeaseName(ipStr)
		now := metav1.NewMicroTime(time.Now())
		lease := &coordinationv1.Lease{
			ObjectMeta: metav1.ObjectMeta{
				Name:      leaseName,
				Namespace: leaseNamespace,
				Labels: map[string]string{
					LabelKeyLimguard: LabelValueTrue,
				},
			},
			Spec: coordinationv1.LeaseSpec{
				HolderIdentity:       ptr.To(nodeName),
				LeaseDurationSeconds: ptr.To(int32(10 * 365 * 24 * 3600)), // 10 year lease.
				AcquireTime:          &now,
				RenewTime:            &now,
			},
		}
		err := kube.Create(ctx, lease)
		if err == nil {
			log.Info("allocated new WireGuard IP", "ip", ipStr)
			return ipStr, nil
		}
		if apierrors.IsAlreadyExists(err) {
			// Check if we own this lease (could be from a previous run)
			existingLease := &coordinationv1.Lease{}
			if getErr := kube.Get(ctx, client.ObjectKey{Name: leaseName, Namespace: leaseNamespace}, existingLease); getErr == nil {
				if existingLease.Spec.HolderIdentity != nil && *existingLease.Spec.HolderIdentity == nodeName {
					return ipStr, nil
				}
			}
			incIP(ip)
			continue
		}
		return "", fmt.Errorf("failed to create lease for %s: %w", ipStr, err)
	}

	return "", fmt.Errorf("no available IPs in range %s", nodeIPNet.String())
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

// ipToLeaseName converts an IP address to a lease name.
func ipToLeaseName(ip string) string {
	return "wg-" + strings.ReplaceAll(ip, ".", "-")
}
