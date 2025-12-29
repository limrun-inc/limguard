package main

import (
	"context"
	"flag"
	"net"
	"os"
	"runtime"

	"github.com/crossplane/crossplane-runtime/pkg/logging"
	"github.com/go-logr/logr"
	limguard "github.com/limrun-inc/limguard/pkg"
	"github.com/limrun-inc/limguard/version"
	"go.uber.org/zap/zapcore"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

var (
	scheme   = kruntime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(coordinationv1.AddToScheme(scheme))
}

func main() {
	var debug bool
	var nodeName string
	var nodeIPCidr string
	var leaseNamespace string
	var probeAddr string
	var interfaceName string
	var listenPort int
	defaultInterfaceName := "wg0"
	if runtime.GOOS == "darwin" {
		defaultInterfaceName = "utun5"
	}

	flag.BoolVar(&debug, "debug", false, "Enable debug logging.")
	flag.StringVar(&nodeName, "node-name", os.Getenv("NODE_NAME"), "The name of the node this instance is running on.")
	flag.StringVar(&nodeIPCidr, "node-ip-cidr", getEnvOrDefault("NODE_IP_CIDR", "10.200.0.0/24"), "The CIDR range to allocate WireGuard IPs from.")
	flag.StringVar(&leaseNamespace, "lease-namespace", getEnvOrDefault("LEASE_NAMESPACE", "kube-node-lease"), "The namespace to create Lease objects for IP coordination.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.StringVar(&interfaceName, "interface-name", getEnvOrDefault("INTERFACE_NAME", defaultInterfaceName), "The WireGuard interface name.")
	flag.IntVar(&listenPort, "listen-port", 51820, "The WireGuard listen port.")
	flag.Parse()
	var zlog logr.Logger
	if debug {
		zlog = zap.New(
			zap.UseDevMode(true),
			zap.Level(zapcore.DebugLevel),
		)
	} else {
		zlog = zap.New(
			zap.UseDevMode(false),
		)
	}
	klog.SetLogger(zlog)
	defer klog.Flush()
	ctrl.SetLogger(zlog)
	if nodeName == "" {
		setupLog.Error(nil, "node-name is required (set via --node-name or NODE_NAME env var)")
		os.Exit(1)
	}
	log := logging.NewLogrLogger(zlog)
	log.Info("initializing",
		"debug", debug,
		"version", version.Version,
		"nodeName", nodeName,
		"nodeIPCidr", nodeIPCidr,
		"leaseNamespace", leaseNamespace,
		"interfaceName", interfaceName,
		"listenPort", listenPort,
	)
	ctrl.SetLogger(zlog)
	privateKeyPath := "/etc/limguard/privatekey"
	if _, err := limguard.EnsurePrivateKey(privateKeyPath); err != nil {
		setupLog.Error(err, "failed to ensure private key")
		os.Exit(1)
	}
	publicKey, err := limguard.DerivePublicKey(privateKeyPath)
	if err != nil {
		setupLog.Error(err, "failed to derive public key")
		os.Exit(1)
	}
	cfg := ctrl.GetConfigOrDie()
	kube, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		setupLog.Error(err, "failed to create kube client")
		os.Exit(1)
	}
	_, ipNet, err := net.ParseCIDR(nodeIPCidr)
	if err != nil {
		setupLog.Error(err, "failed to parse node-ip-cidr", "nodeIPCidr", nodeIPCidr)
		os.Exit(1)
	}
	wireguardIP := ""
	node := &corev1.Node{}
	if err := kube.Get(context.Background(), client.ObjectKey{Name: nodeName}, node); err == nil {
		if ann := node.GetAnnotations(); ann != nil {
			wireguardIP = ann[limguard.AnnotationKeyWireguardIPV4Address]
			log.Info("found existing IP annotation", "ip", wireguardIP)
		}
	}
	if wireguardIP == "" {
		log.Info("no existing IP annotation found, allocating new IP")
		wireguardIP, err = limguard.EnsureWireguardIPAllocation(
			context.Background(),
			kube,
			nodeName,
			ipNet,
			leaseNamespace,
			log.WithValues("component", "ip-allocation"),
		)
		if err != nil {
			setupLog.Error(err, "failed to allocate wireguard IP")
			os.Exit(1)
		}
		log.Info("allocated new WireGuard IP", "ip", wireguardIP)
	}
	// NewNetworkManager is defined per-platform in linux.go and darwin.go
	nm, err := limguard.NewNetworkManager(interfaceName, privateKeyPath, listenPort, wireguardIP, log)
	if err != nil {
		setupLog.Error(err, "failed to initialize network manager")
		os.Exit(1)
	}
	log.Info("network manager initialized", "interface", interfaceName, "publicKey", publicKey, "os", runtime.GOOS)
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                        scheme,
		LeaderElectionReleaseOnCancel: false,
		HealthProbeBindAddress:        probeAddr,
	})
	if err != nil {
		setupLog.Error(err, "unable to create manager")
		os.Exit(1)
	}

	if err := limguard.SetupWithManager(mgr, nm, nodeName, publicKey, wireguardIP, log.WithValues("component", "limguard")); err != nil {
		setupLog.Error(err, "unable to setup limguard controller")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
