/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package tenant

// Operator wiring for the Tenant controller. It lives here rather than in
// cmd/ because the upstream build compiles cmd/main.go as a single file;
// main.go only gains the calls into this one.

import (
	"flag"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/api/resource"
	ctrl "sigs.k8s.io/controller-runtime"
)

// Flags are the operator flags for the Tenant controller.
type Flags struct {
	enabled              bool
	proxyImage           string
	proxyRuntimeClass    string
	credentialsNamespace string
	storageClass         string
	peerEncryption       string
	clusterDomain        string
	dnsNamespace         string
	dnsLabels            string
	overheadCPU          string
	overheadMemory       string
}

// RegisterFlags adds the Tenant flags to the global flag set.
func RegisterFlags() *Flags {
	f := &Flags{}
	flag.BoolVar(&f.enabled, "enable-tenants", false,
		"Run the Tenant isolation controller. Implies --allow-namespace-local-bucket-endpoints.")
	flag.StringVar(&f.proxyImage, "tenant-proxy-image", "ghcr.io/ezgamehost/celld-operator-isolation-proxy:latest",
		"Image for the tenant storage proxy and admin gateway (cmd/isolation-proxy).")
	flag.StringVar(&f.proxyRuntimeClass, "tenant-proxy-runtime-class", "",
		"Optional RuntimeClass for the storage proxy and admin gateway pods.")
	flag.StringVar(&f.credentialsNamespace, "tenant-credentials-namespace", "celld-operator-system",
		"Namespace holding static credential Secrets that Tenants name in spec.credentials.secret.")
	flag.StringVar(&f.storageClass, "tenant-storage-class", "",
		"Default block-backed StorageClass for tenant node volumes.")
	flag.StringVar(&f.peerEncryption, "tenant-peer-encryption", PeerEncryptionNone,
		"How pod traffic is encrypted: istio-ambient, cilium-wireguard, or none.")
	flag.StringVar(&f.clusterDomain, "tenant-cluster-domain", "cluster.local", "Kubernetes DNS suffix.")
	flag.StringVar(&f.dnsNamespace, "tenant-dns-namespace", "kube-system", "Namespace of the cluster DNS pods.")
	flag.StringVar(&f.dnsLabels, "tenant-dns-labels", "k8s-app=kube-dns", "Labels of the cluster DNS pods (k=v,...).")
	flag.StringVar(&f.overheadCPU, "tenant-pod-overhead-cpu", "250m",
		"Per-pod overhead added to tenant quotas; match the RuntimeClass overhead.")
	flag.StringVar(&f.overheadMemory, "tenant-pod-overhead-memory", "256Mi",
		"Per-pod memory overhead added to tenant quotas; match the RuntimeClass overhead.")
	return f
}

// Enabled reports whether --enable-tenants was set.
func (f *Flags) Enabled() bool { return f.enabled }

// Setup registers the controller with the manager when enabled.
func (f *Flags) Setup(mgr ctrl.Manager, watchNamespace, operatorNamespace, gatewayNamespace string) error {
	if !f.enabled {
		return nil
	}
	if watchNamespace != "" {
		// Tenants create namespaces; a single-namespace cache cannot see them.
		return fmt.Errorf("--enable-tenants requires a cluster-wide operator (unset --watch-namespace)")
	}
	switch f.peerEncryption {
	case PeerEncryptionIstioAmbient, PeerEncryptionCiliumWireGuard, PeerEncryptionNone:
	default:
		return fmt.Errorf("--tenant-peer-encryption=%q: want istio-ambient, cilium-wireguard, or none", f.peerEncryption)
	}
	cpu, err := resource.ParseQuantity(f.overheadCPU)
	if err != nil {
		return fmt.Errorf("--tenant-pod-overhead-cpu: %w", err)
	}
	memory, err := resource.ParseQuantity(f.overheadMemory)
	if err != nil {
		return fmt.Errorf("--tenant-pod-overhead-memory: %w", err)
	}
	labels := map[string]string{}
	for pair := range strings.SplitSeq(f.dnsLabels, ",") {
		if key, value, ok := strings.Cut(strings.TrimSpace(pair), "="); ok {
			labels[key] = value
		}
	}
	return (&Reconciler{
		Client:    mgr.GetClient(),
		APIReader: mgr.GetAPIReader(),
		Options: Options{
			ProxyImage:           f.proxyImage,
			ProxyRuntimeClass:    f.proxyRuntimeClass,
			OperatorNamespace:    operatorNamespace,
			GatewayNamespace:     gatewayNamespace,
			CredentialsNamespace: f.credentialsNamespace,
			DefaultStorageClass:  f.storageClass,
			ClusterDomain:        f.clusterDomain,
			PeerEncryption:       f.peerEncryption,
			DNSNamespace:         f.dnsNamespace,
			DNSLabels:            labels,
			PodOverheadCPU:       cpu,
			PodOverheadMemory:    memory,
		},
	}).SetupWithManager(mgr)
}
