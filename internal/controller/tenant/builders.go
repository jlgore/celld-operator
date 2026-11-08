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

import (
	"fmt"
	"maps"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"

	platformv1alpha1 "github.com/ezgamehost/celld-operator/api/v1alpha1"
)

// Builders for everything a Tenant owns. They are pure functions of the
// Tenant and the operator Options so the reconciler and the tests share
// one source of truth.

const (
	TenantLabel    = "celld-operator.io/tenant"
	ComponentLabel = "celld-operator.io/component"

	componentStorageProxy = "storage-proxy"
	componentAdminGateway = "admin-gateway"

	storageProxyName       = "storage-proxy"
	storageProxyPort       = 9000
	storageProxyHealthPort = 9001
	proxyCredentialsSecret = "storage-proxy-credentials"
	placeholderSecret      = "storage-placeholder-credentials"
	stsTokenDir            = "/var/run/secrets/tokens/sts"
	credentialsDir         = "/var/run/secrets/storage"

	adminGatewayName       = "admin-gateway"
	adminGatewayPort       = 8090
	adminGatewayHealthPort = 8091

	defaultDenyPolicy = "default-deny"
	fleetPolicy       = "fleet"

	quotaName      = "tenant-quota"
	limitRangeName = "tenant-limits"

	// PlaceholderAccessKeyPrefix marks the non-secret key the runtime signs
	// with. Nothing but the tenant's own proxy accepts it, and the proxy
	// ignores it.
	PlaceholderAccessKeyPrefix = "celld-tenant-"

	accessKeyIDKey         = "AWS_ACCESS_KEY_ID"
	secretAccessKeyKey     = "AWS_SECRET_ACCESS_KEY"
	sessionTokenKey        = "AWS_SESSION_TOKEN"
	namespaceNameLabel     = "kubernetes.io/metadata.name"
	kubernetesService      = "kubernetes"
	placeholderSecretValue = "not-a-credential-requests-are-re-signed-by-the-tenant-storage-proxy"
)

// Options are the operator-level settings for every Tenant.
type Options struct {
	// ProxyImage runs cmd/isolation-proxy (storage proxy and admin gateway).
	ProxyImage string
	// ProxyRuntimeClass optionally runs the proxy and gateway in a microVM
	// too. Empty uses the cluster default runtime.
	ProxyRuntimeClass string
	// OperatorNamespace and GatewayNamespace feed the default ingress rules.
	OperatorNamespace string
	GatewayNamespace  string
	// CredentialsNamespace holds static credential Secrets named by Tenants.
	CredentialsNamespace string
	// DefaultStorageClass is used when a Tenant names none.
	DefaultStorageClass string
	ClusterDomain       string
	// PeerEncryption declares how pod traffic is encrypted:
	// istio-ambient, cilium-wireguard, or none.
	PeerEncryption string
	// DNS selects the cluster DNS pods for egress.
	DNSNamespace string
	DNSLabels    map[string]string
	// PodOverhead is added per pod to the quota, matching the RuntimeClass
	// overhead (the VMM's own memory and CPU are charged to the pod).
	PodOverheadCPU    resource.Quantity
	PodOverheadMemory resource.Quantity
	// APIServerPeers lets the admin gateway reach the API server for
	// TokenReviews; the reconciler fills it from the kubernetes EndpointSlice.
	APIServerPeers []networkingv1.NetworkPolicyPeer
	APIServerPorts []int32
}

const (
	PeerEncryptionIstioAmbient    = "istio-ambient"
	PeerEncryptionCiliumWireGuard = "cilium-wireguard"
	PeerEncryptionNone            = "none"
)

// NamespaceName is the namespace a Tenant owns.
func NamespaceName(t *platformv1alpha1.Tenant) string { return "tenant-" + t.Name }

func tenantLabels(t *platformv1alpha1.Tenant) map[string]string {
	return map[string]string{TenantLabel: t.Name, "app.kubernetes.io/managed-by": "celld-operator"}
}

func componentLabels(t *platformv1alpha1.Tenant, component string) map[string]string {
	labels := tenantLabels(t)
	labels[ComponentLabel] = component
	return labels
}

func componentSelector(t *platformv1alpha1.Tenant, component string) map[string]string {
	return map[string]string{TenantLabel: t.Name, ComponentLabel: component}
}

func mergeLabels(live, desired map[string]string) map[string]string {
	out := maps.Clone(live)
	if out == nil {
		out = map[string]string{}
	}
	maps.Copy(out, desired)
	return out
}

func nodes(t *platformv1alpha1.Tenant) int32     { return positive(t.Spec.Nodes, 3) }
func cpuMillis(t *platformv1alpha1.Tenant) int32 { return positive(t.Spec.Resources.CPUMillis, 1000) }
func memoryGi(t *platformv1alpha1.Tenant) int32  { return positive(t.Spec.Resources.MemoryGi, 2) }
func ephemeralGi(t *platformv1alpha1.Tenant) int32 {
	return positive(t.Spec.Resources.EphemeralStorageGi, 2)
}
func volumeGi(t *platformv1alpha1.Tenant) int32 { return positive(t.Spec.Volume.SizeGi, 10) }
func proxyReplicas(t *platformv1alpha1.Tenant) int32 {
	return positive(t.Spec.StorageProxy.Replicas, 2)
}

func runtimeClass(t *platformv1alpha1.Tenant) string {
	if t.Spec.RuntimeClassName == "" {
		return "krun"
	}
	return t.Spec.RuntimeClassName
}

func region(t *platformv1alpha1.Tenant) string {
	if t.Spec.Bucket.Region == "" {
		return "us-east-1"
	}
	return t.Spec.Bucket.Region
}

func adminMode(t *platformv1alpha1.Tenant) platformv1alpha1.TenantAdminMode {
	if t.Spec.Admin.Mode == "" {
		return platformv1alpha1.TenantAdminGateway
	}
	return t.Spec.Admin.Mode
}

func positive(v, fallback int32) int32 {
	if v > 0 {
		return v
	}
	return fallback
}

func clusterDomain(o Options) string {
	if o.ClusterDomain == "" {
		return "cluster.local"
	}
	return o.ClusterDomain
}

// StorageEndpoint is the proxy URL the runtime is pointed at.
func StorageEndpoint(t *platformv1alpha1.Tenant, o Options) string {
	return fmt.Sprintf("http://%s.%s.svc.%s:%d", storageProxyName, NamespaceName(t), clusterDomain(o), storageProxyPort)
}

// AdminAudience is the token audience the admin gateway accepts. Mint one
// with: kubectl create token <sa> -n <ns> --audience <AdminAudience>.
func AdminAudience(t *platformv1alpha1.Tenant) string { return "celld-admin." + NamespaceName(t) }

func buildNamespace(t *platformv1alpha1.Tenant, o Options) *corev1.Namespace {
	labels := tenantLabels(t)
	// Every pod a tenant runs (celld, proxy, gateway) passes the
	// restricted profile, so enforce it: a WorkerApp author cannot add a
	// privileged sidecar through some other path.
	labels["pod-security.kubernetes.io/enforce"] = "restricted"
	labels["pod-security.kubernetes.io/enforce-version"] = "latest"
	if o.PeerEncryption == PeerEncryptionIstioAmbient {
		// ztunnel encrypts pod traffic with mTLS without putting a
		// sidecar in celld's drain path (or inside the microVM).
		labels["istio.io/dataplane-mode"] = "ambient"
	}
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: NamespaceName(t), Labels: labels}}
}

func buildPlaceholderSecret(t *platformv1alpha1.Tenant) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: placeholderSecret, Namespace: NamespaceName(t), Labels: tenantLabels(t),
			Annotations: map[string]string{"celld-operator.io/purpose": "Non-secret placeholder; the tenant storage proxy discards this signature and re-signs. See docs/isolation/FINDINGS.md section 3."}},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			accessKeyIDKey:     []byte(PlaceholderAccessKeyPrefix + t.Name),
			secretAccessKeyKey: []byte(placeholderSecretValue),
		},
	}
}

// proxy and gateway sizes; they also feed the quota.
var (
	proxyRequests = corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("128Mi"), corev1.ResourceEphemeralStorage: resource.MustParse("64Mi")}
	proxyLimits   = corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("500m"), corev1.ResourceMemory: resource.MustParse("256Mi"), corev1.ResourceEphemeralStorage: resource.MustParse("64Mi")}
)

func restrictedContainerSecurity() *corev1.SecurityContext {
	return &corev1.SecurityContext{
		AllowPrivilegeEscalation: ptr.To(false),
		ReadOnlyRootFilesystem:   ptr.To(true),
		RunAsNonRoot:             ptr.To(true),
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}
}

func buildServiceAccount(t *platformv1alpha1.Tenant, name, component string, automount bool) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta:                   metav1.ObjectMeta{Name: name, Namespace: NamespaceName(t), Labels: componentLabels(t, component)},
		AutomountServiceAccountToken: ptr.To(automount),
	}
}

func buildStorageProxyDeployment(t *platformv1alpha1.Tenant, o Options) *appsv1.Deployment {
	args := []string{
		"storage",
		fmt.Sprintf("--listen=:%d", storageProxyPort),
		fmt.Sprintf("--health-listen=:%d", storageProxyHealthPort),
		"--bucket=" + strings.TrimSuffix(t.Spec.Bucket.Name, "/"),
		"--region=" + region(t),
	}
	if t.Spec.Bucket.Endpoint != "" {
		args = append(args, "--endpoint="+strings.TrimSuffix(t.Spec.Bucket.Endpoint, "/"))
	}
	var volumes []corev1.Volume
	var mounts []corev1.VolumeMount
	if wi := t.Spec.Credentials.WebIdentity; wi != nil {
		audience := wi.Audience
		if audience == "" {
			audience = "sts.amazonaws.com"
		}
		duration := positive(wi.SessionDurationSeconds, 3600)
		args = append(args,
			"--credential-source=webIdentity",
			"--role-arn="+wi.RoleARN,
			"--token-file="+stsTokenDir+"/token",
			fmt.Sprintf("--session-duration=%ds", duration),
			"--session-name=celld-"+NamespaceName(t),
			fmt.Sprintf("--scope-session-policy=%t", wi.ScopeSessionPolicy == nil || *wi.ScopeSessionPolicy),
		)
		if wi.STSEndpoint != "" {
			args = append(args, "--sts-endpoint="+strings.TrimSuffix(wi.STSEndpoint, "/"))
		}
		// Audience-scoped and short-lived; the kubelet rotates it. This is
		// the only token in the pod (automount is off).
		volumes = append(volumes, corev1.Volume{Name: "sts-token", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
			Sources: []corev1.VolumeProjection{{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
				Audience: audience, ExpirationSeconds: ptr.To(int64(3600)), Path: "token",
			}}},
		}}})
		mounts = append(mounts, corev1.VolumeMount{Name: "sts-token", MountPath: stsTokenDir, ReadOnly: true})
	} else {
		args = append(args, "--credential-source=static", "--credentials-dir="+credentialsDir)
		volumes = append(volumes, corev1.Volume{Name: "credentials", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: proxyCredentialsSecret}}})
		mounts = append(mounts, corev1.VolumeMount{Name: "credentials", MountPath: credentialsDir, ReadOnly: true})
	}
	labels := componentLabels(t, componentStorageProxy)
	selector := componentSelector(t, componentStorageProxy)
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: storageProxyName, Namespace: NamespaceName(t), Labels: labels},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To(proxyReplicas(t)),
			Selector: &metav1.LabelSelector{MatchLabels: selector},
			Strategy: appsv1.DeploymentStrategy{Type: appsv1.RollingUpdateDeploymentStrategyType, RollingUpdate: &appsv1.RollingUpdateDeployment{
				MaxSurge: ptr.To(intstr.FromInt32(1)), MaxUnavailable: ptr.To(intstr.FromInt32(0)),
			}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					ServiceAccountName:           storageProxyName,
					AutomountServiceAccountToken: ptr.To(false),
					RuntimeClassName:             optionalString(o.ProxyRuntimeClass),
					SecurityContext:              &corev1.PodSecurityContext{RunAsNonRoot: ptr.To(true), RunAsUser: ptr.To(int64(65532)), SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
					Containers: []corev1.Container{{
						Name:            "proxy",
						Image:           o.ProxyImage,
						Args:            args,
						Ports:           []corev1.ContainerPort{{Name: "s3", ContainerPort: storageProxyPort}, {Name: "health", ContainerPort: storageProxyHealthPort}},
						ReadinessProbe:  &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/readyz", Port: intstr.FromInt32(storageProxyHealthPort)}}, PeriodSeconds: 10},
						LivenessProbe:   &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: intstr.FromInt32(storageProxyHealthPort)}}, PeriodSeconds: 20},
						Resources:       corev1.ResourceRequirements{Requests: proxyRequests, Limits: proxyLimits},
						SecurityContext: restrictedContainerSecurity(),
						VolumeMounts:    mounts,
					}},
					Volumes: volumes,
					TopologySpreadConstraints: []corev1.TopologySpreadConstraint{{
						MaxSkew: 1, TopologyKey: "kubernetes.io/hostname", WhenUnsatisfiable: corev1.ScheduleAnyway,
						LabelSelector: &metav1.LabelSelector{MatchLabels: selector},
					}},
				},
			},
		},
	}
}

func buildService(t *platformv1alpha1.Tenant, name, component string, port int32) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: NamespaceName(t), Labels: componentLabels(t, component)},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeClusterIP,
			Selector: componentSelector(t, component),
			Ports:    []corev1.ServicePort{{Name: "http", Port: port, TargetPort: intstr.FromInt32(port)}},
		},
	}
}

// AllowedAdminUsers are the Kubernetes usernames the gateway admits.
func AllowedAdminUsers(t *platformv1alpha1.Tenant) []string {
	users := make([]string, 0, len(t.Spec.Admin.AllowedServiceAccounts)+len(t.Spec.Admin.AllowedUsers))
	for _, sa := range t.Spec.Admin.AllowedServiceAccounts {
		users = append(users, fmt.Sprintf("system:serviceaccount:%s:%s", sa.Namespace, sa.Name))
	}
	return append(users, t.Spec.Admin.AllowedUsers...)
}

func buildAdminGatewayDeployment(t *platformv1alpha1.Tenant, o Options, w Workload) *appsv1.Deployment {
	labels := componentLabels(t, componentAdminGateway)
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: adminGatewayName, Namespace: NamespaceName(t), Labels: labels},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To(int32(1)),
			Selector: &metav1.LabelSelector{MatchLabels: componentSelector(t, componentAdminGateway)},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					ServiceAccountName: adminGatewayName,
					// The gateway needs its API token for TokenReviews; it
					// holds no storage credential.
					AutomountServiceAccountToken: ptr.To(true),
					RuntimeClassName:             optionalString(o.ProxyRuntimeClass),
					SecurityContext:              &corev1.PodSecurityContext{RunAsNonRoot: ptr.To(true), RunAsUser: ptr.To(int64(65532)), SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
					Containers: []corev1.Container{{
						Name:  "gateway",
						Image: o.ProxyImage,
						Args: []string{
							"admin",
							fmt.Sprintf("--listen=:%d", adminGatewayPort),
							fmt.Sprintf("--health-listen=:%d", adminGatewayHealthPort),
							"--fleet=" + w.StatefulSetName(t),
							fmt.Sprintf("--headless-service=%s.%s.svc.%s", w.HeadlessService(t), NamespaceName(t), clusterDomain(o)),
							fmt.Sprintf("--port=%d", w.AdminPort()),
							"--audience=" + AdminAudience(t),
							"--allowed=" + strings.Join(AllowedAdminUsers(t), ","),
						},
						Ports:           []corev1.ContainerPort{{Name: "http", ContainerPort: adminGatewayPort}, {Name: "health", ContainerPort: adminGatewayHealthPort}},
						ReadinessProbe:  &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: intstr.FromInt32(adminGatewayHealthPort)}}, PeriodSeconds: 10},
						Resources:       corev1.ResourceRequirements{Requests: proxyRequests, Limits: proxyLimits},
						SecurityContext: restrictedContainerSecurity(),
					}},
				},
			},
		},
	}
}

// buildAdminGatewayBinding lets the gateway create TokenReviews.
func buildAdminGatewayBinding(t *platformv1alpha1.Tenant) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "celld-" + NamespaceName(t) + "-admin-gateway", Labels: tenantLabels(t)},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "system:auth-delegator"},
		Subjects:   []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: adminGatewayName, Namespace: NamespaceName(t)}},
	}
}

func optionalString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// ---- Network policy ----------------------------------------------------

func namespacePeer(name string) networkingv1.NetworkPolicyPeer {
	return networkingv1.NetworkPolicyPeer{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{namespaceNameLabel: name}}}
}

func podPeer(labels map[string]string) networkingv1.NetworkPolicyPeer {
	return networkingv1.NetworkPolicyPeer{PodSelector: &metav1.LabelSelector{MatchLabels: labels}}
}

func tcp(port int32) networkingv1.NetworkPolicyPort {
	return networkingv1.NetworkPolicyPort{Protocol: ptr.To(corev1.ProtocolTCP), Port: ptr.To(intstr.FromInt32(port))}
}

func dnsEgress(o Options) networkingv1.NetworkPolicyEgressRule {
	ns, labels := o.DNSNamespace, o.DNSLabels
	if ns == "" {
		ns = "kube-system"
	}
	if labels == nil {
		labels = map[string]string{"k8s-app": "kube-dns"}
	}
	return networkingv1.NetworkPolicyEgressRule{
		To: []networkingv1.NetworkPolicyPeer{{
			NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{namespaceNameLabel: ns}},
			PodSelector:       &metav1.LabelSelector{MatchLabels: labels},
		}},
		Ports: []networkingv1.NetworkPolicyPort{
			{Protocol: ptr.To(corev1.ProtocolUDP), Port: ptr.To(intstr.FromInt32(53))},
			tcp(53),
		},
	}
}

// publicInternet is the default proxy egress: anything but cluster-private,
// link-local (cloud metadata) and loopback ranges.
func publicInternet() []networkingv1.NetworkPolicyPeer {
	return []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{
		CIDR:   "0.0.0.0/0",
		Except: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "127.0.0.0/8"},
	}}}
}

func policy(t *platformv1alpha1.Tenant, name string, selector map[string]string, ingress []networkingv1.NetworkPolicyIngressRule, egress []networkingv1.NetworkPolicyEgressRule) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: NamespaceName(t), Labels: tenantLabels(t)},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: selector},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
			Ingress:     ingress,
			Egress:      egress,
		},
	}
}

// buildNetworkPolicies renders the tenant's network: deny everything, then
// allow exactly (a) fleet <-> fleet on the peer port, (b) fleet -> proxy,
// (c) DNS, (d) proxy -> store, (e) admin clients -> gateway -> admin port.
// The WorkerApp controller's own policy additionally admits the operator to
// :8081 and the configured sources to :8080 (publicIngressFrom).
func buildNetworkPolicies(t *platformv1alpha1.Tenant, o Options, w Workload) []*networkingv1.NetworkPolicy {
	fleet := w.FleetSelector(t)
	proxy := componentSelector(t, componentStorageProxy)
	gateway := componentSelector(t, componentAdminGateway)

	policies := []*networkingv1.NetworkPolicy{
		// An empty pod selector selects every pod; no rules allow nothing.
		policy(t, defaultDenyPolicy, nil, nil, nil),
	}

	fleetEgress := make([]networkingv1.NetworkPolicyEgressRule, 0, 3+len(t.Spec.App.EgressTo))
	fleetEgress = append(fleetEgress,
		networkingv1.NetworkPolicyEgressRule{To: []networkingv1.NetworkPolicyPeer{podPeer(fleet)}, Ports: []networkingv1.NetworkPolicyPort{tcp(w.PeerPort())}},
		networkingv1.NetworkPolicyEgressRule{To: []networkingv1.NetworkPolicyPeer{podPeer(proxy)}, Ports: []networkingv1.NetworkPolicyPort{tcp(storageProxyPort)}},
		dnsEgress(o),
	)
	fleetEgress = append(fleetEgress, t.Spec.App.EgressTo...)
	fleetIngress := []networkingv1.NetworkPolicyIngressRule{
		{From: []networkingv1.NetworkPolicyPeer{podPeer(fleet)}, Ports: []networkingv1.NetworkPolicyPort{tcp(w.PeerPort())}},
	}
	if adminMode(t) == platformv1alpha1.TenantAdminGateway {
		fleetIngress = append(fleetIngress, networkingv1.NetworkPolicyIngressRule{
			From: []networkingv1.NetworkPolicyPeer{podPeer(gateway)}, Ports: []networkingv1.NetworkPolicyPort{tcp(w.AdminPort())},
		})
	} else if peers := adminClientNamespaces(t); len(peers) > 0 {
		// Istio mode: the AuthorizationPolicy names the principals; the
		// network layer narrows to their namespaces.
		fleetIngress = append(fleetIngress, networkingv1.NetworkPolicyIngressRule{From: peers, Ports: []networkingv1.NetworkPolicyPort{tcp(w.AdminPort())}})
	}
	policies = append(policies, policy(t, fleetPolicy, fleet, fleetIngress, fleetEgress))

	proxyEgress := []networkingv1.NetworkPolicyEgressRule{dnsEgress(o)}
	if len(t.Spec.StorageProxy.EgressTo) > 0 {
		proxyEgress = append(proxyEgress, networkingv1.NetworkPolicyEgressRule{To: t.Spec.StorageProxy.EgressTo})
	} else {
		proxyEgress = append(proxyEgress, networkingv1.NetworkPolicyEgressRule{To: publicInternet()})
	}
	policies = append(policies, policy(t, storageProxyName, proxy,
		[]networkingv1.NetworkPolicyIngressRule{{From: []networkingv1.NetworkPolicyPeer{podPeer(fleet)}, Ports: []networkingv1.NetworkPolicyPort{tcp(storageProxyPort)}}},
		proxyEgress))

	if adminMode(t) == platformv1alpha1.TenantAdminGateway {
		gatewayEgress := []networkingv1.NetworkPolicyEgressRule{
			{To: []networkingv1.NetworkPolicyPeer{podPeer(fleet)}, Ports: []networkingv1.NetworkPolicyPort{tcp(w.AdminPort())}},
			dnsEgress(o),
		}
		if len(o.APIServerPeers) > 0 {
			ports := make([]networkingv1.NetworkPolicyPort, 0, len(o.APIServerPorts))
			for _, port := range o.APIServerPorts {
				ports = append(ports, tcp(port))
			}
			gatewayEgress = append(gatewayEgress, networkingv1.NetworkPolicyEgressRule{To: o.APIServerPeers, Ports: ports})
		}
		var gatewayIngress []networkingv1.NetworkPolicyIngressRule
		if peers := adminClientNamespaces(t); len(peers) > 0 {
			gatewayIngress = append(gatewayIngress, networkingv1.NetworkPolicyIngressRule{From: peers, Ports: []networkingv1.NetworkPolicyPort{tcp(adminGatewayPort)}})
		}
		policies = append(policies, policy(t, adminGatewayName, gateway, gatewayIngress, gatewayEgress))
	}
	return policies
}

// adminClientNamespaces are the namespaces of the allowed service accounts.
// Users (allowedUsers) reach the gateway through the API server's
// port-forward or service proxy, which NetworkPolicy does not see.
func adminClientNamespaces(t *platformv1alpha1.Tenant) []networkingv1.NetworkPolicyPeer {
	seen := map[string]bool{}
	var peers []networkingv1.NetworkPolicyPeer
	for _, sa := range t.Spec.Admin.AllowedServiceAccounts {
		if !seen[sa.Namespace] {
			seen[sa.Namespace] = true
			peers = append(peers, namespacePeer(sa.Namespace))
		}
	}
	return peers
}

// publicIngressFrom is who may reach the fleet's public listener.
func publicIngressFrom(t *platformv1alpha1.Tenant, o Options) []networkingv1.NetworkPolicyPeer {
	if len(t.Spec.App.IngressFrom) > 0 {
		return t.Spec.App.IngressFrom
	}
	peers := []networkingv1.NetworkPolicyPeer{podPeer(map[string]string{TenantLabel: t.Name})}
	if o.GatewayNamespace != "" {
		peers = append(peers, namespacePeer(o.GatewayNamespace))
	}
	return peers
}

// ---- Quota -------------------------------------------------------------

func buildLimitRange(t *platformv1alpha1.Tenant) *corev1.LimitRange {
	cpu := *resource.NewMilliQuantity(int64(cpuMillis(t)), resource.DecimalSI)
	mem := resource.MustParse(fmt.Sprintf("%dGi", memoryGi(t)))
	eph := resource.MustParse(fmt.Sprintf("%dGi", ephemeralGi(t)))
	// Max also admits the helper containers (proxy, gateway), whose fixed
	// limits can exceed a small tenant's per-node size.
	maxCPU, maxMem := larger(cpu, proxyLimits[corev1.ResourceCPU]), larger(mem, proxyLimits[corev1.ResourceMemory])
	return &corev1.LimitRange{
		ObjectMeta: metav1.ObjectMeta{Name: limitRangeName, Namespace: NamespaceName(t), Labels: tenantLabels(t)},
		Spec: corev1.LimitRangeSpec{Limits: []corev1.LimitRangeItem{
			{
				// The WorkerApp sets a CPU request but no CPU limit; the
				// default limit here makes the per-node CPU budget hard.
				// It is also the cgroup quota the microVM's vCPUs run under.
				Type:           corev1.LimitTypeContainer,
				Default:        corev1.ResourceList{corev1.ResourceCPU: cpu, corev1.ResourceMemory: mem, corev1.ResourceEphemeralStorage: eph},
				DefaultRequest: corev1.ResourceList{corev1.ResourceCPU: cpu, corev1.ResourceMemory: mem},
				Max:            corev1.ResourceList{corev1.ResourceCPU: maxCPU, corev1.ResourceMemory: maxMem, corev1.ResourceEphemeralStorage: eph},
			},
			{
				Type: corev1.LimitTypePersistentVolumeClaim,
				Max:  corev1.ResourceList{corev1.ResourceStorage: resource.MustParse(fmt.Sprintf("%dGi", volumeGi(t)))},
			},
		}},
	}
}

func larger(a, b resource.Quantity) resource.Quantity {
	if a.Cmp(b) >= 0 {
		return a
	}
	return b
}

func buildResourceQuota(t *platformv1alpha1.Tenant, o Options) *corev1.ResourceQuota {
	n := int64(nodes(t))
	// Helper pods: proxy replicas + gateway, plus one surge pod each for
	// rolling Deployment updates.
	helpers := int64(proxyReplicas(t)) + 1 + 2
	pods := n + helpers

	sum := func(perNode resource.Quantity, perHelper resource.Quantity, overhead resource.Quantity) resource.Quantity {
		total := resource.Quantity{}
		for range n {
			total.Add(perNode)
		}
		for range helpers {
			total.Add(perHelper)
		}
		for range pods {
			total.Add(overhead)
		}
		return total
	}
	cpu := *resource.NewMilliQuantity(int64(cpuMillis(t)), resource.DecimalSI)
	mem := resource.MustParse(fmt.Sprintf("%dGi", memoryGi(t)))
	eph := resource.MustParse(fmt.Sprintf("%dGi", ephemeralGi(t)))
	storage := resource.MustParse(fmt.Sprintf("%dGi", int64(volumeGi(t))*n))

	hard := corev1.ResourceList{
		corev1.ResourceRequestsCPU:            sum(cpu, proxyRequests[corev1.ResourceCPU], o.PodOverheadCPU),
		corev1.ResourceLimitsCPU:              sum(cpu, proxyLimits[corev1.ResourceCPU], o.PodOverheadCPU),
		corev1.ResourceRequestsMemory:         sum(mem, proxyRequests[corev1.ResourceMemory], o.PodOverheadMemory),
		corev1.ResourceLimitsMemory:           sum(mem, proxyLimits[corev1.ResourceMemory], o.PodOverheadMemory),
		corev1.ResourceLimitsEphemeralStorage: sum(eph, proxyLimits[corev1.ResourceEphemeralStorage], resource.Quantity{}),
		corev1.ResourceRequestsStorage:        storage,
		corev1.ResourcePersistentVolumeClaims: *resource.NewQuantity(n, resource.DecimalSI),
		corev1.ResourcePods:                   *resource.NewQuantity(pods, resource.DecimalSI),
		corev1.ResourceServicesLoadBalancers:  resource.MustParse("0"),
		corev1.ResourceServicesNodePorts:      resource.MustParse("0"),
	}
	return &corev1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{Name: quotaName, Namespace: NamespaceName(t), Labels: tenantLabels(t)},
		Spec:       corev1.ResourceQuotaSpec{Hard: hard},
	}
}

// ---- Istio -------------------------------------------------------------

func buildPeerAuthentication(t *platformv1alpha1.Tenant) map[string]any {
	return map[string]any{
		"apiVersion": "security.istio.io/v1",
		"kind":       "PeerAuthentication",
		"metadata":   map[string]any{"name": "default", "namespace": NamespaceName(t), "labels": toAny(tenantLabels(t))},
		"spec":       map[string]any{"mtls": map[string]any{"mode": "STRICT"}},
	}
}

func buildAdminAuthorizationPolicy(t *platformv1alpha1.Tenant, o Options, w Workload) map[string]any {
	principals := make([]any, 0, len(t.Spec.Admin.AllowedServiceAccounts))
	for _, sa := range t.Spec.Admin.AllowedServiceAccounts {
		principals = append(principals, fmt.Sprintf("%s/ns/%s/sa/%s", clusterDomain(o), sa.Namespace, sa.Name))
	}
	return map[string]any{
		"apiVersion": "security.istio.io/v1",
		"kind":       "AuthorizationPolicy",
		"metadata":   map[string]any{"name": "tenant-admin", "namespace": NamespaceName(t), "labels": toAny(tenantLabels(t))},
		"spec": map[string]any{
			"selector": map[string]any{"matchLabels": toAny(w.FleetSelector(t))},
			"action":   "ALLOW",
			"rules": []any{map[string]any{
				"from": []any{map[string]any{"source": map[string]any{"principals": principals}}},
				"to":   []any{map[string]any{"operation": map[string]any{"ports": []any{fmt.Sprint(w.AdminPort())}}}},
			}},
		},
	}
}

func toAny(in map[string]string) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
