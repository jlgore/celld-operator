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

package v1alpha1

import (
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// A Tenant is the isolation boundary around one tenant's runtime fleet:
// its own namespace, microVM RuntimeClass, quota, default-deny network,
// prefix-scoped storage proxy, and authenticated admin access. The fleet
// itself is an ordinary WorkerApp the Tenant controller owns, so every
// WorkerApp guardrail (gated rollouts, drain rules, memory bounds) still
// applies. See docs/isolation/DESIGN.md.

// TenantEngine names the Durable Objects runtime that runs inside each
// microVM. Only celld is implemented; workerd cluster mode is the planned
// second engine (docs/isolation/DESIGN.md, "Runtime swappability").
// +kubebuilder:validation:Enum=celld
type TenantEngine string

const TenantEngineCelld TenantEngine = "celld"

// TenantAdminMode selects how access to the runtime's admin listener is
// authenticated.
// +kubebuilder:validation:Enum=Gateway;Istio
type TenantAdminMode string

const (
	// TenantAdminGateway runs an authenticating gateway in the tenant
	// namespace: callers present a Kubernetes bearer token, the gateway
	// verifies it with a TokenReview and checks the allowlist.
	TenantAdminGateway TenantAdminMode = "Gateway"
	// TenantAdminIstio grants the allowed service accounts' mesh
	// identities access to the admin port with an AuthorizationPolicy.
	TenantAdminIstio TenantAdminMode = "Istio"
)

// TenantResources are hard per-node limits. Inside a microVM runtime they
// also size the VM: krun takes the guest RAM from the memory limit.
type TenantResources struct {
	// cpuMillis is both the request and the hard CPU limit per node.
	// +optional
	// +kubebuilder:default=1000
	// +kubebuilder:validation:Minimum=100
	// +kubebuilder:validation:Maximum=64000
	CPUMillis int32 `json:"cpuMillis,omitempty"`

	// memoryGi is the memory request and limit per node.
	// +optional
	// +kubebuilder:default=2
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=256
	MemoryGi int32 `json:"memoryGi,omitempty"`

	// ephemeralStorageGi caps writable scratch space per node.
	// +optional
	// +kubebuilder:default=2
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=64
	EphemeralStorageGi int32 `json:"ephemeralStorageGi,omitempty"`
}

// TenantVolume is the per-node SQLite volume. Use a block-backed
// StorageClass: its filesystem size is a hard cap, unlike a shared
// filesystem that only accounts usage.
type TenantVolume struct {
	// sizeGi is the PVC size per node.
	// +optional
	// +kubebuilder:default=10
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4096
	SizeGi int32 `json:"sizeGi,omitempty"`

	// storageClassName selects a block-backed StorageClass. Unset uses the
	// operator's --tenant-storage-class, then the cluster default.
	// +optional
	StorageClassName *string `json:"storageClassName,omitempty"`
}

// TenantBucket locates the tenant's slice of an S3-compatible store. The
// runtime never talks to it directly: it talks to the tenant's storage
// proxy, which enforces the bucket and prefix and signs each request.
type TenantBucket struct {
	// name is the bucket and the tenant's prefix, e.g.
	// "s3://platform-cells/tenants/acme". The prefix is required: it is the
	// boundary the proxy enforces.
	// +required
	// +kubebuilder:validation:MaxLength=1024
	// +kubebuilder:validation:Pattern=`^s3://[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]/[a-zA-Z0-9._-]+(/[a-zA-Z0-9._-]+)*/?$`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="bucket identity is immutable"
	Name string `json:"name"`

	// endpoint is the upstream S3-compatible endpoint the proxy signs for.
	// Unset means AWS S3 in region.
	// +optional
	// +kubebuilder:validation:MaxLength=2048
	// +kubebuilder:validation:Pattern=`^https?://[^/?#@]+/?$`
	Endpoint string `json:"endpoint,omitempty"`

	// region is the signing region.
	// +optional
	// +kubebuilder:default="us-east-1"
	Region string `json:"region,omitempty"`
}

// WebIdentityCredentials mints short-lived credentials with STS
// AssumeRoleWithWebIdentity from the proxy's projected, audience-scoped
// ServiceAccount token. Nothing long-lived is stored anywhere.
type WebIdentityCredentials struct {
	// roleARN is the role the proxy assumes. Its trust policy should
	// accept only the tenant proxy's ServiceAccount
	// (system:serviceaccount:<tenant namespace>:storage-proxy).
	// +required
	// +kubebuilder:validation:MinLength=1
	RoleARN string `json:"roleARN"`

	// audience of the projected token.
	// +optional
	// +kubebuilder:default="sts.amazonaws.com"
	Audience string `json:"audience,omitempty"`

	// stsEndpoint overrides the STS endpoint (MinIO, Ceph RGW, or a
	// regional endpoint).
	// +optional
	// +kubebuilder:validation:Pattern=`^https?://[^/?#@]+/?$`
	STSEndpoint string `json:"stsEndpoint,omitempty"`

	// sessionDurationSeconds bounds each minted credential.
	// +optional
	// +kubebuilder:default=3600
	// +kubebuilder:validation:Minimum=900
	// +kubebuilder:validation:Maximum=43200
	SessionDurationSeconds int32 `json:"sessionDurationSeconds,omitempty"`

	// scopeSessionPolicy attaches an inline session policy that limits the
	// minted credential to the tenant's bucket prefix, even if the role
	// allows more.
	// +optional
	// +kubebuilder:default=true
	ScopeSessionPolicy *bool `json:"scopeSessionPolicy,omitempty"`
}

// SecretCredentials reads a static key pair from a Secret in the
// operator's credentials namespace (--tenant-credentials-namespace). The
// controller copies it into the tenant namespace, where only the proxy
// mounts it. Use for stores without STS, and scope the key to the prefix.
type SecretCredentials struct {
	// name of a Secret with AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY
	// (and optionally AWS_SESSION_TOKEN).
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
}

// TenantCredentials selects exactly one credential source for the proxy.
// +kubebuilder:validation:XValidation:rule="has(self.webIdentity) != has(self.secret)",message="select exactly one credential source"
type TenantCredentials struct {
	// +optional
	WebIdentity *WebIdentityCredentials `json:"webIdentity,omitempty"`
	// +optional
	Secret *SecretCredentials `json:"secret,omitempty"`
}

// TenantStorageProxy shapes the per-tenant signing proxy.
type TenantStorageProxy struct {
	// replicas of the proxy Deployment.
	// +optional
	// +kubebuilder:default=2
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=10
	Replicas int32 `json:"replicas,omitempty"`

	// egressTo names where the store (and STS) live, as NetworkPolicy
	// peers. Unset allows the public internet only: 0.0.0.0/0 minus
	// private, link-local (metadata), and loopback ranges.
	// +optional
	// +listType=atomic
	EgressTo []networkingv1.NetworkPolicyPeer `json:"egressTo,omitempty"`
}

// TenantApp is the application the tenant's fleet serves.
type TenantApp struct {
	// image is the runtime image. It must pass the operator's image
	// allowlist. Under krun, package celld with STOPSIGNAL SIGINT (see
	// docs/isolation/FINDINGS.md).
	// +required
	// +kubebuilder:validation:MinLength=1
	Image string `json:"image"`

	// appVersion is the expected deployment (WorkerApp spec.appVersion).
	// +required
	// +kubebuilder:validation:MinLength=1
	AppVersion string `json:"appVersion"`

	// hostnames routed to the fleet through the shared gateway.
	// +optional
	// +listType=set
	Hostnames []string `json:"hostnames,omitempty"`

	// durability is the WorkerApp durability; fleet needs nodes >= 3.
	// +optional
	// +kubebuilder:default=bucket
	Durability Durability `json:"durability,omitempty"`

	// ingressFrom may reach the public listener (:8080). Unset admits the
	// operator's gateway namespace (--gateway-namespace) and the tenant's
	// own namespace.
	// +optional
	// +listType=atomic
	IngressFrom []networkingv1.NetworkPolicyPeer `json:"ingressFrom,omitempty"`

	// egressTo lets Worker code reach these peers (outbound fetch). Unset
	// means none: nodes reach only peers, the storage proxy, and DNS.
	// +optional
	// +listType=atomic
	EgressTo []networkingv1.NetworkPolicyEgressRule `json:"egressTo,omitempty"`
}

// ServiceAccountRef names a ServiceAccount.
type ServiceAccountRef struct {
	// +required
	// +kubebuilder:validation:MinLength=1
	Namespace string `json:"namespace"`
	// +required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// TenantAdmin governs access to the runtime's admin listener (:8081),
// which upstream leaves unauthenticated. The listener stays ClusterIP-only.
type TenantAdmin struct {
	// mode selects the enforcement point.
	// +optional
	// +kubebuilder:default=Gateway
	Mode TenantAdminMode `json:"mode,omitempty"`

	// allowedServiceAccounts may use the admin API.
	// +optional
	// +listType=atomic
	AllowedServiceAccounts []ServiceAccountRef `json:"allowedServiceAccounts,omitempty"`

	// allowedUsers are additional Kubernetes usernames (as TokenReview
	// reports them, e.g. OIDC users) allowed through the gateway. Gateway
	// mode only.
	// +optional
	// +listType=set
	AllowedUsers []string `json:"allowedUsers,omitempty"`
}

// TenantSpec defines the desired state of Tenant.
// +kubebuilder:validation:XValidation:rule="self.app.durability != 'fleet' || self.nodes >= 3",message="fleet durability requires at least three nodes"
// +kubebuilder:validation:XValidation:rule="!has(self.admin) || self.admin.mode != 'Istio' || !has(self.admin.allowedUsers) || size(self.admin.allowedUsers) == 0",message="allowedUsers requires Gateway mode"
type TenantSpec struct {
	// engine is the runtime inside each microVM.
	// +optional
	// +kubebuilder:default=celld
	Engine TenantEngine `json:"engine,omitempty"`

	// runtimeClassName is the microVM RuntimeClass, e.g. "krun" or "kata".
	// +optional
	// +kubebuilder:default=krun
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	RuntimeClassName string `json:"runtimeClassName,omitempty"`

	// nodes is the fleet size: one microVM per node.
	// +optional
	// +kubebuilder:default=3
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=64
	Nodes int32 `json:"nodes,omitempty"`

	// +optional
	Resources TenantResources `json:"resources,omitzero"`

	// volume is the per-node SQLite PVC.
	// +optional
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="volume is immutable; migrate to a new Tenant"
	Volume TenantVolume `json:"volume,omitzero"`

	// +required
	Bucket TenantBucket `json:"bucket"`

	// +required
	Credentials TenantCredentials `json:"credentials"`

	// +optional
	StorageProxy TenantStorageProxy `json:"storageProxy,omitzero"`

	// +required
	App TenantApp `json:"app"`

	// +optional
	Admin TenantAdmin `json:"admin,omitzero"`
}

// TenantStatus defines the observed state of Tenant.
type TenantStatus struct {
	// namespace holds the tenant's objects.
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// observedGeneration is the generation the conditions describe.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// conditions: Ready, WorkloadReady, StorageProxyReady,
	// PeerEncryption, AdminAccessReady.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:validation:XValidation:rule="size(self.metadata.name) <= 40",message="Tenant name must not exceed 40 characters"
// +kubebuilder:printcolumn:name="Namespace",type=string,JSONPath=`.status.namespace`
// +kubebuilder:printcolumn:name="Runtime",type=string,JSONPath=`.spec.runtimeClassName`
// +kubebuilder:printcolumn:name="Nodes",type=integer,JSONPath=`.spec.nodes`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=='Ready')].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// Tenant is the Schema for the tenants API.
type Tenant struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of Tenant
	// +required
	Spec TenantSpec `json:"spec"`

	// status defines the observed state of Tenant
	// +optional
	Status TenantStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// TenantList contains a list of Tenant
type TenantList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []Tenant `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &Tenant{}, &TenantList{})
		return nil
	})
}
