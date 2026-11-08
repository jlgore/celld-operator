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

// Package tenant reconciles the Tenant isolation layer: one namespace per
// tenant holding a WorkerApp fleet that runs in microVMs, behind a
// default-deny network, a prefix-scoped signing storage proxy, and an
// authenticated admin gateway. See docs/isolation/DESIGN.md.
package tenant

import (
	"context"
	"fmt"
	"net"
	"slices"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	platformv1alpha1 "github.com/ezgamehost/celld-operator/api/v1alpha1"
)

// Condition types reported on Tenant status.
const (
	CondReady             = "Ready"
	CondWorkloadReady     = "WorkloadReady"
	CondStorageProxyReady = "StorageProxyReady"
	CondPeerEncryption    = "PeerEncryption"
	CondAdminAccessReady  = "AdminAccessReady"
)

// Reconciler reconciles cluster-scoped Tenants.
type Reconciler struct {
	client.Client
	Options Options
	// APIReader reads uncached: EndpointSlices of the kubernetes Service
	// only, without a cluster-wide informer.
	APIReader client.Reader
	// Workloads maps an engine to its backend; celld is built in.
	Workloads map[platformv1alpha1.TenantEngine]Workload
}

// +kubebuilder:rbac:groups=celld-operator.io,resources=tenants,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=celld-operator.io,resources=tenants/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=celld-operator.io,resources=tenants/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=namespaces;resourcequotas;limitranges,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=services;serviceaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;create;update;patch;delete
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterrolebindings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles,verbs=bind,resourceNames="system:auth-delegator"
// +kubebuilder:rbac:groups=discovery.k8s.io,resources=endpointslices,verbs=list
// +kubebuilder:rbac:groups=security.istio.io,resources=peerauthentications;authorizationpolicies,verbs=get;list;watch;create;update;patch;delete

// Reconcile drives one Tenant toward its spec.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	t := &platformv1alpha1.Tenant{}
	if err := r.Get(ctx, req.NamespacedName, t); err != nil {
		// Deleted: the namespace and everything in it are owned and
		// garbage-collected. Bucket data is deliberately retained.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !t.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}
	workload, ok := r.workload(t)
	if !ok {
		return ctrl.Result{}, r.setStatus(ctx, t, []metav1.Condition{{Type: CondReady, Status: metav1.ConditionFalse, Reason: "UnsupportedEngine", Message: fmt.Sprintf("engine %q is not implemented", t.Spec.Engine)}})
	}
	options := r.Options
	peers, ports, err := r.apiServerPeers(ctx)
	if err != nil {
		log.Error(err, "Could not resolve API server endpoints; admin gateway egress stays closed")
	}
	options.APIServerPeers, options.APIServerPorts = peers, ports

	conditions, err := r.reconcileChildren(ctx, t, options, workload)
	if err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		_ = r.setStatus(ctx, t, []metav1.Condition{{Type: CondReady, Status: metav1.ConditionFalse, Reason: "ReconcileError", Message: err.Error()}})
		return ctrl.Result{}, err
	}
	ready := metav1.Condition{Type: CondReady, Status: metav1.ConditionTrue, Reason: "Ready", Message: "workload, storage proxy and admin access are ready"}
	for _, c := range conditions {
		// PeerEncryption is reported, not gating: it reflects a cluster
		// property the operator can only declare (see DESIGN.md).
		if c.Type != CondPeerEncryption && c.Status != metav1.ConditionTrue {
			ready = metav1.Condition{Type: CondReady, Status: metav1.ConditionFalse, Reason: "Waiting", Message: c.Type + ": " + c.Message}
			break
		}
	}
	conditions = append(conditions, ready)
	if err := r.setStatus(ctx, t, conditions); err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, err
	}
	if ready.Status != metav1.ConditionTrue {
		return ctrl.Result{RequeueAfter: 15 * time.Second}, nil
	}
	return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
}

func (r *Reconciler) workload(t *platformv1alpha1.Tenant) (Workload, bool) {
	engine := t.Spec.Engine
	if engine == "" {
		engine = platformv1alpha1.TenantEngineCelld
	}
	if r.Workloads != nil {
		w, ok := r.Workloads[engine]
		return w, ok
	}
	return celldWorkload{}, engine == platformv1alpha1.TenantEngineCelld
}

func (r *Reconciler) reconcileChildren(ctx context.Context, t *platformv1alpha1.Tenant, o Options, w Workload) ([]metav1.Condition, error) {
	ns := NamespaceName(t)
	conditions := make([]metav1.Condition, 0, 5)

	namespace := buildNamespace(t, o)
	if err := r.apply(ctx, t, namespace, func(live client.Object) {
		live.SetLabels(mergeLabels(live.GetLabels(), namespace.Labels))
	}); err != nil {
		return nil, fmt.Errorf("namespace: %w", err)
	}

	// Quota and limits first: they must exist before any pod is admitted.
	quota := buildResourceQuota(t, o)
	if err := r.apply(ctx, t, quota, func(live client.Object) { live.(*corev1.ResourceQuota).Spec = quota.Spec }); err != nil {
		return nil, fmt.Errorf("resource quota: %w", err)
	}
	limits := buildLimitRange(t)
	if err := r.apply(ctx, t, limits, func(live client.Object) { live.(*corev1.LimitRange).Spec = limits.Spec }); err != nil {
		return nil, fmt.Errorf("limit range: %w", err)
	}

	// Network next: deny-by-default is in place before workloads start.
	for _, policy := range buildNetworkPolicies(t, o, w) {
		if err := r.apply(ctx, t, policy, func(live client.Object) { live.(*networkingv1.NetworkPolicy).Spec = policy.Spec }); err != nil {
			return nil, fmt.Errorf("network policy %s: %w", policy.Name, err)
		}
	}
	conditions = append(conditions, r.reconcilePeerEncryption(ctx, t, o))

	proxyCondition, err := r.reconcileStorageProxy(ctx, t, o)
	if err != nil {
		return nil, err
	}
	conditions = append(conditions, proxyCondition)

	adminCondition, err := r.reconcileAdmin(ctx, t, o, w)
	if err != nil {
		return nil, err
	}
	conditions = append(conditions, adminCondition)

	placeholder := buildPlaceholderSecret(t)
	if err := r.apply(ctx, t, placeholder, func(live client.Object) {
		s := live.(*corev1.Secret)
		s.Data = placeholder.Data
		s.Annotations = placeholder.Annotations
	}); err != nil {
		return nil, fmt.Errorf("placeholder secret: %w", err)
	}

	storageClass := t.Spec.Volume.StorageClassName
	if storageClass == nil && o.DefaultStorageClass != "" {
		storageClass = &o.DefaultStorageClass
	}
	workloadCondition, err := w.Reconcile(ctx, r.Client, t, WorkloadEnv{
		Namespace:         ns,
		StorageEndpoint:   StorageEndpoint(t, o),
		PlaceholderSecret: placeholderSecret,
		StorageClassName:  storageClass,
		PublicIngressFrom: publicIngressFrom(t, o),
	})
	if err != nil {
		return nil, err
	}
	return append(conditions, workloadCondition), nil
}

func (r *Reconciler) reconcileStorageProxy(ctx context.Context, t *platformv1alpha1.Tenant, o Options) (metav1.Condition, error) {
	if t.Spec.Credentials.Secret != nil {
		ready, err := r.copyCredentials(ctx, t, o)
		if err != nil {
			return metav1.Condition{}, err
		}
		if !ready {
			return metav1.Condition{Type: CondStorageProxyReady, Status: metav1.ConditionFalse, Reason: "CredentialsMissing",
				Message: fmt.Sprintf("Secret %s/%s with AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY not found", o.CredentialsNamespace, t.Spec.Credentials.Secret.Name)}, nil
		}
	}
	sa := buildServiceAccount(t, storageProxyName, componentStorageProxy, false)
	if err := r.apply(ctx, t, sa, func(live client.Object) {
		live.(*corev1.ServiceAccount).AutomountServiceAccountToken = sa.AutomountServiceAccountToken
	}); err != nil {
		return metav1.Condition{}, fmt.Errorf("proxy service account: %w", err)
	}
	service := buildService(t, storageProxyName, componentStorageProxy, storageProxyPort)
	if err := r.apply(ctx, t, service, func(live client.Object) {
		l := live.(*corev1.Service)
		l.Spec.Selector, l.Spec.Ports = service.Spec.Selector, service.Spec.Ports
	}); err != nil {
		return metav1.Condition{}, fmt.Errorf("proxy service: %w", err)
	}
	deployment := buildStorageProxyDeployment(t, o)
	if err := r.apply(ctx, t, deployment, func(live client.Object) { copyDeploymentSpec(live.(*appsv1.Deployment), deployment) }); err != nil {
		return metav1.Condition{}, fmt.Errorf("proxy deployment: %w", err)
	}
	return deploymentCondition(CondStorageProxyReady, deployment, r.liveDeployment(ctx, deployment)), nil
}

// copyCredentials mirrors the named static credential into the tenant
// namespace, where only the proxy mounts it.
func (r *Reconciler) copyCredentials(ctx context.Context, t *platformv1alpha1.Tenant, o Options) (bool, error) {
	source := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Namespace: o.CredentialsNamespace, Name: t.Spec.Credentials.Secret.Name}, source)
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	data := map[string][]byte{}
	for _, key := range []string{accessKeyIDKey, secretAccessKeyKey, sessionTokenKey} {
		if value, ok := source.Data[key]; ok {
			data[key] = value
		}
	}
	if len(data[accessKeyIDKey]) == 0 || len(data[secretAccessKeyKey]) == 0 {
		return false, nil
	}
	copied := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: proxyCredentialsSecret, Namespace: NamespaceName(t), Labels: componentLabels(t, componentStorageProxy)}, Type: corev1.SecretTypeOpaque, Data: data}
	return true, r.apply(ctx, t, copied, func(live client.Object) { live.(*corev1.Secret).Data = data })
}

func (r *Reconciler) reconcileAdmin(ctx context.Context, t *platformv1alpha1.Tenant, o Options, w Workload) (metav1.Condition, error) {
	if adminMode(t) == platformv1alpha1.TenantAdminIstio {
		if err := r.applyUnstructured(ctx, t, buildAdminAuthorizationPolicy(t, o, w)); err != nil {
			if meta.IsNoMatchError(err) {
				return metav1.Condition{Type: CondAdminAccessReady, Status: metav1.ConditionFalse, Reason: "IstioUnavailable", Message: "admin.mode Istio requires security.istio.io CRDs; use Gateway mode"}, nil
			}
			return metav1.Condition{}, fmt.Errorf("admin authorization policy: %w", err)
		}
		return metav1.Condition{Type: CondAdminAccessReady, Status: metav1.ConditionTrue, Reason: "AuthorizationPolicy", Message: "admin port restricted to the allowed mesh principals"}, nil
	}
	sa := buildServiceAccount(t, adminGatewayName, componentAdminGateway, true)
	if err := r.apply(ctx, t, sa, func(live client.Object) {
		live.(*corev1.ServiceAccount).AutomountServiceAccountToken = sa.AutomountServiceAccountToken
	}); err != nil {
		return metav1.Condition{}, fmt.Errorf("gateway service account: %w", err)
	}
	binding := buildAdminGatewayBinding(t)
	if err := r.apply(ctx, t, binding, func(live client.Object) {
		l := live.(*rbacv1.ClusterRoleBinding)
		l.Subjects = binding.Subjects // RoleRef is immutable and never changes.
	}); err != nil {
		return metav1.Condition{}, fmt.Errorf("gateway binding: %w", err)
	}
	service := buildService(t, adminGatewayName, componentAdminGateway, adminGatewayPort)
	if err := r.apply(ctx, t, service, func(live client.Object) {
		l := live.(*corev1.Service)
		l.Spec.Selector, l.Spec.Ports = service.Spec.Selector, service.Spec.Ports
	}); err != nil {
		return metav1.Condition{}, fmt.Errorf("gateway service: %w", err)
	}
	deployment := buildAdminGatewayDeployment(t, o, w)
	if err := r.apply(ctx, t, deployment, func(live client.Object) { copyDeploymentSpec(live.(*appsv1.Deployment), deployment) }); err != nil {
		return metav1.Condition{}, fmt.Errorf("gateway deployment: %w", err)
	}
	return deploymentCondition(CondAdminAccessReady, deployment, r.liveDeployment(ctx, deployment)), nil
}

func (r *Reconciler) reconcilePeerEncryption(ctx context.Context, t *platformv1alpha1.Tenant, o Options) metav1.Condition {
	switch o.PeerEncryption {
	case PeerEncryptionIstioAmbient:
		if err := r.applyUnstructured(ctx, t, buildPeerAuthentication(t)); err != nil {
			return metav1.Condition{Type: CondPeerEncryption, Status: metav1.ConditionFalse, Reason: "PeerAuthenticationError", Message: err.Error()}
		}
		return metav1.Condition{Type: CondPeerEncryption, Status: metav1.ConditionTrue, Reason: "IstioAmbientMTLS", Message: "namespace enrolled in ambient mesh with STRICT mTLS"}
	case PeerEncryptionCiliumWireGuard:
		return metav1.Condition{Type: CondPeerEncryption, Status: metav1.ConditionTrue, Reason: "CiliumWireGuard", Message: "declared by the operator: the CNI encrypts pod-to-pod traffic with WireGuard"}
	default:
		return metav1.Condition{Type: CondPeerEncryption, Status: metav1.ConditionFalse, Reason: "Unencrypted", Message: "peer, storage-proxy and admin traffic cross the pod network in plaintext; set --tenant-peer-encryption"}
	}
}

func copyDeploymentSpec(live, desired *appsv1.Deployment) {
	live.Spec.Replicas = desired.Spec.Replicas
	live.Spec.Selector = desired.Spec.Selector
	live.Spec.Strategy = desired.Spec.Strategy
	live.Spec.Template = desired.Spec.Template
}

func (r *Reconciler) liveDeployment(ctx context.Context, d *appsv1.Deployment) *appsv1.Deployment {
	live := &appsv1.Deployment{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(d), live); err != nil {
		return nil
	}
	return live
}

func deploymentCondition(kind string, desired, live *appsv1.Deployment) metav1.Condition {
	if live == nil || live.Status.AvailableReplicas < 1 {
		return metav1.Condition{Type: kind, Status: metav1.ConditionFalse, Reason: "Unavailable", Message: fmt.Sprintf("Deployment %s has no available replicas", desired.Name)}
	}
	return metav1.Condition{Type: kind, Status: metav1.ConditionTrue, Reason: "Available", Message: fmt.Sprintf("%d/%d replicas available", live.Status.AvailableReplicas, *desired.Spec.Replicas)}
}

// apply creates desired or applies mutate to the live copy, refusing to
// adopt objects another owner controls.
func (r *Reconciler) apply(ctx context.Context, t *platformv1alpha1.Tenant, desired client.Object, mutate func(live client.Object)) error {
	if err := controllerutil.SetControllerReference(t, desired, r.Scheme()); err != nil {
		return err
	}
	live := desired.DeepCopyObject().(client.Object)
	err := r.Get(ctx, client.ObjectKeyFromObject(desired), live)
	if apierrors.IsNotFound(err) {
		return r.Create(ctx, desired)
	}
	if err != nil {
		return err
	}
	if !metav1.IsControlledBy(live, t) {
		return fmt.Errorf("refusing to modify %T %s: not controlled by Tenant %s", live, client.ObjectKeyFromObject(live), t.Name)
	}
	before := live.DeepCopyObject()
	mutate(live)
	live.SetLabels(mergeLabels(live.GetLabels(), desired.GetLabels()))
	if apiequality.Semantic.DeepEqual(before, live) {
		return nil
	}
	return r.Update(ctx, live)
}

// applyUnstructured handles optional CRDs (Istio) the operator does not
// link types for; a NoMatch error means the CRD is absent.
func (r *Reconciler) applyUnstructured(ctx context.Context, t *platformv1alpha1.Tenant, object map[string]any) error {
	desired := &unstructured.Unstructured{Object: object}
	if err := controllerutil.SetControllerReference(t, desired, r.Scheme()); err != nil {
		return err
	}
	live := &unstructured.Unstructured{}
	live.SetGroupVersionKind(desired.GroupVersionKind())
	err := r.Get(ctx, client.ObjectKeyFromObject(desired), live)
	if apierrors.IsNotFound(err) {
		return r.Create(ctx, desired)
	}
	if err != nil {
		return err
	}
	if !metav1.IsControlledBy(live, t) {
		return fmt.Errorf("refusing to modify %s %s: not controlled by Tenant %s", live.GetKind(), client.ObjectKeyFromObject(live), t.Name)
	}
	if apiequality.Semantic.DeepEqual(live.Object["spec"], desired.Object["spec"]) {
		return nil
	}
	live.Object["spec"] = desired.Object["spec"]
	return r.Update(ctx, live)
}

// apiServerPeers resolves the API server endpoints for the admin gateway's
// TokenReview egress (NetworkPolicy cannot name the API server directly).
func (r *Reconciler) apiServerPeers(ctx context.Context) ([]networkingv1.NetworkPolicyPeer, []int32, error) {
	endpointSlices := &discoveryv1.EndpointSliceList{}
	reader := r.APIReader
	if reader == nil {
		reader = r.Client
	}
	if err := reader.List(ctx, endpointSlices, client.InNamespace(metav1.NamespaceDefault), client.MatchingLabels{discoveryv1.LabelServiceName: kubernetesService}); err != nil {
		return nil, nil, err
	}
	var peers []networkingv1.NetworkPolicyPeer
	var ports []int32
	for _, slice := range endpointSlices.Items {
		for _, endpoint := range slice.Endpoints {
			for _, address := range endpoint.Addresses {
				ip := net.ParseIP(address)
				if ip == nil {
					continue
				}
				bits := "/32"
				if ip.To4() == nil {
					bits = "/128"
				}
				peers = append(peers, networkingv1.NetworkPolicyPeer{IPBlock: &networkingv1.IPBlock{CIDR: address + bits}})
			}
		}
		for _, port := range slice.Ports {
			if port.Port != nil && !slices.Contains(ports, *port.Port) {
				ports = append(ports, *port.Port)
			}
		}
	}
	slices.SortFunc(peers, func(a, b networkingv1.NetworkPolicyPeer) int {
		switch {
		case a.IPBlock.CIDR < b.IPBlock.CIDR:
			return -1
		case a.IPBlock.CIDR > b.IPBlock.CIDR:
			return 1
		}
		return 0
	})
	peers = slices.CompactFunc(peers, func(a, b networkingv1.NetworkPolicyPeer) bool { return a.IPBlock.CIDR == b.IPBlock.CIDR })
	slices.Sort(ports)
	return peers, ports, nil
}

func (r *Reconciler) setStatus(ctx context.Context, t *platformv1alpha1.Tenant, conditions []metav1.Condition) error {
	before := t.Status.DeepCopy()
	t.Status.Namespace = NamespaceName(t)
	t.Status.ObservedGeneration = t.Generation
	for _, c := range conditions {
		c.ObservedGeneration = t.Generation
		meta.SetStatusCondition(&t.Status.Conditions, c)
	}
	if apiequality.Semantic.DeepEqual(before, &t.Status) {
		return nil
	}
	return r.Status().Update(ctx, t)
}

// SetupWithManager registers the controller. Tenant-owned children are
// watched through their controller reference. Secrets are deliberately not
// watched: the operator never caches Secrets (cmd/main.go), so a rotated
// static credential reaches the proxy copy on the periodic resync.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&platformv1alpha1.Tenant{}).
		Owns(&corev1.Namespace{}).
		Owns(&platformv1alpha1.WorkerApp{}).
		Owns(&appsv1.Deployment{}).
		Owns(&networkingv1.NetworkPolicy{}).
		Owns(&corev1.ResourceQuota{}).
		Owns(&corev1.LimitRange{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.ServiceAccount{}).
		Named("tenant").
		Complete(r)
}
