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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	platformv1alpha1 "github.com/ezgamehost/celld-operator/api/v1alpha1"
)

const credentialsNamespace = "celld-operator-system"

func testOptions() Options {
	return Options{
		ProxyImage:           "example.com/isolation-proxy:test",
		OperatorNamespace:    "celld-operator-system",
		GatewayNamespace:     "infra",
		CredentialsNamespace: credentialsNamespace,
		DefaultStorageClass:  "block-ssd",
		PeerEncryption:       PeerEncryptionCiliumWireGuard,
		PodOverheadCPU:       resource.MustParse("250m"),
		PodOverheadMemory:    resource.MustParse("256Mi"),
	}
}

func newTenant(name string) *platformv1alpha1.Tenant {
	return &platformv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: platformv1alpha1.TenantSpec{
			Nodes:     3,
			Resources: platformv1alpha1.TenantResources{CPUMillis: 2000, MemoryGi: 4, EphemeralStorageGi: 2},
			Volume:    platformv1alpha1.TenantVolume{SizeGi: 20},
			Bucket:    platformv1alpha1.TenantBucket{Name: "s3://platform-cells/tenants/" + name, Region: "us-east-1"},
			Credentials: platformv1alpha1.TenantCredentials{WebIdentity: &platformv1alpha1.WebIdentityCredentials{
				RoleARN: "arn:aws:iam::123456789012:role/celld-" + name,
			}},
			App: platformv1alpha1.TenantApp{Image: "ghcr.io/denoland/celld:v0.6.2", AppVersion: "deploy-a", Durability: platformv1alpha1.DurabilityFleet},
			Admin: platformv1alpha1.TenantAdmin{AllowedServiceAccounts: []platformv1alpha1.ServiceAccountRef{
				{Namespace: "platform-ops", Name: "celld-admin"},
			}},
		},
	}
}

func reconcileTenant(r *Reconciler, name string) {
	_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: name}})
	Expect(err).NotTo(HaveOccurred())
}

func get[T client.Object](namespace, name string, obj T) T {
	Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, obj)).To(Succeed())
	return obj
}

func condition(t *platformv1alpha1.Tenant, kind string) *metav1.Condition {
	return meta.FindStatusCondition(t.Status.Conditions, kind)
}

var _ = Describe("Tenant controller", func() {
	var r *Reconciler

	BeforeEach(func() {
		r = &Reconciler{Client: k8sClient, APIReader: k8sClient, Options: testOptions()}
	})

	It("isolates a tenant: namespace, quota, network, proxy, gateway and a microVM WorkerApp", func() {
		t := newTenant("acme")
		Expect(k8sClient.Create(ctx, t)).To(Succeed())
		// The API server's own EndpointSlice is how the gateway reaches
		// TokenReview; envtest has none, so provide one.
		Expect(client.IgnoreAlreadyExists(k8sClient.Create(ctx, &discoveryv1.EndpointSlice{
			ObjectMeta:  metav1.ObjectMeta{Name: kubernetesService, Namespace: "default", Labels: map[string]string{discoveryv1.LabelServiceName: kubernetesService}},
			AddressType: discoveryv1.AddressTypeIPv4,
			Endpoints:   []discoveryv1.Endpoint{{Addresses: []string{"172.18.0.2"}}},
			Ports:       []discoveryv1.EndpointPort{{Name: ptr.To("https"), Port: ptr.To(int32(6443))}},
		}))).To(Succeed())
		reconcileTenant(r, "acme")
		ns := "tenant-acme"

		By("owning a restricted namespace")
		namespace := get("", ns, &corev1.Namespace{})
		Expect(namespace.Labels).To(HaveKeyWithValue(TenantLabel, "acme"))
		Expect(namespace.Labels).To(HaveKeyWithValue("pod-security.kubernetes.io/enforce", "restricted"))
		Expect(metav1.IsControlledBy(namespace, get("", "acme", &platformv1alpha1.Tenant{}))).To(BeTrue())

		By("rendering the fleet as a WorkerApp under the microVM RuntimeClass")
		app := get(ns, "acme", &platformv1alpha1.WorkerApp{})
		Expect(app.Spec.RuntimeClassName).To(Equal(ptr.To("krun")))
		Expect(*app.Spec.Replicas).To(Equal(int32(3)))
		Expect(app.Spec.Resources.CPUMillis).To(Equal(int32(2000)))
		Expect(app.Spec.Resources.MemoryGi).To(Equal(int32(4)))
		Expect(app.Spec.Storage.SizeGi).To(Equal(int32(20)))
		Expect(app.Spec.Storage.StorageClassName).To(Equal(ptr.To("block-ssd")))
		Expect(app.Spec.Durability).To(Equal(platformv1alpha1.DurabilityFleet))
		Expect(app.Spec.Bucket.Name).To(Equal("s3://platform-cells/tenants/acme"))
		Expect(app.Spec.Bucket.Endpoint).To(Equal("http://storage-proxy.tenant-acme.svc.cluster.local:9000"))
		Expect(app.Spec.Bucket.CredentialsFrom.SecretRef).To(Equal(placeholderSecret))
		Expect(app.Spec.Bucket.CredentialsFrom.IAMRole).To(BeEmpty(), "the fleet must not get a cloud identity")
		Expect(app.Spec.PublicIngressFrom).To(HaveLen(2), "own namespace plus the gateway namespace")

		By("giving the fleet only a placeholder key")
		placeholder := get(ns, placeholderSecret, &corev1.Secret{})
		Expect(string(placeholder.Data[accessKeyIDKey])).To(Equal("celld-tenant-acme"))
		Expect(placeholder.Data).NotTo(HaveKey(sessionTokenKey))

		By("enforcing hard per-node limits and a namespace quota")
		limits := get(ns, limitRangeName, &corev1.LimitRange{})
		container := limits.Spec.Limits[0]
		Expect(container.Default.Cpu().MilliValue()).To(Equal(int64(2000)), "default CPU limit makes the CPU budget hard")
		Expect(container.Max.Memory().String()).To(Equal("4Gi"))
		Expect(limits.Spec.Limits[1].Max.Storage().String()).To(Equal("20Gi"))
		quota := get(ns, quotaName, &corev1.ResourceQuota{})
		requestsStorage := quota.Spec.Hard[corev1.ResourceRequestsStorage]
		Expect(requestsStorage.String()).To(Equal("60Gi"))
		pvcs, loadBalancers := quota.Spec.Hard[corev1.ResourcePersistentVolumeClaims], quota.Spec.Hard[corev1.ResourceServicesLoadBalancers]
		Expect(pvcs.Value()).To(Equal(int64(3)))
		Expect(loadBalancers.IsZero()).To(BeTrue())
		// 3 nodes x 2000m + 5 helper pods x 100m + 8 pods x 250m overhead.
		requestsCPU := quota.Spec.Hard[corev1.ResourceRequestsCPU]
		Expect(requestsCPU.MilliValue()).To(Equal(int64(8500)))

		By("denying all traffic by default and allowing only the tenant's own paths")
		deny := get(ns, defaultDenyPolicy, &networkingv1.NetworkPolicy{})
		Expect(deny.Spec.PodSelector.MatchLabels).To(BeEmpty())
		Expect(deny.Spec.PolicyTypes).To(ConsistOf(networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress))
		Expect(deny.Spec.Ingress).To(BeEmpty())
		Expect(deny.Spec.Egress).To(BeEmpty())
		fleet := get(ns, fleetPolicy, &networkingv1.NetworkPolicy{})
		Expect(fleet.Spec.Egress).To(HaveLen(3), "peers, storage proxy, DNS: nothing else")
		for _, rule := range fleet.Spec.Egress {
			for _, peer := range rule.To {
				Expect(peer.IPBlock).To(BeNil(), "the fleet has no IP-range egress (no store, no metadata service)")
			}
		}
		proxyPolicy := get(ns, storageProxyName, &networkingv1.NetworkPolicy{})
		Expect(proxyPolicy.Spec.Ingress).To(HaveLen(1))
		Expect(proxyPolicy.Spec.Ingress[0].From[0].PodSelector.MatchLabels).To(Equal(map[string]string{"celld-operator.io/workerapp": "acme"}))
		Expect(proxyPolicy.Spec.Egress[1].To[0].IPBlock.Except).To(ContainElement("169.254.0.0/16"))
		gatewayPolicy := get(ns, adminGatewayName, &networkingv1.NetworkPolicy{})
		Expect(gatewayPolicy.Spec.Ingress[0].From[0].NamespaceSelector.MatchLabels).To(Equal(map[string]string{namespaceNameLabel: "platform-ops"}))
		apiSlices := &discoveryv1.EndpointSliceList{}
		Expect(k8sClient.List(ctx, apiSlices, client.InNamespace("default"), client.MatchingLabels{discoveryv1.LabelServiceName: kubernetesService})).To(Succeed())
		Expect(gatewayPolicy.Spec.Egress[2].To[0].IPBlock.CIDR).To(Equal(apiSlices.Items[0].Endpoints[0].Addresses[0]+"/32"), "TokenReview egress to the API server only")

		By("running the storage proxy with a projected, audience-scoped token and no API token")
		proxy := get(ns, storageProxyName, &appsv1.Deployment{})
		pod := proxy.Spec.Template.Spec
		Expect(*pod.AutomountServiceAccountToken).To(BeFalse())
		Expect(pod.Volumes[0].Projected.Sources[0].ServiceAccountToken.Audience).To(Equal("sts.amazonaws.com"))
		Expect(pod.Containers[0].Args).To(ContainElements(
			"--bucket=s3://platform-cells/tenants/acme",
			"--credential-source=webIdentity",
			"--role-arn=arn:aws:iam::123456789012:role/celld-acme",
			"--scope-session-policy=true",
		))
		Expect(*pod.Containers[0].SecurityContext.ReadOnlyRootFilesystem).To(BeTrue())

		By("authenticating admin access through the gateway")
		gateway := get(ns, adminGatewayName, &appsv1.Deployment{})
		Expect(gateway.Spec.Template.Spec.Containers[0].Args).To(ContainElements(
			"--audience=celld-admin.tenant-acme",
			"--allowed=system:serviceaccount:platform-ops:celld-admin",
			"--fleet=acme-celld",
			"--headless-service=acme-celld-internal.tenant-acme.svc.cluster.local",
		))
		binding := get("", "celld-tenant-acme-admin-gateway", &rbacv1.ClusterRoleBinding{})
		Expect(binding.RoleRef.Name).To(Equal("system:auth-delegator"))
		service := get(ns, adminGatewayName, &corev1.Service{})
		Expect(service.Spec.Type).To(Equal(corev1.ServiceTypeClusterIP))

		By("reporting status")
		t = get("", "acme", &platformv1alpha1.Tenant{})
		Expect(t.Status.Namespace).To(Equal(ns))
		Expect(condition(t, CondPeerEncryption).Status).To(Equal(metav1.ConditionTrue))
		Expect(condition(t, CondStorageProxyReady).Status).To(Equal(metav1.ConditionFalse), "envtest runs no Deployment controller")
		Expect(condition(t, CondReady).Status).To(Equal(metav1.ConditionFalse))

		By("swapping the runtime class (krun -> kata) without touching anything else")
		t.Spec.RuntimeClassName = "kata"
		Expect(k8sClient.Update(ctx, t)).To(Succeed())
		reconcileTenant(r, "acme")
		Expect(get(ns, "acme", &platformv1alpha1.WorkerApp{}).Spec.RuntimeClassName).To(Equal(ptr.To("kata")))

		By("reconciling idempotently")
		before := get(ns, storageProxyName, &appsv1.Deployment{}).ResourceVersion
		reconcileTenant(r, "acme")
		Expect(get(ns, storageProxyName, &appsv1.Deployment{}).ResourceVersion).To(Equal(before))
	})

	It("admits the helper pods in a tenant smaller than they are", func() {
		t := newTenant("tiny")
		t.Spec.Resources.CPUMillis = 100
		limits := buildLimitRange(t).Spec.Limits[0]
		Expect(limits.Default.Cpu().MilliValue()).To(Equal(int64(100)), "the fleet's hard limit stays the tenant size")
		Expect(limits.Max.Cpu().Cmp(proxyLimits[corev1.ResourceCPU])).To(BeNumerically(">=", 0), "proxy limits must fit under Max")
		Expect(limits.Max.Memory().Cmp(proxyLimits[corev1.ResourceMemory])).To(BeNumerically(">=", 0))
	})

	It("copies a static credential only into the proxy, and waits for it", func() {
		t := newTenant("static")
		t.Spec.Credentials = platformv1alpha1.TenantCredentials{Secret: &platformv1alpha1.SecretCredentials{Name: "static-store-key"}}
		Expect(k8sClient.Create(ctx, t)).To(Succeed())
		reconcileTenant(r, "static")
		t = get("", "static", &platformv1alpha1.Tenant{})
		Expect(condition(t, CondStorageProxyReady).Reason).To(Equal("CredentialsMissing"))

		Expect(client.IgnoreAlreadyExists(k8sClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: credentialsNamespace}}))).To(Succeed())
		Expect(k8sClient.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "static-store-key", Namespace: credentialsNamespace},
			Data:       map[string][]byte{accessKeyIDKey: []byte("AKIA"), secretAccessKeyKey: []byte("s3cr3t"), "unrelated": []byte("x")},
		})).To(Succeed())
		reconcileTenant(r, "static")
		copied := get("tenant-static", proxyCredentialsSecret, &corev1.Secret{})
		Expect(copied.Data).To(HaveKeyWithValue(secretAccessKeyKey, []byte("s3cr3t")))
		Expect(copied.Data).NotTo(HaveKey("unrelated"))
		proxy := get("tenant-static", storageProxyName, &appsv1.Deployment{})
		Expect(proxy.Spec.Template.Spec.Volumes[0].Secret.SecretName).To(Equal(proxyCredentialsSecret))

		By("never mounting the real credential into the fleet")
		app := get("tenant-static", "static", &platformv1alpha1.WorkerApp{})
		Expect(app.Spec.Bucket.CredentialsFrom.SecretRef).To(Equal(placeholderSecret))
	})

	It("uses an Istio AuthorizationPolicy in Istio admin mode and reports a missing mesh", func() {
		t := newTenant("meshy")
		t.Spec.Admin.Mode = platformv1alpha1.TenantAdminIstio
		Expect(k8sClient.Create(ctx, t)).To(Succeed())
		reconcileTenant(r, "meshy")
		t = get("", "meshy", &platformv1alpha1.Tenant{})
		Expect(condition(t, CondAdminAccessReady).Reason).To(Equal("IstioUnavailable"))
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: "tenant-meshy", Name: adminGatewayName}, &appsv1.Deployment{})).NotTo(Succeed())
		fleet := get("tenant-meshy", fleetPolicy, &networkingv1.NetworkPolicy{})
		Expect(fleet.Spec.Ingress[1].From[0].NamespaceSelector.MatchLabels).To(HaveKeyWithValue(namespaceNameLabel, "platform-ops"))
	})

	It("refuses to adopt a namespace another owner created", func() {
		Expect(k8sClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant-squatted"}})).To(Succeed())
		Expect(k8sClient.Create(ctx, newTenant("squatted"))).To(Succeed())
		_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "squatted"}})
		Expect(err).To(MatchError(ContainSubstring("not controlled by Tenant squatted")))
		t := get("", "squatted", &platformv1alpha1.Tenant{})
		Expect(condition(t, CondReady).Reason).To(Equal("ReconcileError"))
	})

	It("keeps two tenants' policies disjoint", func() {
		for _, name := range []string{"red", "blue"} {
			Expect(k8sClient.Create(ctx, newTenant(name))).To(Succeed())
			reconcileTenant(r, name)
		}
		for _, name := range []string{"red", "blue"} {
			list := &networkingv1.NetworkPolicyList{}
			Expect(k8sClient.List(ctx, list, client.InNamespace("tenant-"+name))).To(Succeed())
			Expect(list.Items).To(HaveLen(4))
			for _, policy := range list.Items {
				for _, rule := range policy.Spec.Ingress {
					for _, peer := range rule.From {
						if peer.NamespaceSelector != nil {
							Expect(peer.NamespaceSelector.MatchLabels[namespaceNameLabel]).NotTo(HavePrefix("tenant-"), "no tenant namespace admits another")
						}
					}
				}
			}
		}
		red := get("tenant-red", "red", &platformv1alpha1.WorkerApp{})
		Expect(red.Spec.Bucket.Name).NotTo(Equal(get("tenant-blue", "blue", &platformv1alpha1.WorkerApp{}).Spec.Bucket.Name))
	})

	DescribeTable("CRD validation",
		func(name string, mutate func(*platformv1alpha1.Tenant), message string) {
			t := newTenant("invalid-" + name)
			mutate(t)
			err := k8sClient.Create(ctx, t)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring(message))
		},
		Entry("both credential sources", "both", func(t *platformv1alpha1.Tenant) {
			t.Spec.Credentials.Secret = &platformv1alpha1.SecretCredentials{Name: "x"}
		}, "select exactly one credential source"),
		Entry("no credential source", "none", func(t *platformv1alpha1.Tenant) {
			t.Spec.Credentials = platformv1alpha1.TenantCredentials{}
		}, "select exactly one credential source"),
		Entry("a bucket without a prefix", "noprefix", func(t *platformv1alpha1.Tenant) {
			t.Spec.Bucket.Name = "s3://platform-cells"
		}, "spec.bucket.name"),
		Entry("fleet durability on one node", "fleet", func(t *platformv1alpha1.Tenant) {
			t.Spec.Nodes = 1
		}, "fleet durability requires at least three nodes"),
		Entry("users in Istio mode", "users", func(t *platformv1alpha1.Tenant) {
			t.Spec.Admin.Mode = platformv1alpha1.TenantAdminIstio
			t.Spec.Admin.AllowedUsers = []string{"alice"}
		}, "allowedUsers requires Gateway mode"),
	)
})
