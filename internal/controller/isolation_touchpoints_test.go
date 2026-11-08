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

package controller

// Tests for the WorkerApp fields the Tenant isolation layer needs
// (docs/isolation/PLAN.md, touch points T1-T3). The unset path must be
// byte-identical to the pre-isolation output so upgrading the operator
// never rolls an existing fleet.

import (
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	platformv1alpha1 "github.com/ezgamehost/celld-operator/api/v1alpha1"
)

func isolationApp() *platformv1alpha1.WorkerApp {
	return &platformv1alpha1.WorkerApp{
		ObjectMeta: metav1.ObjectMeta{Name: "acme", Namespace: "tenant-acme"},
		Spec: platformv1alpha1.WorkerAppSpec{
			AppVersion: "deploy-a",
			Celld:      platformv1alpha1.CelldSpec{Image: testCelldImage},
			Bucket:     platformv1alpha1.BucketSpec{Name: "s3://cells/tenants/acme"},
		},
	}
}

// pinnedTemplateHash is the hash of isolationApp()'s pod template before
// the isolation fields existed. If it changes, every existing fleet rolls
// on operator upgrade.
const pinnedTemplateHash = "80a674ca84cfa290"

func TestUnsetIsolationFieldsKeepTemplateAndPolicy(t *testing.T) {
	app := isolationApp()
	template := buildPodTemplate(app, "", app.Spec.AppVersion)
	if template.Spec.RuntimeClassName != nil {
		t.Fatalf("runtimeClassName = %v, want nil", *template.Spec.RuntimeClassName)
	}
	if got := templateHash(template); got != pinnedTemplateHash {
		t.Fatalf("template hash = %s, want %s: unset isolation fields changed the pod template", got, pinnedTemplateHash)
	}
	policy := buildNetworkPolicy(app, "celld-operator-system")
	if from := policy.Spec.Ingress[1].From; from != nil {
		t.Fatalf("public ingress From = %v, want nil (open)", from)
	}
}

func TestRuntimeClassAndPublicIngressRender(t *testing.T) {
	app := isolationApp()
	app.Spec.RuntimeClassName = ptr.To("krun")
	peers := []networkingv1.NetworkPolicyPeer{{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "edge-gateways"}}}}
	app.Spec.PublicIngressFrom = peers

	template := buildPodTemplate(app, "", app.Spec.AppVersion)
	if template.Spec.RuntimeClassName == nil || *template.Spec.RuntimeClassName != "krun" {
		t.Fatalf("runtimeClassName not rendered: %v", template.Spec.RuntimeClassName)
	}
	if templateHash(template) == pinnedTemplateHash {
		t.Fatal("changing runtimeClassName must change the template hash so the fleet rolls onto the new runtime")
	}
	policy := buildNetworkPolicy(app, "celld-operator-system")
	public := policy.Spec.Ingress[1]
	if public.Ports[0].Port.IntValue() != publicPort || len(public.From) != 1 || public.From[0].NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"] != "edge-gateways" {
		t.Fatalf("public ingress rule = %+v", public)
	}
	internal := policy.Spec.Ingress[0]
	if internal.Ports[0].Port.IntValue() != internalPort || len(internal.From) != 2 {
		t.Fatalf("internal ingress rule changed: %+v", internal)
	}
}

func TestNamespaceLocalBucketEndpoint(t *testing.T) {
	cases := []struct {
		endpoint string
		want     bool
	}{
		{"http://storage-proxy.tenant-acme.svc.cluster.local:9000", true},
		{"https://storage-proxy.tenant-acme.svc.cluster.local:9443/", true},
		{"http://storage-proxy.tenant-other.svc.cluster.local:9000", false}, // another namespace
		{"http://storage-proxy.tenant-acme.svc.cluster.local", false},       // no port
		{"http://storage-proxy.tenant-acme.svc:9000", false},                // short name
		{"http://a.b.tenant-acme.svc.cluster.local:9000", false},            // not a Service name
		{"http://u:p@storage-proxy.tenant-acme.svc.cluster.local:9000", false},
		{"http://storage-proxy.tenant-acme.svc.cluster.local:9000/x", false},
		{"http://storage-proxy.tenant-acme.svc.cluster.local:9000?a=b", false},
		{"ftp://storage-proxy.tenant-acme.svc.cluster.local:9000", false},
	}
	app := isolationApp()
	for _, c := range cases {
		if got := namespaceLocalEndpoint(app, c.endpoint); got != c.want {
			t.Errorf("namespaceLocalEndpoint(%q) = %v, want %v", c.endpoint, got, c.want)
		}
	}
}

func TestNamespaceLocalEndpointRequiresOptIn(t *testing.T) {
	app := isolationApp()
	app.Spec.Bucket.Endpoint = "http://storage-proxy.tenant-acme.svc.cluster.local:9000"
	r := &WorkerAppReconciler{AllowedImagePrefixes: []string{"ghcr.io/denoland/celld:"}}
	if err := r.validateTrust(app); err == nil {
		t.Fatal("namespace-local endpoint accepted without --allow-namespace-local-bucket-endpoints")
	}
	r.LocalBucketEndpoints = true
	if err := r.validateTrust(app); err != nil {
		t.Fatalf("namespace-local endpoint rejected with the opt-in: %v", err)
	}
	app.Spec.Bucket.Endpoint = "http://evil.example.com:9000"
	if err := r.validateTrust(app); err == nil {
		t.Fatal("opt-in must not admit arbitrary plaintext endpoints")
	}
}
