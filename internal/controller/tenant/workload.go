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
	"context"
	"fmt"
	"strings"

	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	platformv1alpha1 "github.com/ezgamehost/celld-operator/api/v1alpha1"
)

// Workload is the runtime-specific part of a Tenant: everything else
// (namespace, quota, network policy, storage proxy, RuntimeClass) is the
// same whether celld or workerd cluster mode runs inside the VM. A workerd
// backend implements this interface; nothing else changes
// (docs/isolation/DESIGN.md, "Runtime swappability").
type Workload interface {
	// Reconcile creates or updates the fleet and reports readiness.
	Reconcile(ctx context.Context, c client.Client, t *platformv1alpha1.Tenant, env WorkloadEnv) (metav1.Condition, error)
	// FleetSelector matches the fleet's pods.
	FleetSelector(t *platformv1alpha1.Tenant) map[string]string
	// PeerPort carries node-to-node traffic; AdminPort the admin API.
	PeerPort() int32
	AdminPort() int32
	// StatefulSetName and HeadlessService locate individual nodes.
	StatefulSetName(t *platformv1alpha1.Tenant) string
	HeadlessService(t *platformv1alpha1.Tenant) string
}

// WorkloadEnv is what the Tenant controller hands the workload backend.
type WorkloadEnv struct {
	Namespace string
	// StorageEndpoint is the tenant proxy URL the runtime uses as its S3
	// endpoint.
	StorageEndpoint string
	// PlaceholderSecret holds the non-secret key pair the runtime signs
	// with; the proxy discards that signature (FINDINGS.md, section 3).
	PlaceholderSecret string
	StorageClassName  *string
	PublicIngressFrom []networkingv1.NetworkPolicyPeer
}

// celldWorkload renders a Tenant as a WorkerApp, reusing every WorkerApp
// guardrail instead of duplicating it.
type celldWorkload struct{}

const (
	celldPeerPort  = 8081
	celldAdminPort = 8081 // celld serves peers and the admin API on one listener
)

func (celldWorkload) PeerPort() int32  { return celldPeerPort }
func (celldWorkload) AdminPort() int32 { return celldAdminPort }

func (celldWorkload) FleetSelector(t *platformv1alpha1.Tenant) map[string]string {
	// Matches the WorkerApp controller's selectorLabels.
	return map[string]string{"celld-operator.io/workerapp": t.Name}
}

func (celldWorkload) StatefulSetName(t *platformv1alpha1.Tenant) string { return t.Name + "-celld" }

func (celldWorkload) HeadlessService(t *platformv1alpha1.Tenant) string {
	return t.Name + "-celld-internal"
}

// desiredWorkerAppSpec maps the Tenant onto the fields of a WorkerApp the
// Tenant owns. Fields it does not set keep their WorkerApp defaults.
func desiredWorkerAppSpec(t *platformv1alpha1.Tenant, env WorkloadEnv, spec *platformv1alpha1.WorkerAppSpec) {
	spec.AppVersion = t.Spec.App.AppVersion
	spec.Celld.Image = t.Spec.App.Image
	if spec.Celld.UpdateStrategy == "" {
		spec.Celld.UpdateStrategy = platformv1alpha1.UpdateStrategyRolling
	}
	spec.Replicas = ptr.To(nodes(t))
	spec.Bucket = platformv1alpha1.BucketSpec{
		Name:     strings.TrimSuffix(t.Spec.Bucket.Name, "/"),
		Endpoint: env.StorageEndpoint,
		Region:   region(t),
		CredentialsFrom: platformv1alpha1.BucketCredentials{
			SecretRef: env.PlaceholderSecret,
		},
	}
	spec.Resources.CPUMillis = cpuMillis(t)
	spec.Resources.MemoryGi = memoryGi(t)
	spec.Resources.EphemeralStorageGi = ephemeralGi(t)
	if spec.Resources.MaxResidentCells == 0 {
		spec.Resources.MaxResidentCells = 1000
	}
	// Storage is immutable on a WorkerApp; set it only at creation.
	if spec.Storage == nil {
		spec.Storage = &platformv1alpha1.StorageSpec{SizeGi: volumeGi(t), StorageClassName: env.StorageClassName}
	}
	spec.Durability = t.Spec.App.Durability
	if spec.Durability == "" {
		spec.Durability = platformv1alpha1.DurabilityBucket
	}
	spec.Hostnames = t.Spec.App.Hostnames
	spec.RuntimeClassName = ptr.To(runtimeClass(t))
	spec.PublicIngressFrom = env.PublicIngressFrom
}

func (w celldWorkload) Reconcile(ctx context.Context, c client.Client, t *platformv1alpha1.Tenant, env WorkloadEnv) (metav1.Condition, error) {
	app := &platformv1alpha1.WorkerApp{ObjectMeta: metav1.ObjectMeta{Name: t.Name, Namespace: env.Namespace}}
	_, err := controllerutil.CreateOrUpdate(ctx, c, app, func() error {
		app.Labels = mergeLabels(app.Labels, tenantLabels(t))
		desiredWorkerAppSpec(t, env, &app.Spec)
		return controllerutil.SetControllerReference(t, app, c.Scheme())
	})
	if err != nil {
		return metav1.Condition{}, fmt.Errorf("workerapp: %w", err)
	}
	condition := metav1.Condition{Type: CondWorkloadReady, Status: metav1.ConditionFalse, Reason: "Pending", Message: "WorkerApp has not reported status yet"}
	if app.Status.Phase != "" {
		condition.Reason = string(app.Status.Phase)
		condition.Message = fmt.Sprintf("WorkerApp %s/%s is %s (%d ready)", app.Namespace, app.Name, app.Status.Phase, app.Status.Fleet.Ready)
		if invalid := meta.FindStatusCondition(app.Status.Conditions, "SpecValid"); invalid != nil && invalid.Status == metav1.ConditionFalse {
			condition.Message = "WorkerApp rejected the rendered spec: " + invalid.Message
		}
	}
	if app.Status.Phase == platformv1alpha1.PhaseReady {
		condition.Status = metav1.ConditionTrue
	}
	return condition, nil
}
