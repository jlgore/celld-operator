//go:build e2e

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

package e2e

// Tenant isolation e2e (docs/isolation). Two tenants share one cluster
// and one bucket. The spec proves, from inside tenant A's runtime process:
// it cannot reach tenant B's pods, proxy or admin gateway; its storage
// proxy refuses tenant B's prefix; it cannot reach the store or a cloud
// metadata service directly; and it holds no usable bucket credential in
// its environment, filesystem, or metadata. It then checks admin access
// and that a pod stop reaches the runtime as a graceful signal.
//
// RuntimeClass: E2E_RUNTIME_CLASS names an existing class (krun, kata) on
// a KVM-capable cluster. Unset, the spec creates "e2e-runc" (handler runc)
// so the isolation layer is exercised on plain kind.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/ezgamehost/celld-operator/test/utils"
)

const (
	isolationFixtureImage = "example.com/celld-isolation-fixture:v0.6.2"
	isolationProxyImage   = "example.com/celld-isolation-proxy:e2e"
	seaweedImage          = "chrislusf/seaweedfs:4.51"
	storeNamespace        = "e2e-store"
	adminNamespace        = "e2e-admin"
	storeAdminKey         = "e2e-admin"
	storeAdminSecret      = "e2e-admin-secret"
)

// tenantKeys are each tenant's real store credential: prefix-scoped at the
// store, held only by that tenant's proxy.
var tenantKeys = map[string][2]string{
	"a": {"tenant-a-key", "tenant-a-real-secret-0d1e"},
	"b": {"tenant-b-key", "tenant-b-real-secret-7f3c"},
}

func kubectl(args ...string) string {
	out, err := utils.Run(exec.Command("kubectl", args...))
	Expect(err).NotTo(HaveOccurred(), "kubectl %s", strings.Join(args, " "))
	return out
}

func kubectlApply(manifest string) {
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	_, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), manifest)
}

// portForward forwards a local port to target ("pod/x" or "svc/x") and
// returns the base URL. Port-forward enters the pod's network namespace
// from the kubelet, so it bypasses NetworkPolicy: it is used to *drive*
// probes, never as evidence of reachability.
func portForward(namespace, target string, port int) string {
	cmd := exec.Command("kubectl", "port-forward", "-n", namespace, target, fmt.Sprintf(":%d", port))
	stdout, err := cmd.StdoutPipe()
	Expect(err).NotTo(HaveOccurred())
	Expect(cmd.Start()).To(Succeed())
	DeferCleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	line, err := bufio.NewReader(stdout).ReadString('\n')
	Expect(err).NotTo(HaveOccurred())
	match := regexp.MustCompile(`127\.0\.0\.1:(\d+)`).FindStringSubmatch(line)
	Expect(match).To(HaveLen(2), line)
	go func() { _, _ = io.Copy(io.Discard, stdout) }()
	return "http://127.0.0.1:" + match[1]
}

func getJSON(url string, header ...string) (int, map[string]any) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	Expect(err).NotTo(HaveOccurred())
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	Expect(err).NotTo(HaveOccurred())
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	result := map[string]any{}
	_ = json.Unmarshal(body, &result)
	result["_raw"] = string(body)
	return resp.StatusCode, result
}

func storeClient(endpoint, key, secret string) *s3.Client {
	return s3.New(s3.Options{
		Region: "us-east-1", BaseEndpoint: aws.String(endpoint), UsePathStyle: true, RetryMaxAttempts: 1,
		Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""),
	})
}

func s3Status(err error) int {
	var httpErr interface{ HTTPStatusCode() int }
	if errors.As(err, &httpErr) {
		return httpErr.HTTPStatusCode()
	}
	Expect(err).NotTo(HaveOccurred())
	return http.StatusOK
}

func verifyTenantIsolation() {
	runtimeClass := os.Getenv("E2E_RUNTIME_CLASS")
	overheadCPU, overheadMemory := "250m", "256Mi"

	By("building and loading the isolation proxy and the isolation fixture")
	_, err := utils.Run(exec.Command("docker", "build", "-f", "Dockerfile.isolation-proxy", "-t", isolationProxyImage, "."))
	Expect(err).NotTo(HaveOccurred())
	_, err = utils.Run(exec.Command("docker", "build", "-f", "test/fixtures/isolation/Dockerfile", "-t", isolationFixtureImage, "."))
	Expect(err).NotTo(HaveOccurred())
	_, err = utils.Run(exec.Command("docker", "pull", seaweedImage))
	Expect(err).NotTo(HaveOccurred())
	for _, image := range []string{isolationProxyImage, isolationFixtureImage, seaweedImage} {
		Expect(utils.LoadImageToKindClusterWithName(image)).To(Succeed())
	}

	if runtimeClass == "" {
		By("using a runc RuntimeClass stand-in (set E2E_RUNTIME_CLASS=krun|kata on a KVM cluster)")
		runtimeClass, overheadCPU, overheadMemory = "e2e-runc", "0", "0"
		kubectlApply("apiVersion: node.k8s.io/v1\nkind: RuntimeClass\nmetadata:\n  name: e2e-runc\nhandler: runc\n")
		DeferCleanup(func() { _, _ = utils.Run(exec.Command("kubectl", "delete", "runtimeclass", "e2e-runc", "--ignore-not-found")) })
	}

	By("running an S3 store with prefix-scoped identities per tenant")
	identities := fmt.Sprintf(`{"identities":[
  {"name":"admin","credentials":[{"accessKey":%q,"secretKey":%q}],"actions":["Admin","Read","Write","List"]},
  {"name":"tenant-a","credentials":[{"accessKey":%q,"secretKey":%q}],"actions":["Read:cells/tenants/a/*","Write:cells/tenants/a/*","List:cells/tenants/a/*"]},
  {"name":"tenant-b","credentials":[{"accessKey":%q,"secretKey":%q}],"actions":["Read:cells/tenants/b/*","Write:cells/tenants/b/*","List:cells/tenants/b/*"]}]}`,
		storeAdminKey, storeAdminSecret, tenantKeys["a"][0], tenantKeys["a"][1], tenantKeys["b"][0], tenantKeys["b"][1])
	kubectl("create", "namespace", storeNamespace)
	DeferCleanup(func() { _, _ = utils.Run(exec.Command("kubectl", "delete", "namespace", storeNamespace, "--wait=false")) })
	cm := exec.Command("kubectl", "create", "secret", "generic", "s3-config", "-n", storeNamespace, "--from-file=s3.json=/dev/stdin")
	cm.Stdin = strings.NewReader(identities)
	_, err = utils.Run(cm)
	Expect(err).NotTo(HaveOccurred())
	kubectlApply(fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata: {name: seaweedfs, namespace: %[1]s}
spec:
  selector: {matchLabels: {app: seaweedfs}}
  template:
    metadata: {labels: {app: seaweedfs}}
    spec:
      containers:
      - name: seaweedfs
        image: %[2]s
        args: [server, -s3, -s3.config=/etc/seaweedfs/s3.json, -dir=/data]
        ports: [{containerPort: 8333}]
        readinessProbe: {tcpSocket: {port: 8333}, periodSeconds: 2}
        volumeMounts: [{name: config, mountPath: /etc/seaweedfs}, {name: data, mountPath: /data}]
      volumes:
      - {name: config, secret: {secretName: s3-config}}
      - {name: data, emptyDir: {}}
---
apiVersion: v1
kind: Service
metadata: {name: seaweedfs, namespace: %[1]s}
spec: {selector: {app: seaweedfs}, ports: [{port: 8333}]}
`, storeNamespace, seaweedImage))
	kubectl("rollout", "status", "deployment/seaweedfs", "-n", storeNamespace, "--timeout=180s")
	storeURL := portForward(storeNamespace, "svc/seaweedfs", 8333)
	Eventually(func(g Gomega) {
		_, err := storeClient(storeURL, storeAdminKey, storeAdminSecret).CreateBucket(context.Background(), &s3.CreateBucketInput{Bucket: aws.String("cells")})
		g.Expect(err == nil || s3Status(err) == http.StatusConflict).To(BeTrue(), fmt.Sprint(err))
	}, time.Minute, 2*time.Second).Should(Succeed())

	By("handing each tenant's real key to the operator's credentials namespace only")
	for name, key := range tenantKeys {
		kubectl("create", "secret", "generic", "tenant-"+name+"-store", "-n", namespace,
			"--from-literal=AWS_ACCESS_KEY_ID="+key[0], "--from-literal=AWS_SECRET_ACCESS_KEY="+key[1])
	}

	By("enabling the Tenant controller")
	args := []string{
		"--enable-tenants",
		"--tenant-proxy-image=" + isolationProxyImage,
		"--tenant-credentials-namespace=" + namespace,
		"--gateway-namespace=e2e-gateway",
		"--tenant-pod-overhead-cpu=" + overheadCPU,
		"--tenant-pod-overhead-memory=" + overheadMemory,
		"--allowed-image-prefixes=ghcr.io/denoland/celld:,example.com/celld-fixture:,example.com/celld-isolation-fixture:",
	}
	patches := make([]string, 0, len(args))
	for _, arg := range args {
		patches = append(patches, fmt.Sprintf(`{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":%q}`, arg))
	}
	kubectl("patch", "deployment", "celld-operator-controller-manager", "-n", namespace, "--type=json", "-p", "["+strings.Join(patches, ",")+"]")
	kubectl("rollout", "status", "deployment/celld-operator-controller-manager", "-n", namespace, "--timeout=180s")

	By("creating admin identities: admin-a may administer tenant a, admin-b may not")
	kubectl("create", "namespace", adminNamespace)
	DeferCleanup(func() { _, _ = utils.Run(exec.Command("kubectl", "delete", "namespace", adminNamespace, "--wait=false")) })
	kubectl("create", "serviceaccount", "admin-a", "-n", adminNamespace)
	kubectl("create", "serviceaccount", "admin-b", "-n", adminNamespace)

	By("creating two tenants on one bucket")
	for _, name := range []string{"a", "b"} {
		kubectlApply(fmt.Sprintf(`apiVersion: celld-operator.io/v1alpha1
kind: Tenant
metadata: {name: %[1]s}
spec:
  runtimeClassName: %[2]s
  nodes: 1
  resources: {cpuMillis: 200, memoryGi: 1, ephemeralStorageGi: 1}
  volume: {sizeGi: 1}
  bucket: {name: s3://cells/tenants/%[1]s, endpoint: "http://seaweedfs.%[3]s.svc.cluster.local:8333", region: us-east-1}
  credentials: {secret: {name: tenant-%[1]s-store}}
  storageProxy:
    replicas: 1
    egressTo: [{namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: %[3]s}}}]
  app: {image: %[4]s, appVersion: deploy-a, durability: bucket}
  admin:
    allowedServiceAccounts: [{namespace: %[5]s, name: admin-%[1]s}]
`, name, runtimeClass, storeNamespace, isolationFixtureImage, adminNamespace))
		DeferCleanup(func() { _, _ = utils.Run(exec.Command("kubectl", "delete", "tenant", name, "--wait=false")) })
	}
	for _, name := range []string{"a", "b"} {
		Eventually(func(g Gomega) {
			out, err := utils.Run(exec.Command("kubectl", "get", "tenant", name, "-o", `jsonpath={.status.conditions[?(@.type=="Ready")].status}`))
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(out).To(Equal("True"), kubectl("get", "tenant", name, "-o", "jsonpath={.status.conditions}"))
		}, 5*time.Minute, 2*time.Second).Should(Succeed())
	}

	podA := kubectl("get", "pod", "-n", "tenant-a", "-l", "celld-operator.io/workerapp=a", "-o", "jsonpath={.items[0].metadata.name}")
	podB := kubectl("get", "pod", "-n", "tenant-b", "-l", "celld-operator.io/workerapp=b", "-o", "jsonpath={.items[0].metadata.name}")
	ipB := kubectl("get", "pod", podB, "-n", "tenant-b", "-o", "jsonpath={.status.podIP}")
	Expect(kubectl("get", "pod", podA, "-n", "tenant-a", "-o", "jsonpath={.spec.runtimeClassName}")).To(Equal(runtimeClass))
	probe := portForward("tenant-a", "pod/"+podA, 8080)
	dial := func(addr string) bool {
		_, result := getJSON(probe + "/__isolation/dial?addr=" + addr)
		return result["connected"] == true
	}
	_, creds := getJSON(probe + "/__isolation/creds?secret=" + tenantKeys["a"][1])
	_, _ = fmt.Fprintf(GinkgoWriter, "tenant a runtime kernel: %v\n", creds["kernel"])

	By("reaching its own proxy and peers (positive controls, so denials below are meaningful)")
	Expect(dial("storage-proxy.tenant-a.svc.cluster.local:9000")).To(BeTrue())
	Expect(dial(podA + ".a-celld-internal.tenant-a.svc.cluster.local:8081")).To(BeTrue())

	By("not reaching tenant b's pods, storage proxy, or admin gateway")
	Expect(dial(ipB + ":8080")).To(BeFalse(), "tenant b public port")
	Expect(dial(ipB + ":8081")).To(BeFalse(), "tenant b peer/admin port")
	Expect(dial("storage-proxy.tenant-b.svc.cluster.local:9000")).To(BeFalse(), "tenant b proxy")
	Expect(dial("admin-gateway.tenant-b.svc.cluster.local:8090")).To(BeFalse(), "tenant b admin gateway")

	By("not reaching the store or a metadata service directly")
	Expect(dial("seaweedfs." + storeNamespace + ".svc.cluster.local:8333")).To(BeFalse(), "store bypassing the proxy")
	Expect(creds["metadataReachable"]).To(HaveKeyWithValue("aws-imds", false))
	Expect(creds["metadataReachable"]).To(HaveKeyWithValue("ecs-task", false))
	Expect(creds["metadataReachable"]).To(HaveKeyWithValue("eks-pod-identity", false))

	By("its proxy serving its own prefix and refusing tenant b's")
	s3Probe := func(query string) float64 {
		_, result := getJSON(probe + "/__isolation/s3?" + query)
		return result["status"].(float64)
	}
	Expect(s3Probe("method=PUT&key=tenants/a/probe")).To(Equal(200.0))
	Expect(s3Probe("method=PUT&key=tenants/a/probe&ifNoneMatch=*")).To(Equal(412.0), "create-if-absent passes through the proxy")
	Expect(s3Probe("method=GET&key=tenants/a/probe")).To(Equal(200.0))
	_, err = storeClient(storeURL, tenantKeys["b"][0], tenantKeys["b"][1]).PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String("cells"), Key: aws.String("tenants/b/secret"), Body: strings.NewReader("b-only")})
	Expect(err).NotTo(HaveOccurred())
	Expect(s3Probe("method=GET&key=tenants/b/secret")).To(Equal(403.0), "tenant b's object through tenant a's proxy")
	Expect(s3Probe("method=LIST&prefix=tenants/")).To(Equal(403.0), "listing above the tenant prefix")
	Expect(s3Probe("method=GET&key=tenants/a/../b/secret")).To(Equal(403.0), "dot-segment escape")

	By("holding no usable bucket credential in env, filesystem, or metadata")
	env := creds["env"].(map[string]any)
	Expect(env).To(HaveKeyWithValue("AWS_ACCESS_KEY_ID", "celld-tenant-a"))
	for key := range env {
		Expect(key).To(BeElementOf("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION"), "unexpected credential-like variable %s", key)
	}
	Expect(creds["leakedEnv"]).To(BeNil(), "real secret in the environment")
	Expect(creds["leakedFiles"]).To(BeNil(), "real secret in a file")
	Expect(creds["tokenFiles"]).To(BeNil(), "no Kubernetes or projected token is mounted in the runtime")
	_, err = storeClient(storeURL, env["AWS_ACCESS_KEY_ID"].(string), env["AWS_SECRET_ACCESS_KEY"].(string)).GetObject(context.Background(),
		&s3.GetObjectInput{Bucket: aws.String("cells"), Key: aws.String("tenants/a/probe")})
	Expect(s3Status(err)).To(Equal(http.StatusForbidden), "the placeholder key the runtime holds is useless against the store")
	_, err = storeClient(storeURL, tenantKeys["a"][0], tenantKeys["a"][1]).GetObject(context.Background(),
		&s3.GetObjectInput{Bucket: aws.String("cells"), Key: aws.String("tenants/b/secret")})
	Expect(s3Status(err)).To(Equal(http.StatusForbidden), "even tenant a's real key is scoped at the store")

	By("authenticating admin access per tenant")
	gateway := portForward("tenant-a", "svc/admin-gateway", 8090)
	audience := "celld-admin.tenant-a"
	tokenA := strings.TrimSpace(kubectl("create", "token", "admin-a", "-n", adminNamespace, "--audience", audience))
	tokenB := strings.TrimSpace(kubectl("create", "token", "admin-b", "-n", adminNamespace, "--audience", audience))
	tokenDefault := strings.TrimSpace(kubectl("create", "token", "admin-a", "-n", adminNamespace))
	status, state := getJSON(gateway+"/state", "Authorization", "Bearer "+tokenA)
	Expect(status).To(Equal(http.StatusOK), state["_raw"])
	Expect(state).To(HaveKey("occupied"))
	status, _ = getJSON(gateway+"/state", "Authorization", "Bearer "+tokenB)
	Expect(status).To(Equal(http.StatusForbidden), "tenant b's admin")
	status, _ = getJSON(gateway+"/state", "Authorization", "Bearer "+tokenDefault)
	Expect(status).To(Equal(http.StatusUnauthorized), "a token for another audience")
	status, _ = getJSON(gateway + "/state")
	Expect(status).To(Equal(http.StatusUnauthorized))
	Expect(kubectl("get", "svc", "-n", "tenant-a", "-o", "jsonpath={.items[*].spec.type}")).NotTo(ContainSubstring("LoadBalancer"))

	By("delivering a graceful stop signal to the runtime on pod deletion (decides DO handoff)")
	start := time.Now()
	kubectl("delete", "pod", podA, "-n", "tenant-a", "--wait=true", "--timeout=90s")
	stopped := time.Since(start)
	Eventually(func(g Gomega) {
		logs, err := utils.Run(exec.Command("kubectl", "logs", podA, "-n", "tenant-a"))
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(logs).To(ContainSubstring("Previous stop:"))
		g.Expect(logs).To(MatchRegexp(`Previous stop: signal=(interrupt|terminated) graceful=true`),
			"the runtime never saw a stop signal: under this RuntimeClass pods are SIGKILLed after the grace period")
	}, 3*time.Minute, 2*time.Second).Should(Succeed())
	Expect(stopped).To(BeNumerically("<", 30*time.Second), "stop took the whole grace period")
}
