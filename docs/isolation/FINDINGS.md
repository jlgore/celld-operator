# Tenant isolation: verified findings

Each item states what was checked, how, and the source. "Source" means the
upstream code at the pinned revision. "Measured" means it was run on this
branch's test harness. Assumptions from the original brief that turned out
false are marked **Assumption corrected**, and the design change is
described next to them.

Pinned revisions:

| Project | Revision |
|---|---|
| celld | `v0.6.2` (the version this operator tracks), `crates/celld` |
| object_store (celld's S3 client) | `0.12.5` (from celld's `Cargo.lock`) |
| workerd | `main` @ `88b5871e` (2026-11-08), `src/workerd/server/cluster` |
| crun | `main` @ `73547f5a` (2026-11-06); packaged `crun-krun-1.28-1.fc43` for measurements |
| libkrun | `v1.19.8` source; packaged `libkrun-1.19.7-1.fc43`, `libkrunfw-5.6.2-1.fc43` for measurements |
| containerd | `containerd-2.2.10-1.fc43` (measurements) |
| podman / conmon (stand-in for CRI-O's OCI path) | `podman-5.8.9-1.fc43` |

## 1. celld accepts a custom S3 endpoint: yes, path-style, plain HTTP allowed

- `S3_ENDPOINT` (or `--endpoint`) is read by the CLI and the fleet node
  (`crates/celld/main/cli.rs:136`, `crates/celld/fleet.rs:556`).
  `AWS_ENDPOINT_URL` / `AWS_ENDPOINT` are honored as fallbacks
  (`crates/celld/bucket.rs:305-313`).
- With an endpoint set, the main client switches to path-style requests
  (`with_virtual_hosted_style_request(false)`, `bucket.rs:741-749`) and allows
  `http://` (`ClientOptions::with_allow_http(true)`, `bucket.rs:690`). URLs are
  `<endpoint>/<bucket>/<prefix>/<key>`.
- **There is a second S3 client**: the LTX replication client
  (`crates/celld/ltx_repl.rs:5420 node_config`, `crates/ltx/src/client/object_store.rs:296 build_s3`).
  It takes the same endpoint, is also path-style when an endpoint is set
  (`force_path_style: !endpoint.is_empty()`), and allows HTTP when the
  endpoint is `http://` (`object_store.rs:362`). The proxy must serve both.
- The bucket prefix accepts only `[A-Za-z0-9-_./]` (`bucket.rs:676-680`), so the
  proxy's prefix check can compare decoded paths without ambiguity.

## 2. Conditional-write semantics the proxy must pass through unchanged

celld fences ownership with S3 conditional writes. The proxy is in the
fencing path, so it must forward these byte-for-byte and return the store's
status codes unchanged.

| Operation | Wire form | Source |
|---|---|---|
| Create-if-absent | `PUT` with `If-None-Match: *`; store answers `412` (S3, R2) or `304`; object_store maps both to `AlreadyExists` | object_store `aws/mod.rs:187-197` |
| Compare-and-swap | `PUT` with `If-Match: <etag>`; `412` = lost race; S3 may answer `409` under concurrent `If-Match` (retried by object_store) and `404` if absent (mapped to precondition) | object_store `aws/mod.rs:205-226` |
| Conditional multipart complete | `POST ?uploadId=` with `If-None-Match: *` | object_store `aws/client.rs:784` |
| R2-binding conditional reads | `GET` with `If-Match` / `If-None-Match` (etag lists), `Range` | celld `bucket.rs:332-372` (`BlobConditions`) |
| CAS token | the response `ETag` (S3 and Azure dialects); a response without one is an error | celld `bucket.rs:96-112` |

Other operations celld issues (object_store calls in `crates/celld`): `get_opts`,
`head`, `put_opts`, `put_multipart_opts`, `delete`, `delete_stream`
(S3 `POST ?delete`, keys in an XML body), `list`, `list_paginated`,
`list_with_delimiter`, `list_with_offset` (ListObjectsV2 with `prefix`,
`delimiter`, `start-after`, `continuation-token`), and `rename` (CopyObject with
`x-amz-copy-source`, then delete).

Consequences for the proxy:

1. Never retry a conditional `PUT`. celld sets zero transport retries for CAS
   writes on purpose: a repeated `If-Match` PUT can answer `412` for a write
   that committed (`bucket.rs:695-708`). The proxy forwards exactly once and
   never buffers and replays.
2. Pass `If-Match`, `If-None-Match`, `If-Modified-Since`,
   `If-Unmodified-Since`, `Range`, `x-amz-copy-source-if-*`, `Content-MD5`,
   `x-amz-checksum-*`, `x-amz-meta-*` and `ETag` through unchanged, along with
   the status code (`200/204/206/304/404/409/412`).
3. Enforce the prefix on every key-bearing input: the path, the ListObjects
   `prefix` query, every `<Key>` in a `DeleteObjects` body, and the
   `x-amz-copy-source` header.
4. Reuse the caller's `x-amz-content-sha256` when it is a hex digest (S3
   verifies the body against it, so the proxy need not trust it). Send
   `UNSIGNED-PAYLOAD` when it is absent or unsigned. Refuse `STREAMING-*`
   payload signing, which would need re-chunking.

workerd cluster mode speaks the same dialect: `if-none-match: *` for
create and `if-match: <etag>` for replace (`cluster/s3.rs:160-165`),
path-style against `aws_endpoint` (`cluster/s3.rs:6`, `:77-126`).

## 3. Neither celld S3 client can run unsigned. Use placeholder keys

**Assumption corrected.** The brief asks for no long-lived bucket credentials
inside celld pods, and it is tempting to read that as "no credentials at
all". That does not work:

- The main client honors `AWS_SKIP_SIGNATURE=true`. `AmazonS3Builder::from_env`
  maps it (object_store `aws/builder.rs:464`, `:524-537`), and with it set,
  `get_credential` returns `None` (`aws/client.rs:219-240`).
- The LTX replication client builds with `AmazonS3Builder::new()` and forwards
  only an allowlist of `AWS_*` credential variables (`ltx/src/client/object_store.rs:320-345`).
  `AWS_SKIP_SIGNATURE` is not on it. Without static keys it walks the provider
  chain: web identity → ECS task → EKS Pod Identity → **instance metadata
  (IMDS, 169.254.169.254)** (object_store `aws/builder.rs:1020-1095`; celld's own
  comment at `ltx_repl.rs:5428-5436`).
- workerd cluster mode *requires* `aws_access_key_id` / `aws_secret_access_key`
  (`cluster/s3.rs:108-120`).

**Design:** the fleet gets a non-secret placeholder key pair through the
existing WorkerApp `credentialsFrom.secretRef`
(`AWS_ACCESS_KEY_ID=celld-tenant-<name>`, `AWS_SECRET_ACCESS_KEY=signed-by-proxy`).
Both clients sign with it, and the proxy discards that signature and re-signs
with the real, short-lived credential. The placeholder is accepted by
nothing but the tenant's own proxy, which is reachable only from the
tenant's own namespace. It grants nothing the fleet does not already have.
The e2e suite proves the store rejects it. Default-deny egress also blocks
IMDS, so a misconfiguration cannot fall back to the node role.

## 4. SIGTERM under crun+krun is NOT delivered to the workload

**Assumption corrected; this decides DO handoff behavior.**

*Source:*

- libkrun's VMM installs handlers for `SIGSYS`, `SIGBUS`, `SIGSEGV`,
  `SIGWINCH` and `SIGINT` only (`src/vmm/src/signal_handler.rs`). `SIGINT` is
  forwarded into the guest as an `ETX` byte on the console
  (`src/devices/src/virtio/console/port_io.rs:250-256`). The guest init then
  delivers SIGINT to the workload, which init forks for exactly that reason
  (`src/init_blob/init/init.c:1579`). There is no `SIGTERM` handler and no
  other forwarding path.
- crun's krun handler (`src/libcrun/handlers/krun.c`) calls
  `krun_start_enter`, which turns the container's PID 1 into the VMM. It adds
  no signal translation.
- A container's PID 1 does not receive signals from an ancestor PID namespace
  unless it has installed a handler for them, except `SIGKILL`/`SIGSTOP`
  (pid_namespaces(7)). So `kill SIGTERM` from the runtime is dropped.

*Measured* with `hack/isolation/krun-sigterm/run.sh` (probe workload traps
SIGTERM and SIGINT; `podman stop -t 15` is the same `kill SIGTERM`, wait,
`kill SIGKILL` sequence kubelet drives through CRI `StopContainer`):

```
crun   stop_seconds=2   grace=15 sigterm_delivered=yes clean_exit=yes exit_code=0
krun   stop_seconds=15  grace=15 sigterm_delivered=no  clean_exit=no  exit_code=137
```

The workload really ran in a VM: the guest reported kernel `6.12.109`
(libkrunfw), while the host runs `6.6.114.1-microsoft-standard-WSL2`.
Sending signals directly to the krun container:

```
after SIGINT:  exited/0  (probe printed PROBE_GOT_SIGINT)
after SIGTERM: running   (nothing printed; SIGKILL after the timeout)
```

The same result through containerd's runc v2 shim with
`--runc-binary /usr/bin/krun`: SIGTERM leaves the task `RUNNING`, and SIGINT
stops it.

*Meaning:*

- **terminationGracePeriodSeconds is honored**, but only as a delay. Kubelet
  waits the full grace period (the operator pins 60 s) and then SIGKILLs the
  VMM. celld never starts its drain (`main.rs:4872`: SIGTERM and SIGINT both
  map to `ShutdownMode::Handoff`), so its Durable Objects are not handed off.
  Peers take them over only after the ownership lease expires. Every pod
  delete costs a 60 s stall, then the lease timeout, then cold restores.
  Rollouts are gated on `restoring == 0`, so they still converge, slowly.
- **Mitigation for celld (no runtime change):** celld drains on SIGINT
  exactly as on SIGTERM. A celld image with `STOPSIGNAL SIGINT` (OCI image
  config) makes the stop graceful under krun. Both CRIs honor the image's
  stop signal when the container spec sets none: containerd
  `internal/cri/server/container_stop.go:167-192` (main), CRI-O
  `internal/oci/container.go:328` (`Container.StopSignal`, main).
  `hack/isolation/celld-stopsignal/Dockerfile` builds one from the upstream
  image without changing the binary. Kubernetes' per-container
  `lifecycle.stopSignal` (KEP-4960, feature gate `ContainerStopSignals`,
  alpha in 1.33, beta in 1.37 per the KEP page) is the API-level equivalent
  once enabled.
- **workerd cluster mode drains only on SIGTERM** (`server/server/entry.rs:216-236`,
  `cluster/logic/handoff.rs:9`). SIGINT takes the default action there, so the
  STOPSIGNAL workaround does not carry over. A runtime-swappable design
  needs SIGTERM forwarding in libkrun. That is proposed upstream in
  [upstream/libkrun-sigterm-forwarding.md](upstream/libkrun-sigterm-forwarding.md).
  This is a libkrun change, not a celld or workerd change.
- **Kata** forwards signals through the shim and the kata-agent to the
  container process in the guest (`SignalProcess`). It was not measured here
  (no Kata install on this host). The Kubernetes-level e2e spec
  (`test/e2e/isolation_test.go`, "graceful stop") measures it on any cluster
  with `E2E_RUNTIME_CLASS=kata`.

Harness limits: the measurements ran nested in a privileged Fedora 43
container on a WSL2 host with nested KVM. Cgroup controller delegation in
that nesting is incomplete, so cgroup limits were not measured here (the
crun control under containerd failed on cgroup delegation, not on krun).
Kubelet itself was not in the loop; the e2e spec covers the kubelet path on
a real cluster.

## 5. containerd vs CRI-O with the krun handler

| Path | Status | Evidence |
|---|---|---|
| CRI-O, runtime handler `krun` → `runtime_path=/usr/bin/krun` (`krun` is a symlink to `crun`; argv[0] selects krun mode) | Works. This is the configuration crun's `krun.1` documents and the Fedora `crun-krun` package ships. | `/usr/bin/krun -> crun` in `crun-krun-1.28`. Measured through podman+conmon, which invokes the OCI runtime the same way CRI-O does. |
| CRI-O, plain `crun` + `run.oci.handler=krun` annotation | Works if the annotation is in the handler's `allowed_annotations` | crun `custom-handler.c:328`; measured through containerd below |
| containerd 2.x, `runtime_type = "io.containerd.runc.v2"` + `options.BinaryName = "/usr/bin/krun"` | Boots and runs the workload in a VM | Measured: guest kernel `6.12.109` via `ctr run --runc-binary /usr/bin/krun` |
| containerd, plain crun + `run.oci.handler=krun` OCI annotation | Boots | Measured (label propagated as an annotation by `ctr`). Under the CRI, pod annotations reach the OCI spec only if listed in the runtime's `pod_annotations`. |
| VM sizing | RAM comes from the container memory limit; vCPUs from the `krun.cpus` annotation, else the host CPU affinity (capped). The cgroup CPU quota still applies. | crun `krun.c:326-345`. CPU *limits* therefore matter: the Tenant's LimitRange sets them. |
| `kubectl exec` | Runs a process in the container's namespaces **outside** the VM (crun exec does not enter the guest). Do not use exec to inspect a krun workload; the e2e probes run inside the workload process. | crun krun handler has no exec hook into the guest. |

Neither path was run under a real kubelet here. `config/isolation/runtimeclass/README.md`
documents both node configurations.

## 6. Other facts the design relies on

- Fleet pods already set `automountServiceAccountToken: false`
  (`internal/controller/fleet_resources.go`), so no Kubernetes API token
  reaches the VM.
- The WorkerApp NetworkPolicy opens `:8080` to all sources. NetworkPolicies
  are additive (an allow in any selecting policy admits the traffic), so a
  namespace default-deny cannot narrow it. That is why touch point T1 adds
  `publicIngressFrom`.
- The WorkerApp endpoint validation requires an allowlisted `https://` URL.
  The in-namespace proxy is `http://` on purpose: the hop never leaves the
  namespace, and the mesh or CNI encrypts it along with peer traffic. Touch
  point T3 adds an opt-in exception for namespace-local Services.
- workerd cluster mode adds a shared cluster `key` (`workerd.capnp`
  `ClusterConfig.key`). That inter-node secret would live in the VM. It is
  not a bucket credential, but DESIGN.md lists it as a residual risk for the
  workerd backend.
