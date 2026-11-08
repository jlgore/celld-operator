# MicroVM RuntimeClasses for tenants

A Tenant's `spec.runtimeClassName` (default `krun`) names one of these.
The operator never assumes a runtime: the name is configuration, and the
same Tenant runs under `kata` by changing that field (the fleet rolls
through the WorkerApp's ordinary gated rollout).

Verified behavior, and what was not verified, is in
[docs/isolation/FINDINGS.md](../../../docs/isolation/FINDINGS.md) sections 4 and 5.

## Node preparation (both runtimes)

1. Hardware virtualization: `/dev/kvm` must exist on the node (bare metal,
   or a VM type with nested virtualization).
2. Label and taint the nodes, so only tenant microVM pods land there and
   they never land anywhere else:

   ```sh
   kubectl label node $NODE celld-operator.io/kvm=true
   kubectl taint node $NODE celld-operator.io/microvm=true:NoSchedule
   ```

   With Node Feature Discovery, a local feature source can set the `kvm`
   label automatically from `/dev/kvm`.

## krun

Packages: `crun` built with libkrun support (Fedora/RHEL: `crun-krun`, which
installs `/usr/bin/krun` as a symlink to `crun`), `libkrun`, `libkrunfw`.

### CRI-O (recommended; the documented upstream path)

`/etc/crio/crio.conf.d/50-krun.conf`:

```toml
[crio.runtime.runtimes.krun]
runtime_path = "/usr/bin/krun"
runtime_type = "oci"
runtime_root = "/run/krun"
# Lets a pod size the VM's vCPUs; otherwise krun uses the host CPU
# affinity. The cgroup CPU quota (the Tenant's hard limit) applies either way.
allowed_annotations = ["krun.cpus", "krun.ram_mib"]
```

```sh
kubectl label node $NODE celld-operator.io/runtime-krun=true
```

### containerd 2.x

`/etc/containerd/config.toml`:

```toml
[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.krun]
  runtime_type = 'io.containerd.runc.v2'
  [plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.krun.options]
    BinaryName = '/usr/bin/krun'
    SystemdCgroup = true
```

The runc v2 shim driving `/usr/bin/krun` boots the workload in a VM. This
was measured outside kubelet (FINDINGS.md section 5). CRI-O is the path
crun documents. Under containerd, pod annotations such as `krun.cpus` reach
the OCI spec only if they are listed in the runtime's `pod_annotations`.

### Stop signal (read this before running celld under krun)

libkrun does not forward SIGTERM into the guest, so a pod stop never
starts celld's graceful handoff. The pod is SIGKILLed after the 60 s grace
period, and Durable Objects move only after their leases expire. libkrun
does forward SIGINT, which celld treats the same as SIGTERM. Run celld from
an image with `STOPSIGNAL SIGINT`
([hack/isolation/celld-stopsignal](../../../hack/isolation/celld-stopsignal/Dockerfile)).
Check a node with
[hack/isolation/krun-sigterm/run.sh](../../../hack/isolation/krun-sigterm/run.sh).

### Inspecting a krun pod

`kubectl exec` runs on the host side of the VM boundary, in the
container's namespaces. It does not run inside the guest. Debug through
the workload's own endpoints or its logs (the console).

## kata

Install with [kata-deploy](https://github.com/kata-containers/kata-containers/tree/main/tools/packaging/kata-deploy).
It configures CRI-O or containerd, registers the `kata` handler (plus
`kata-qemu`, `kata-clh`, ...), and labels nodes
`katacontainers.io/kata-runtime=true`. Point `handler:` in `kata.yaml` at
the variant you want. Kata forwards signals to the container process
through the kata-agent, so SIGTERM reaches celld without the STOPSIGNAL
workaround. The e2e "graceful stop" spec measures this on your cluster.
