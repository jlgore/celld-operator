# Upstream status: SIGTERM forwarding under libkrun

This file used to propose a new libkrun change. That change is already in
progress upstream, so no new proposal is needed. This page tracks the
upstream work and records what we measured against it.

## Upstream work

| Item | What it is | State (2026-11-08) |
|---|---|---|
| [libkrun/libkrun#10](https://github.com/libkrun/libkrun/issues/10) | "Relay SIGTERM from the VMM to the isolated process" | Open; labels `enhancement`, `help wanted` |
| [libkrun/libkrun#905](https://github.com/libkrun/libkrun/issues/905) | Design discussion: an optional vsock exec server in krun-init for exec and signal delivery | Open; a maintainer (mtjhrc) agreed on the design |
| [libkrun/libkrun#912](https://github.com/libkrun/libkrun/pull/912) | "init: add a control server for exec and signal delivery"; "Fixes #10" | Open, mergeable, review required |
| [AlphaJack/crun `krun-exec`](https://github.com/AlphaJack/crun/tree/krun-exec) | crun side: ports the krun handler to the libkrun 2.0 API and routes `krun kill` and `krun exec` through the control server | Branch only, no PR yet; 269 commits behind crun main |
| [containers/crun#2158](https://github.com/containers/crun/issues/2158) | "krun: Containers do not shut down cleanly" | Open; a maintainer redirected it to libkrun#10 |

Both #912 and the crun branch target libkrun 2.0 (main), not the 1.19.x
releases that distributions ship.

## How #912 delivers the signal

- krun-init runs a control server on a thread, listening on a private vsock
  port. It accepts host CIDs only. The vsock muxer refuses guest TSI
  `connect()`s to host listening Unix ports, so a guest cannot reach the
  socket through AF_UNIX hijacking.
- libkrun_init maps that port to a Unix socket. The crun branch exposes it at
  `/dev/krun-init.sock` in the container's `/dev` tmpfs.
- `crun kill` with any signal except SIGKILL calls
  `Controller::signal_entrypoint(sig)`. It reaches the socket through
  `/proc/<vmm pid>/root` after checking the pid. In the guest, the server
  calls `kill(workload_pid, sig)`. SIGKILL still goes to the VMM.
- **Opt-in:** this is enabled only by the OCI annotation `krun.exec=1`.
  Without the annotation, behavior is unchanged (the VMM drops SIGTERM).
- **Single process:** the signal goes to the workload pid, not its process
  group. A shell wrapper that does not `exec` the server will swallow it.
- The same server also makes `krun exec` (`podman exec`, `kubectl exec`,
  exec probes) run inside the guest.

## Measured against #912

Built #912 (`5f7d3ed8`, libkrun 2.0.0-dev) and `krun-exec` (`54f3c669`,
crun 1.30.1 + 131) in a privileged `fedora:43` container with `/dev/kvm`,
against the packaged libkrunfw 5.6.2. To reproduce, run
[hack/isolation/krun-sigterm/pr912.sh](../../../hack/isolation/krun-sigterm/pr912.sh).
It runs the same probe workload as `run.sh`.

podman 5.8.9, `podman stop -t 15`:

```
crun-control     stop_seconds=2   sigterm_delivered=yes clean_exit=yes exit_code=0
krun912-default  stop_seconds=15  sigterm_delivered=no  clean_exit=no  exit_code=137
krun912-exec     stop_seconds=3   sigterm_delivered=yes clean_exit=yes exit_code=0   (--annotation krun.exec=1)
```

containerd 2.2.10, runc v2 shim, `--runc-binary krun`, `ctr task kill -s SIGTERM`
(the path kubelet drives through CRI `StopContainer`):

```
krun912-default  seconds=15  state=RUNNING  sigterm_delivered=no  clean_exit=no
krun912-exec     seconds=4   state=STOPPED  sigterm_delivered=yes clean_exit=yes   (--annotation krun.exec=1)
```

The podman results held across three runs. Both krun probes reported guest
kernel `6.12.109`, so they ran in the VM. The containerd plain-crun control
did not start (`sh` not found in `$PATH`, a harness issue). The containerd
control from FINDINGS.md section 4 still stands.

## Not verified

- Kubernetes end to end. For kubelet to reach this path, the pod annotation
  `krun.exec` must reach the OCI spec. CRI-O needs `krun.exec` in the
  runtime handler's `allowed_annotations`. containerd needs it in the
  runtime's `pod_annotations`. Neither has been tested.
- The security of the control socket beyond the code read above: any host
  process that can open `/proc/<vmm pid>/root/dev/krun-init.sock` can exec
  in the guest.
- Behavior under `KRUN_INIT_PID1=1`, which #912 refuses for now, and under
  the SEV, TDX and Nitro variants, where the control server is not
  available.

## What we would add upstream (ask first)

These are outward-facing; post them only after the repo owner agrees.

- A comment on #912 with the podman and containerd numbers above, as
  independent confirmation of the author's `podman stop` result.
- A note on #912 or #905 that Kubernetes needs `krun.exec` passed through
  (or a handler-level default), and that process-group delivery would cover
  wrapper entrypoints.
