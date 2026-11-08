# Proposed upstream change: forward SIGTERM into the guest (libkrun)

Target: containers/libkrun (the VMM). An alternative home is crun's krun
handler, but only libkrun can reach the guest init.

## Problem

When crun runs a container in krun mode, `krun_start_enter` turns the
container's PID 1 into the libkrun VMM. The VMM handles `SIGINT` (it
forwards it to the guest as console `ETX`, and the guest init delivers
SIGINT to the workload) but installs no `SIGTERM` handler. As PID 1 of the
container's PID namespace, it ignores signals it has no handler for, so
`kill SIGTERM` from the runtime is dropped.

Every orchestrator stops containers with SIGTERM followed by SIGKILL after a
grace period: Kubernetes via CRI `StopContainer`, podman, and docker. Under
krun the workload never sees the SIGTERM, so it never runs its graceful
shutdown and is SIGKILLed when the grace period ends. Measured with
libkrun 1.19.7 / crun 1.28 under podman and under containerd's runc v2 shim
(`hack/isolation/krun-sigterm/run.sh` in jlgore/celld-operator):

```
crun   stop_seconds=2   sigterm_delivered=yes clean_exit=yes exit_code=0
krun   stop_seconds=15  sigterm_delivered=no  clean_exit=no  exit_code=137
```

This matters for stateful workloads that hand off state on SIGTERM:
Durable Objects runtimes (celld, workerd cluster mode), databases, and
queue consumers. workerd cluster mode drains *only* on SIGTERM, so an image
`STOPSIGNAL SIGINT` cannot work around it.

## Proposal

1. In the VMM, register a `SIGTERM` handler next to the existing `SIGINT`
   handler (`src/vmm/src/signal_handler.rs`). Like `sigint_handler`, it only
   writes to an eventfd, so it is async-signal-safe.
2. Carry the event to the guest init over a channel that does not depend on
   a console TTY. The existing vsock control path or a dedicated
   virtio-console port both work. The guest init (`init/init.c`), which
   already forks the workload so it can deliver signals to it, sends
   `SIGTERM` to the workload's process group.
3. Keep today's behavior for `SIGKILL` (the VMM dies and the guest goes
   with it), and for workloads that ignore SIGTERM (the runtime's grace
   timeout still applies).
4. Optional generalization: forward a configurable set of signals
   (`SIGTERM`, `SIGHUP`, `SIGUSR1`, `SIGUSR2`, `SIGQUIT`), selected through a
   `krun_set_forwarded_signals(ctx_id, mask)` API that crun can set from an
   annotation.

## Test

The probe in `hack/isolation/krun-sigterm/` asserts `sigterm_delivered=yes`
and a clean exit within the grace period under `--runtime krun`, with plain
crun as the control.

## Compatibility

A workload that previously relied on the VMM being unkillable by SIGTERM
would now see the signal. That is the documented OCI and Kubernetes
contract, so the risk is low. The `krun_set_forwarded_signals` gate can
default to `SIGTERM` only.
