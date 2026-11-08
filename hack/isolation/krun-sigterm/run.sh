#!/usr/bin/env bash
# Runtime-level test: does stopping a crun+krun container deliver SIGTERM to
# the workload inside the microVM, and is the grace period honored before
# SIGKILL? This is the exact path kubelet takes (CRI StopContainer(timeout)
# -> OCI `kill SIGTERM`, then `kill SIGKILL` after terminationGracePeriodSeconds).
#
# Runs on any KVM host with podman. It runs the same probe under plain crun
# as a control. Exit status 0 means the krun result matches the control
# (graceful); 1 means SIGTERM was not delivered (the handoff will wait for
# lease expiry unless something else triggers the drain).
#
#   GRACE=15 ./hack/isolation/krun-sigterm/run.sh
set -euo pipefail
GRACE="${GRACE:-15}"
IMAGE="${IMAGE:-registry.fedoraproject.org/fedora-minimal:41}"
HERE="$(cd "$(dirname "$0")" && pwd)"
result=0

probe() {
  local runtime="$1" name="sigterm-probe-$1"
  podman rm -f "$name" >/dev/null 2>&1 || true
  podman run -d --name "$name" --runtime "$runtime" --log-driver k8s-file \
    -v "$HERE/probe.sh:/probe.sh:ro,z" "$IMAGE" sh /probe.sh >/dev/null
  for _ in $(seq 1 60); do
    podman logs "$name" 2>&1 | grep -q PROBE_READY && break
    sleep 1
  done
  local start end
  start=$(date +%s)
  podman stop -t "$GRACE" "$name" >/dev/null
  end=$(date +%s)
  local logs code
  logs="$(podman logs "$name" 2>&1)"
  code="$(podman inspect -f '{{.State.ExitCode}}' "$name")"
  podman rm -f "$name" >/dev/null
  local got=no clean=no
  grep -q PROBE_GOT_SIGTERM <<<"$logs" && got=yes
  grep -q PROBE_CLEAN_EXIT <<<"$logs" && clean=yes
  printf '%-6s stop_seconds=%-3s grace=%s sigterm_delivered=%s clean_exit=%s exit_code=%s\n' \
    "$runtime" "$((end - start))" "$GRACE" "$got" "$clean" "$code"
  [[ "$got" == yes && "$clean" == yes ]]
}

probe crun || { echo "control failed: plain crun did not deliver SIGTERM" >&2; exit 2; }
probe krun || result=1
exit "$result"
