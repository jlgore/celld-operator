#!/usr/bin/env bash
# Inner half of pr912.sh; runs inside a privileged fedora:43 container with
# /dev/kvm. Mounts: /src/libkrun and /src/crun (read-only checkouts),
# /probe/probe.sh, and /cache (docker volume for cargo and build trees).
set -uo pipefail
log() { echo "### $*"; }

log "deps"
dnf -y -q install dnf-plugins-core >/dev/null 2>&1
dnf -y -q builddep crun >/dev/null 2>&1
dnf -y -q install podman containerd crun libkrunfw rustup clang clang-devel llvm-devel lld gcc make git \
  procps-ng >/dev/null 2>&1 || { echo "dnf failed"; exit 3; }
rpm -q libkrunfw crun podman containerd

export CARGO_HOME=/cache/cargo RUSTUP_HOME=/cache/rustup
export PATH=/cache/cargo/bin:$PATH
if ! command -v cargo >/dev/null; then
  rustup-init -y -q --no-modify-path --default-toolchain stable >/dev/null 2>&1 || { echo "rustup failed"; exit 3; }
fi
rustup target add x86_64-unknown-linux-musl >/dev/null 2>&1
rustc --version
mkdir -p /cache/build
if [[ ! -f /cache/build/libkrun.done ]]; then
  log "build libkrun (PR #912)"
  rm -rf /cache/build/libkrun && cp -a /src/libkrun /cache/build/libkrun
  (cd /cache/build/libkrun && make -j"$(nproc)" >/cache/build/libkrun.log 2>&1) \
    || { tail -40 /cache/build/libkrun.log; exit 4; }
  touch /cache/build/libkrun.done
fi
(cd /cache/build/libkrun && make install PREFIX=/usr/local >/dev/null) || exit 4
echo /usr/local/lib64 >/etc/ld.so.conf.d/local.conf; ldconfig
ls -l /usr/local/lib64/libkrun*

if [[ ! -f /cache/build/crun.done ]]; then
  log "build crun (krun-exec)"
  rm -rf /cache/build/crun && cp -a /src/crun /cache/build/crun; git config --global --add safe.directory "*"
  (cd /cache/build/crun && ./autogen.sh && \
     PKG_CONFIG_PATH=/usr/local/lib64/pkgconfig CPPFLAGS=-I/usr/local/include \
     LDFLAGS=-L/usr/local/lib64 ./configure --with-libkrun --prefix=/usr/local && \
     make -j"$(nproc)") >/cache/build/crun.log 2>&1 || { tail -40 /cache/build/crun.log; exit 5; }
  touch /cache/build/crun.done
fi
install -m755 /cache/build/crun/crun /usr/local/bin/crun-912
ln -sf crun-912 /usr/local/bin/krun
/usr/local/bin/krun --version | head -3

cat >/etc/containers/containers.conf <<'C'
[engine]
cgroup_manager = "cgroupfs"
events_logger = "file"
[engine.runtimes]
krun912 = ["/usr/local/bin/krun"]
[containers]
netns = "host"
C

GRACE=15
IMAGE=registry.fedoraproject.org/fedora-minimal:41
podman pull -q "$IMAGE" >/dev/null

# probe <label> <runtime> [podman run args...]
probe() {
  local label="$1" runtime="$2"; shift 2
  local name="p-$label"
  podman rm -f "$name" >/dev/null 2>&1
  podman run -d --name "$name" --runtime "$runtime" --log-driver k8s-file "$@" \
    -v /probe/probe.sh:/probe.sh:ro "$IMAGE" sh /probe.sh >/dev/null || { echo "$label: run failed"; return 1; }
  for _ in $(seq 1 60); do podman logs "$name" 2>&1 | grep -q PROBE_READY && break; sleep 1; done
  local start end logs code got=no clean=no
  start=$(date +%s); podman stop -t "$GRACE" "$name" >/dev/null 2>&1; end=$(date +%s)
  logs="$(podman logs "$name" 2>&1)"; code="$(podman inspect -f '{{.State.ExitCode}}' "$name")"
  podman rm -f "$name" >/dev/null
  grep -q PROBE_GOT_SIGTERM <<<"$logs" && got=yes
  grep -q PROBE_CLEAN_EXIT <<<"$logs" && clean=yes
  printf 'RESULT podman %-18s stop_seconds=%-3s sigterm_delivered=%s clean_exit=%s exit_code=%s\n' \
    "$label" "$((end - start))" "$got" "$clean" "$code"
  grep PROBE_READY <<<"$logs" | sed 's/^/    /'
}

log "podman probes"
probe crun-control crun
probe krun912-default krun912
probe krun912-exec krun912 --annotation krun.exec=1

log "containerd runc-v2 shim probes (kubelet path: task kill SIGTERM)"
mkdir -p /var/lib/containerd; mountpoint -q /var/lib/containerd || mount -t tmpfs tmpfs /var/lib/containerd
mkdir -p /etc/containerd; containerd config default >/etc/containerd/config.toml 2>/dev/null
(containerd >/tmp/ctrd.log 2>&1 &); sleep 4
ctr images pull "$IMAGE" >/dev/null 2>&1
ctr run --help 2>&1 | grep -i annotation | head -2
ctrprobe() {
  local label="$1" bin="$2"; shift 2
  local id="c-$label"
  ctr run -d --runtime io.containerd.runc.v2 --runc-binary "$bin" "$@" \
    --mount type=bind,src=/probe/probe.sh,dst=/probe.sh,options=rbind:ro \
    --log-uri file:///tmp/$id.log "$IMAGE" "$id" sh /probe.sh >/tmp/$id.err 2>&1 \
    || { echo "$label: ctr run failed"; cat /tmp/$id.err; grep -i error /tmp/ctrd.log | tail -5; return 1; }
  for _ in $(seq 1 60); do grep -q PROBE_READY /tmp/$id.log 2>/dev/null && break; sleep 1; done
  local start end st
  start=$(date +%s); ctr task kill -s SIGTERM "$id"
  for _ in $(seq 1 "$GRACE"); do
    st=$(ctr task ls | awk -v id="$id" '$1==id{print $3}'); [[ "$st" == STOPPED ]] && break; sleep 1
  done
  end=$(date +%s)
  st=$(ctr task ls | awk -v id="$id" '$1==id{print $3}')
  local got=no clean=no
  grep -q PROBE_GOT_SIGTERM /tmp/$id.log && got=yes
  grep -q PROBE_CLEAN_EXIT /tmp/$id.log && clean=yes
  printf 'RESULT ctr    %-18s seconds=%-3s state=%s sigterm_delivered=%s clean_exit=%s\n' \
    "$label" "$((end - start))" "$st" "$got" "$clean"
  ctr task kill -s SIGKILL "$id" >/dev/null 2>&1; sleep 2
  ctr task rm -f "$id" >/dev/null 2>&1; ctr c rm "$id" >/dev/null 2>&1
}
ctrprobe crun-control /usr/bin/crun
ctrprobe krun912-default /usr/local/bin/krun
ctrprobe krun912-exec /usr/local/bin/krun --annotation krun.exec=1
log done
