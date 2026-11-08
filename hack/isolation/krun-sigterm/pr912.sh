#!/usr/bin/env bash
# Measure SIGTERM delivery under libkrun PR #912 (vsock control server in
# krun-init) with the matching crun branch. It builds both in a privileged
# fedora:43 container with /dev/kvm, then runs probe.sh under podman and
# under containerd's runc v2 shim, with and without the krun.exec=1
# annotation. Results: docs/isolation/upstream/libkrun-sigterm-forwarding.md
#
#   WORK=/tmp/pr912 ./hack/isolation/krun-sigterm/pr912.sh
#
# Needs docker and /dev/kvm. Builds are cached in the docker volume
# krun912-cache; delete it to rebuild from new revisions.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-$(mktemp -d)}"
LIBKRUN_REF="${LIBKRUN_REF:-pull/912/head}"
CRUN_REPO="${CRUN_REPO:-https://github.com/AlphaJack/crun.git}"
CRUN_REF="${CRUN_REF:-krun-exec}"

if [[ ! -d "$WORK/libkrun" ]]; then
  git clone -q https://github.com/libkrun/libkrun.git "$WORK/libkrun"
  git -C "$WORK/libkrun" fetch -q origin "$LIBKRUN_REF:probe"
  git -C "$WORK/libkrun" checkout -q probe
fi
if [[ ! -d "$WORK/crun" ]]; then
  git clone -q -b "$CRUN_REF" "$CRUN_REPO" "$WORK/crun"
  git -C "$WORK/crun" submodule update --init --recursive -q
fi
echo "libkrun $(git -C "$WORK/libkrun" rev-parse --short HEAD), crun $(git -C "$WORK/crun" rev-parse --short HEAD)"

docker run --rm --privileged --device /dev/kvm \
  -v "$WORK/libkrun:/src/libkrun:ro" -v "$WORK/crun:/src/crun:ro" \
  -v "$HERE:/probe:ro" -v "$HERE:/harness:ro" -v krun912-cache:/cache \
  registry.fedoraproject.org/fedora:43 bash /harness/pr912-inner.sh
