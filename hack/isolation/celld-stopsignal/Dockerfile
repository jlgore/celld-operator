# Repackages an upstream celld release so that its container stop signal is
# SIGINT instead of SIGTERM. The binary is unchanged: celld starts the same
# graceful handoff on SIGINT as on SIGTERM (crates/celld/main.rs,
# `sigint.recv() => break ShutdownMode::Handoff`).
#
# Why: under crun+krun the VMM is the container's PID 1 and installs no
# SIGTERM handler, so kubelet's SIGTERM never reaches celld; libkrun does
# forward SIGINT into the guest. See docs/isolation/FINDINGS.md section 4.
#
#   docker build --build-arg CELLD_IMAGE=ghcr.io/denoland/celld:v0.6.2 \
#     -t <registry>/celld:v0.6.2-sigint hack/isolation/celld-stopsignal
#
# Keep the upstream version in the tag (the operator parses it to gate
# rollouts) and add the registry prefix to --allowed-image-prefixes.
ARG CELLD_IMAGE=ghcr.io/denoland/celld:v0.6.2
FROM ${CELLD_IMAGE}
STOPSIGNAL SIGINT
