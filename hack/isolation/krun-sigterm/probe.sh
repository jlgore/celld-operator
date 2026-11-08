#!/bin/sh
# Workload for the SIGTERM probe. It stands in for celld: it traps SIGTERM
# (celld's graceful-handoff trigger, crates/celld/main.rs) and reports how
# long after the signal it got to run its shutdown path.
trap 'echo "PROBE_GOT_SIGTERM $(date +%s)"; sleep 2; echo "PROBE_CLEAN_EXIT"; exit 0' TERM
trap 'echo "PROBE_GOT_SIGINT $(date +%s)"; exit 0' INT
echo "PROBE_READY $(date +%s) kernel=$(uname -r)"
while :; do sleep 1 & wait $!; done
