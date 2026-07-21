#!/bin/sh
set -eu

# One manual, deterministic proof that the root-owned Nyx snapshot can boot and
# accept the audited no-op byte stream. This is not a fuzzer and it does not
# consume model output, produce an execution candidate, alter an AFL queue, or
# invoke a systemd unit. It runs exactly one snapshot-only VM measurement.
if [ "$(id -u)" -ne 0 ]; then
    echo "run with sudo" >&2
    exit 1
fi

CANARY_ROOT=/opt/iou-ai-canary/current
RUNNER=/opt/iou-ai/current/deploy/remote/nyx_canary_oneshot.sh
SELFTEST_ROOT=/var/lib/iou-ai-canary/selftest
SEED=$SELFTEST_ROOT/audited-noop-v1.bin
MEASUREMENT=$SELFTEST_ROOT/last-measurement.json
LOG=$SELFTEST_ROOT/last-run.log
SNAPSHOT=$CANARY_ROOT/snapshot.json
NOOP_SHA256=6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d

die() { echo "canary self-test blocked: $*" >&2; exit 1; }
test -f "$CANARY_ROOT/.ready" || die "isolated snapshot is not ready"
test -f "$SNAPSHOT" || die "isolated snapshot metadata is missing"
test -x "$RUNNER" || die "isolated runner is missing"

snapshot_id=$(sed -n 's/.*"snapshot_id":"\([0-9a-f][0-9a-f]*\)".*/\1/p' "$SNAPSHOT")
snapshot_runner=$(sed -n 's/.*"runner_sha256":"\([0-9a-f][0-9a-f]*\)".*/\1/p' "$SNAPSHOT")
case "$snapshot_id" in
    ????????????????????????????????????????????????????????????????) ;;
    *) die "snapshot identifier is unavailable" ;;
esac
case "$snapshot_runner" in
    ????????????????????????????????????????????????????????????????) ;;
    *) die "snapshot runner hash is unavailable" ;;
esac
runner_hash=$(sha256sum "$RUNNER" | awk '{print $1}')
test "$snapshot_runner" = "$runner_hash" || die "runner changed since snapshot preparation"

worker_count() {
    pgrep -x "$1" 2>/dev/null | wc -l | tr -d '[:space:]'
}

fleet_snapshot() {
    {
        pgrep -x afl-fuzz 2>/dev/null | sed 's/^/afl-fuzz:/' || true
        pgrep -x qemu-system-x86 2>/dev/null | sed 's/^/qemu-system-x86:/' || true
    } | LC_ALL=C sort | sha256sum | awk '{print $1}'
}

afl_before=$(worker_count afl-fuzz)
qemu_before=$(worker_count qemu-system-x86)
test "$afl_before" -ge 1 || die "live AFL worker set is absent"
test "$qemu_before" -ge 1 || die "live Nyx worker set is absent"
before=$(fleet_snapshot)

install -d -o root -g root -m 0700 "$SELFTEST_ROOT"
seed_tmp=$SELFTEST_ROOT/.audited-noop-v1.$$
measurement_tmp=$SELFTEST_ROOT/.measurement.$$
log_tmp=$SELFTEST_ROOT/.log.$$
trap 'rm -f "$seed_tmp" "$measurement_tmp" "$log_tmp"' EXIT HUP INT TERM
umask 077
printf '\000' > "$seed_tmp"
test "$(wc -c < "$seed_tmp" | tr -d '[:space:]')" = 1 || die "no-op seed length is wrong"
test "$(sha256sum "$seed_tmp" | awk '{print $1}')" = "$NOOP_SHA256" || die "no-op seed hash is wrong"
mv -f "$seed_tmp" "$SEED"
chmod 0600 "$SEED"

set +e
CANARY_PER_SEED_MS=5000 CANARY_OUTER_SECONDS=90 "$RUNNER" "$SEED" > "$measurement_tmp" 2> "$log_tmp"
runner_rc=$?
set -e
mv -f "$measurement_tmp" "$MEASUREMENT"
mv -f "$log_tmp" "$LOG"
chmod 0600 "$MEASUREMENT" "$LOG"

afl_after=$(worker_count afl-fuzz)
qemu_after=$(worker_count qemu-system-x86)
after=$(fleet_snapshot)
test "$before" = "$after" || die "canary changed the live fleet worker set"
test "$afl_before" = "$afl_after" || die "canary changed the live AFL worker count"
test "$qemu_before" = "$qemu_after" || die "canary changed the live Nyx worker count"
if [ "$runner_rc" -ne 0 ]; then
    tail -n 80 "$LOG" >&2 || true
    die "isolated runner returned $runner_rc"
fi

# The runner owns this fixed JSON grammar. A clean no-op must boot at least
# once, be accepted, and report neither a timeout nor infrastructure error.
if ! grep -Eq '^\{"executions_total":[1-9][0-9]*,"harness_accepted":true,"timed_out":false,"signal_number":0,"infrastructure_error":false\}$' "$MEASUREMENT"; then
    tail -n 80 "$LOG" >&2 || true
    die "audited no-op was not accepted by the isolated canary"
fi

measurement=$(cat "$MEASUREMENT")
printf '{"schema_version":"isolated-canary-selftest.v1","snapshot_id":"%s","seed_sha256":"%s","runner_sha256":"%s","afl_workers_before":%s,"afl_workers_after":%s,"nyx_workers_before":%s,"nyx_workers_after":%s,"fleet_snapshot_before":"%s","fleet_snapshot_after":"%s","live_fleet_modified":false,"measurement":%s}\n' \
    "$snapshot_id" "$NOOP_SHA256" "$runner_hash" "$afl_before" "$afl_after" "$qemu_before" "$qemu_after" "$before" "$after" "$measurement"
trap - EXIT HUP INT TERM
