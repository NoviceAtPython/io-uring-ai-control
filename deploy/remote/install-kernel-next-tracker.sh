#!/bin/sh
# stage36-automate-kernel-next.sh -- Install the unattended kernel-next tracker.
# Installs /usr/local/bin/iou-kernel-next (the whole fetch->build->validate->rotate
# ->rollback loop, guarded), seeds its state with the currently-live commit so it
# does not needlessly rebuild, and enables a daily timer that ACTS ONLY when
# io_uring-next actually advances. Kill switch: touch KERNEL_NEXT_DISABLED.
set -u
CURRENT_COMMIT=c905736a46892e4776efc7f50888d67715d6ec08   # what stage33/35 deployed
STATE=/var/lib/iou-ai/runtime
umask 0022

echo '===== 1. INSTALL /usr/local/bin/iou-kernel-next ====='
cat > /usr/local/bin/iou-kernel-next <<'EOS'
#!/bin/sh
# Unattended guest-kernel-next tracker. Rebuilds+rotates the fuzzer onto the
# newest io_uring dev branch ONLY when it advances and ONLY after the new kernels
# are proven to boot; otherwise it stays put and (on failure) alerts. Fail-safe:
# any build/validation failure leaves the live fleet exactly as it was.
set -u
WS=/root/fuzzer_workspace
SRC=$WS/kernels/linux
WT=$WS/kernels/linux-iou-next
TGT=$WS/nyx_targets
T=$TGT/nat_out
STAGE=$WS/staging
SEEDS=$TGT/nat_seeds
NYX=$WS/AFLplusplus
AXBOE=https://git.kernel.org/pub/scm/linux/kernel/git/axboe/linux.git
STATEDIR=/var/lib/iou-ai/runtime
COMMIT_FILE=$STATEDIR/kernel-next.commit
KILL=$STATEDIR/KERNEL_NEXT_DISABLED
J=$(nproc)
umask 0022
alert() { [ -x /usr/local/bin/iou-alert ] && /usr/local/bin/iou-alert "$1"; logger -t iou-kernel-next "$1" 2>/dev/null; }
log() { echo "$(date -Is) $1"; }

[ -e "$KILL" ] && { log "KERNEL_NEXT_DISABLED present; skipping"; exit 0; }
install -d "$STAGE"

# 1. newest io_uring dev branch + its HEAD
BR=$(git ls-remote --heads "$AXBOE" 2>/dev/null | grep -oE 'for-[0-9]+\.[0-9]+/io_uring$' | sort -V | tail -1)
[ -n "$BR" ] || { log "could not list branches (network?)"; exit 0; }
cd "$SRC" 2>/dev/null || { log "no source tree"; exit 1; }
git remote get-url axboe >/dev/null 2>&1 || git remote add axboe "$AXBOE"
git fetch --depth=1 axboe "$BR" >/dev/null 2>&1 || { log "fetch failed"; exit 0; }
NEWREF=$(git rev-parse FETCH_HEAD)
LASTREF=$(cat "$COMMIT_FILE" 2>/dev/null || echo none)
if [ "$NEWREF" = "$LASTREF" ]; then
    log "already on newest ($BR @ ${NEWREF%??????????????????????????????????????}...); nothing to do"
    exit 0
fi
log "io_uring-next advanced: $BR $LASTREF -> $NEWREF; rebuilding"

# 2. build both kernels to staging in a clean worktree
git worktree remove --force "$WT" 2>/dev/null; rm -rf "$WT"
git worktree add --detach "$WT" "$NEWREF" >/dev/null 2>&1 || { alert "io_uring kernel-next: worktree add failed for $NEWREF; fleet unchanged."; exit 1; }
cd "$WT" || exit 1
KVER=$(make -s kernelversion 2>/dev/null)
cp "$SRC/.config" "$WT/.config"; make olddefconfig >/dev/null 2>&1
if ! make -j"$J" bzImage >/tmp/kn-fast.log 2>&1; then
    alert "io_uring kernel-next: FAST build failed on $BR ($KVER). Fleet stays on the current kernel. Log: /tmp/kn-fast.log"; exit 1
fi
cp arch/x86/boot/bzImage "$STAGE/bzImage.fast.next"
cp "$SRC/.config.kasan" "$WT/.config"; make olddefconfig >/dev/null 2>&1
if ! make -j"$J" bzImage >/tmp/kn-kasan.log 2>&1; then
    alert "io_uring kernel-next: KASAN build failed on $BR ($KVER). Fleet stays on the current kernel. Log: /tmp/kn-kasan.log"; exit 1
fi
cp arch/x86/boot/bzImage "$STAGE/bzImage.kasan.next"
log "built $KVER (fast+kasan) to staging"

# 3. validate BOTH boot under Nyx (isolated; no live impact)
probe() { # name pack newkernel
    NAME=$1; PACK=$2; NEWK=$3; P=$TGT/kn_$NAME; OUT=/tmp/kn_out_$NAME
    rm -rf "$P" "$OUT"; mkdir -p "$OUT"; cp -r "$TGT/$PACK" "$P" || return 1
    LIVE_RON=$(grep -oE '/[^"]*default_config_kernel[a-z_]*\.ron' "$P/config.ron" | head -1)
    cp "$LIVE_RON" "$P/probe_kernel.ron" || return 1
    sed -i "s#kernel: \"[^\"]*\"#kernel: \"$NEWK\"#" "$P/probe_kernel.ron"
    sed -i "s#$LIVE_RON#$P/probe_kernel.ron#" "$P/config.ron"
    cd "$TGT" || return 1
    AFL_PATH="$NYX/nyx_mode" AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_NO_UI=1 AFL_NO_AFFINITY=1 \
        timeout -s INT 100 "$NYX/afl-fuzz" -i "$SEEDS" -o "$OUT" -G 4096 -Y -M 0 -- ./kn_"$NAME" >/tmp/kn_val_$NAME.log 2>&1
    e=$(awk -F': *' '/^execs_done/{print $2}' "$OUT"/0/fuzzer_stats 2>/dev/null | tr -d ' ')
    rm -rf "$P" "$OUT"
    [ "${e:-0}" -gt 0 ] 2>/dev/null
}
if ! probe fast iou_native_pack "$STAGE/bzImage.fast.next" || ! probe kasan iou_native_kasan "$STAGE/bzImage.kasan.next"; then
    alert "io_uring kernel-next: $KVER built but FAILED to boot under Nyx; NOT rotating. Fleet stays on the current kernel."; exit 1
fi
log "both kernels validated"

# 4. rotate with backup + health verify + rollback
TS=$(date +%Y%m%d-%H%M%S); BK=$WS/kernel-backups/$TS; install -d "$BK"
cp -a "$WS/bzImage.fast" "$BK/"; cp -a "$WS/bzImage.kasan" "$BK/"
cp -a "$STAGE/bzImage.fast.next" "$WS/bzImage.fast"; cp -a "$STAGE/bzImage.kasan.next" "$WS/bzImage.kasan"
systemctl restart iou-fleet.service
healthy() { i=0; while [ $i -lt 24 ]; do i=$((i+1)); sleep 10;
    n=$(pgrep -c -x afl-fuzz); fresh=$(find "$T"/0/fuzzer_stats -newermt '-25 seconds' 2>/dev/null)
    [ "$n" = 10 ] && [ -n "$fresh" ] && return 0; done; return 1; }
if healthy; then
    echo "$NEWREF" > "$COMMIT_FILE"
    printf 'guest=io_uring-next\nkernelversion=%s\nbranch=%s\ncommit=%s\nrotated_at=%s\nbackup=%s\n' "$KVER" "$BR" "$NEWREF" "$TS" "$BK" > "$WS/CURRENT_GUEST_KERNEL"
    alert "io_uring fuzzer: auto-updated guest kernel to $KVER ($BR) and fleet is healthy (10/10). Now fuzzing the newest io_uring code."
    log "rotated to $KVER; fleet healthy"
else
    cp -a "$BK/bzImage.fast" "$WS/bzImage.fast"; cp -a "$BK/bzImage.kasan" "$WS/bzImage.kasan"
    systemctl restart iou-fleet.service
    if healthy; then alert "io_uring kernel-next: $KVER did not run under the full fleet; auto-rolled back, fleet healthy. Needs a look."
    else alert "io_uring fuzzer CRITICAL: kernel auto-update failed AND rollback did not restore the fleet. Manual check needed."; fi
    exit 1
fi
EOS
chmod 0755 /usr/local/bin/iou-kernel-next
echo "installed /usr/local/bin/iou-kernel-next"

echo '===== 2. SEED STATE WITH THE CURRENTLY-LIVE COMMIT (avoid a needless rebuild) ====='
install -d -o iou-ai -g iou-ai -m 0700 "$STATE" 2>/dev/null || install -d "$STATE"
echo "$CURRENT_COMMIT" > "$STATE/kernel-next.commit"
echo "seeded $STATE/kernel-next.commit = $CURRENT_COMMIT"

echo '===== 3. INSTALL SYSTEMD SERVICE + TIMER (daily; acts only on change) ====='
cat > /etc/systemd/system/iou-kernel-next.service <<'EOU'
[Unit]
Description=io_uring guest-kernel-next tracker (fetch/build/validate/rotate)
ConditionPathExists=!/var/lib/iou-ai/runtime/KERNEL_NEXT_DISABLED

[Service]
Type=oneshot
User=root
ExecStart=/usr/local/bin/iou-kernel-next
Nice=15
IOSchedulingClass=idle
TimeoutStartSec=45min
EOU
cat > /etc/systemd/system/iou-kernel-next.timer <<'EOU'
[Unit]
Description=Daily check for a newer io_uring-next kernel (rebuild+rotate only if advanced)

[Timer]
OnCalendar=*-*-* 05:30:00
RandomizedDelaySec=30m
Persistent=true
Unit=iou-kernel-next.service

[Install]
WantedBy=timers.target
EOU
systemctl daemon-reload
systemctl enable --now iou-kernel-next.timer
echo "timer enabled:"
systemctl list-timers iou-kernel-next.timer --no-pager | head -3

echo '===== DONE ====='
echo "The guest kernel now tracks io_uring-next automatically: a daily check that"
echo "rebuilds + validates + rotates ONLY when the branch advances, rolls back on"
echo "any failure, and texts you the outcome. Disable anytime with:"
echo "  sudo touch /var/lib/iou-ai/runtime/KERNEL_NEXT_DISABLED"
