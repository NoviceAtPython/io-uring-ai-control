#!/bin/sh
set -eu

# Root-only, read-only snapshot of the exact deployed harness authority. This
# intentionally does not manufacture a production HarnessContract: independent
# extraction and encoder/decode round-trip verification are still required.
if [ "$(id -u)" -ne 0 ]; then
    echo "run with sudo" >&2
    exit 1
fi

WORKSPACE=/root/fuzzer_workspace
DEST=/var/lib/iou-ai/contracts/authority
NATIVE_BINARY=$WORKSPACE/nyx_targets/iou_native_pack
KASAN_BINARY=$WORKSPACE/nyx_targets/iou_native_kasan
HARNESS_CANDIDATES=$(find "$WORKSPACE" -xdev -maxdepth 5 -type f \
    -name io_uring_harness_native.c -print)
HARNESS_COUNT=$(printf '%s\n' "$HARNESS_CANDIDATES" | awk 'NF { count++ } END { print count + 0 }')

if [ "$HARNESS_COUNT" -ne 1 ]; then
    echo "expected exactly one io_uring_harness_native.c under $WORKSPACE; found $HARNESS_COUNT" >&2
    printf '%s\n' "$HARNESS_CANDIDATES" >&2
    exit 1
fi
HARNESS=$HARNESS_CANDIDATES
test -f "$HARNESS"
test -e "$NATIVE_BINARY"
test -e "$KASAN_BINARY"
command -v file >/dev/null
command -v readelf >/dev/null
command -v objdump >/dev/null

# Bind the snapshot to the two files referenced by the live Nyx VMs.  Reading
# process arguments and binaries is observational only; no process is signalled.
NATIVE_REFERENCES=$(ps -C qemu-system-x86 -o args= | awk -v needle="sharedir=$NATIVE_BINARY" \
    'index($0, needle) { count++ } END { print count + 0 }')
KASAN_REFERENCES=$(ps -C qemu-system-x86 -o args= | awk -v needle="sharedir=$KASAN_BINARY" \
    'index($0, needle) { count++ } END { print count + 0 }')
if [ "$NATIVE_REFERENCES" -ne 8 ] || [ "$KASAN_REFERENCES" -ne 2 ]; then
    echo "expected live binary references native=8 kasan=2; found native=$NATIVE_REFERENCES kasan=$KASAN_REFERENCES" >&2
    exit 1
fi

install -d -o root -g iou-ai -m 0750 "$DEST"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
install -o root -g iou-ai -m 0640 "$HARNESS" "$DEST/io_uring_harness_native.$STAMP.c"
sha256sum "$DEST/io_uring_harness_native.$STAMP.c" > "$DEST/io_uring_harness_native.$STAMP.sha256"

snapshot_target() {
    flavor=$1
    target=$2
    references=$3
    manifest="$DEST/iou_${flavor}.$STAMP.target.sha256"
    inventory="$DEST/iou_${flavor}.$STAMP.target.inventory.txt"

    if [ -f "$target" ]; then
        sha256sum "$target" > "$manifest"
        {
            printf 'authority_path=%s\n' "$target"
            printf 'authority_type=regular-file\n'
            printf 'live_qemu_references=%s\n' "$references"
            printf 'bytes=%s\n' "$(stat -c %s "$target")"
            file "$target"
        } > "$inventory"
        candidates=$target
    elif [ -d "$target" ]; then
        find "$target" -xdev -type f -print0 | sort -z | xargs -0 -r sha256sum > "$manifest"
        {
            printf 'authority_path=%s\n' "$target"
            printf 'authority_type=directory\n'
            printf 'live_qemu_references=%s\n' "$references"
            printf 'bytes=%s\n' "$(du -sb "$target" | awk '{print $1}')"
            find "$target" -xdev -type f -printf '%s\t%P\n' | sort -k2
            printf '\n[file-types]\n'
            find "$target" -xdev -type f -size -64M -exec file {} +
        } > "$inventory"
        # Copy only plausibly relevant target ELFs; the complete content hash
        # and inventory still attest every file without duplicating a rootfs.
        candidates=$(find "$target" -xdev -maxdepth 6 -type f -size -64M \
            \( -name 'iou*' -o -name '*harness*' -o -name 'target' -o -name 'fuzz*' \) \
            -print)
    else
        echo "live target authority is neither a regular file nor directory: $target" >&2
        exit 1
    fi

    candidate_index=0
    printf '%s\n' "$candidates" | while IFS= read -r candidate; do
        test -f "$candidate" || continue
        case $(file -b "$candidate") in
            ELF*) ;;
            *) continue ;;
        esac
        candidate_index=$((candidate_index + 1))
        candidate_label=$(printf '%03d' "$candidate_index")
        snapshot="$DEST/iou_${flavor}.$STAMP.elf${candidate_label}.bin"
        install -o root -g iou-ai -m 0640 "$candidate" "$snapshot"
        sha256sum "$snapshot" > "$DEST/iou_${flavor}.$STAMP.elf${candidate_label}.sha256"
        {
            printf 'authority_path=%s\n' "$candidate"
            printf 'file='; file -b "$snapshot"
            printf '\n[elf-header]\n'; readelf -h "$snapshot"
            printf '\n[notes]\n'; readelf -n "$snapshot"
            printf '\n[compiler-comment]\n'; readelf -p .comment "$snapshot" 2>&1 || true
            printf '\n[objdump-version]\n'; objdump --version | sed -n '1p'
        } > "$DEST/iou_${flavor}.$STAMP.elf${candidate_label}.metadata.txt"
        objdump -drwC --disassemble=main "$snapshot" \
            > "$DEST/iou_${flavor}.$STAMP.elf${candidate_label}.main.objdump.txt"
    done
}

snapshot_target native "$NATIVE_BINARY" "$NATIVE_REFERENCES"
snapshot_target kasan "$KASAN_BINARY" "$KASAN_REFERENCES"

chown root:iou-ai "$DEST"/*".$STAMP."*
chmod 0640 "$DEST"/*".$STAMP."*
echo "snapshotted source plus live native/KASAN target manifests and ELF candidates; production compilation remains disabled"
