# The fuzzer / client (on the bare-metal host)

The control plane in this repo *steers* a coverage-guided fuzzer that runs on a
dedicated bare-metal Linux host. That fuzzer is host- and hardware-specific and
lives under `/root/fuzzer_workspace` on the machine, not in this repository. This
document describes its design and the interface the AI control plane targets.

## Why bare metal

The stack needs Intel Processor Trace (`intel_pt`) + `vmx` + `/dev/kvm` with
**KVM-Nyx**, a patched KVM that exposes guest PT to the host. Nested
virtualization hides the required MSRs, so a cloud VM cannot run it — it must be
bare metal (an Intel i9-10900 here).

## Stack (top to bottom)

- **Host kernel = KVM-Nyx** — patched KVM (`CONFIG_KVM_NYX=y`) providing Intel-PT
  tracing of the guest. Never changes.
- **QEMU-Nyx (stock)** — boots + snapshots a guest VM; PT decodes coverage.
- **libnyx** — Rust loader that spawns/controls QEMU-Nyx.
- **AFL++** — drives it in Nyx mode (`-Y -M 0` main / `-Y -S k` secondaries).
- **Guest kernel** — the target: a fast (non-KASAN) bzImage for explorers and a
  KASAN bzImage (`kasan.fault=panic`) for detectors, so a memory bug -> guest
  panic -> AFL records a crash.
- **The harness** (`io_uring_harness_native.c`) — a native Nyx-agent that runs
  *inside* the guest. It does the raw Nyx hypercall handshake, sets up `io_uring`
  once before the snapshot (persistent mode), submits the kernel text range for
  PT tracing, then loops: `ACQUIRE -> decode payload into io_uring ops ->
  RELEASE (snapshot reset)`. **This is the program the AI's bytes drive.**

## Fleet

8 fast explorers + 2 KASAN detectors (10 workers), all sharing one corpus via AFL
sync, so detectors replay explorers' finds under KASAN. Durable via
`AFL_AUTORESUME=1` + systemd `Restart=on-failure`; resumes its corpus on reboot.
The main node also ingests AI-promoted seeds via `afl-fuzz -F <inbox>`.

## The op-script byte encoding (what the AI emits)

The fuzzer input is a byte string (<= 2048 B, <= 96 ops) decoded by the harness:

- **byte[0]** = ring selector -> `ring % 8` picks one of 8 `IORING_SETUP_*`
  personalities.
- then, until bytes run out or 96 ops: an **op byte** -> `switch (op % 61)`
  selects the operation -> each op reads its own argument bytes (fd index,
  lengths, flags) -> a **flags byte** sets SQE flags
  (`LINK/DRAIN/ASYNC/HARDLINK/BUFFER_SELECT/FIXED_FILE`) and `buf_group = c >> 4`.

The authoritative table is the `switch (op % NOPS)` in the harness (`NOPS = 61`).
The control plane extracts a hash-pinned **contract** from it and hands that to
both the planner (as the generation spec) and the validator (as the checker). The
AI emits *bytes*, never syzlang. Op groups: 22-34 sockets; 35-40
cancellation/linking; 41-46 fixed I/O; 47-48 msg_ring; 49-52 futex/waitid; 53-58
path/xattr; 60 = raw `io_uring_register()` opcode fuzz.

## Where random mutation saturates — and why the AI lane exists

Width (widening 22 -> 60 ops) broke an early coverage plateau (+63%). Past ~60
ops, more width costs stability without adding coverage. The remaining lever is
**depth** — operation combinations, state, cancellation races, registered-resource
lifecycles — which is exactly what an LLM reading a specific patch can target and
undirected mutation cannot. The AI lane feeds those depth-seeking seeds into the
fleet through the fail-closed pipeline in this repo.

## Landmines (hard-won)

- `SIGPIPE` silently kills the harness (sockets -> send/write); the harness
  ignores it.
- Use **stock** QEMU-Nyx, not a custom "instant snapshot" fork (no
  `-fast_vm_reload`).
- `IORING_SETUP_SQPOLL` destroys coverage stability (async poll thread ->
  nondeterminism); excluded from the ring pool.
- `RANGE_SUBMIT` wants a flat `uint64_t[3] = {start, end, reg}` for the kernel
  text range, not the `kAFL_ranges` struct.
- Measure exec/s over >= 90 s windows; `fuzzer_stats` is written infrequently and
  short samples wildly under-report.

Full living notes are maintained privately by the operator; this is the public
summary needed to understand what the control plane drives.
