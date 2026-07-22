# The guest harness

`io_uring_harness_native.c` is the fuzzing agent that runs **inside the guest
kernel** under Nyx. It is the concrete target the whole control plane is built
around: the AI's proposals are validated into the exact byte grammar this program
decodes.

It is included here as the reference artifact of the fuzzer/client. It is **not
built by this repository** — it compiles on the host against the Nyx hypercall
headers (`nyx.h`) and a static `liburing`, and runs in the snapshotted guest, not
on any normal machine. See [`../docs/FUZZER.md`](../docs/FUZZER.md) for the stack
it runs in.

## What it does

- Speaks the raw Nyx hypercall API: one-time `io_uring` setup **before** the
  snapshot, then a persistent loop where each iteration only submits fuzzed
  operations and resets to the snapshot (no per-iteration setup — this is the
  ~30× speedup over a naive reset-per-exec harness).
- Submits the **kernel text range** for Intel-PT, so coverage measures `io_uring`
  kernel paths, not the userspace harness.
- Decodes an input byte stream into up to 96 operations across **61 operation
  cases** and **8 `IORING_SETUP_*` ring personalities**, covering sockets,
  cancellation/linking, `msg_ring`, registered files/buffers (fixed I/O), futex,
  waitid, path/xattr, multishot, and the full `io_uring_register()` opcode surface.

## Why the design choices in the comments matter

The comments record real, measured findings from tuning this to a sustained
high-throughput campaign — e.g. `SQPOLL` is deliberately excluded because its
async kernel poll thread makes identical inputs produce different coverage
(stability 30% → 14% for ~2% more edges), and `SIGPIPE` is ignored because
socket/pipe sends can otherwise kill the harness silently. That history is
documented in [`../docs/METRICS.md`](../docs/METRICS.md).

## Relationship to the control plane

The exact operand read order and the 61-case op table are mirrored, byte-for-byte,
by [`../src/iou_ai/harness_codec.py`](../src/iou_ai/harness_codec.py) (the audited
codec) and enforced by the compiler's hash-pinned contract. That is what lets the
AI target this harness precisely while never producing anything that executes: the
model emits typed proposals, the validator turns them into exactly these bytes,
and only bytes ever reach the VM.
