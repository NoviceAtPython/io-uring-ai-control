# Performance engineering log

The fuzzer this control plane drives was tuned from a naive baseline to a
sustained high-throughput campaign. This log records the real progression and the
diagnosis behind each jump — it is the honest engineering history, not a
benchmark sheet. Throughput is measured over >= 90 s windows (short samples of
`fuzzer_stats` badly under-report; see the measurement landmine in
[`FUZZER.md`](FUZZER.md)).

| Stage | Exec/s | Coverage (edges) | What changed / what was wrong |
|---|---:|---:|---|
| Classic syzkaller + KCOV | ~550 | — | Baseline. Abandoned for snapshot fuzzing. |
| Nyx hello-world, 1 worker | ~10,000 | — | Proved the KVM-Nyx -> QEMU-Nyx -> libnyx -> AFL++ stack. |
| Nyx hello-world, 8 workers | ~58,000 | — | Linear-ish scaling across cores. |
| io_uring, ld_preload + KASAN | ~705 | 163 | **Bug: was tracing the userspace harness, not the kernel.** |
| Native persistent harness, 1 worker | ~4,780 | 4,782 | Submit the *kernel* text range for PT -> real kernel coverage (163 -> 4,782). |
| 3-hour soak | 18k -> 2.3k decay | ~5,596 plateau | **Bug: input bloat** — unbounded inputs slowed every iteration. |
| Re-optimized (cap + cmin + DEFER_TASKRUN) | ~19,000 sustained | — | Stability 6% -> 48%; decay eliminated. |
| Overnight 10.8 h | ~20,000 | +68 only | **Saturated at 22 ops ≈ 34% of the op surface.** |
| v2 widen (22 -> 60 ops) | ~20,000 | 9,107 (**+63%**) | Width broke the plateau. Also fixed a silent `SIGPIPE` kill. |
| v3 (ring-config pool + register surface) | ~22,000 | 9,305 | But stability crashed to 14% — over-widened. |
| **v3.1 (current) — drop SQPOLL** | **~24,000–31,000** | **~10,300** | Best on all three axes. ~29% stability (async io_uring floor). |

**Current campaign:** 10 workers (8 fast explorers + 2 KASAN detectors),
~11.4 billion executions, ~10,300 edges, **0 crashes**, reboot-proof.

## The lesson that motivates the AI lane

Width was the answer from 22 -> 60 ops (+63% coverage). Past ~60 ops it stops
paying — +2% coverage for half the stability. Coverage has since been flat for
days: the surface reachable by undirected mutation is **saturated**. Zero crashes
in ~11.4 billion executions is consistent with that — `io_uring` has been fuzzed
continuously by syzbot for years, and the shallow surface is picked clean.

The remaining lever is **depth**: specific operation sequences, state, cancellation
races, and registered-resource lifecycles that random mutation will not assemble
on its own. That is exactly what an LLM reading a specific new patch can target —
and it is the entire reason for the control plane in this repository. The AI lane
is not expected to beat mutation on the saturated surface; its edge is the window
right after new `io_uring` code lands, before the wider ecosystem catches up.

## Honest status

This is a running research campaign, not a results claim. No vulnerabilities have
been found to date, which for a mature subsystem is the expected base case. The
open, measurable question — tracked but not yet answered — is whether AI-directed
seeds add coverage or reproducible findings beyond the non-AI baseline. Any
confirmed memory-safety finding would go upstream via coordinated disclosure (see
[`../SECURITY.md`](../SECURITY.md)).
