# Research context

This is an **ongoing research project**: a working architecture for putting a large
language model *inside* a kernel-fuzzing loop without letting the model's output
ever execute, and an open experiment into whether AI-directed, patch-targeted
seeding finds defects that undirected mutation does not.

It is presented honestly. The **architecture** is the contribution that stands on
its own. Whether it beats a non-AI baseline on a heavily-fuzzed target is the
**open question the system is running to answer** — not a claim being made.

## The problem

Coverage-guided fuzzers (AFL++, syzkaller) are extraordinarily good at breadth but
structurally weak at *depth*: the specific multi-step, stateful sequences where
modern `io_uring` memory-safety bugs live — a resource freed or unregistered while
an asynchronous request that references it is still in flight. LLMs are good at
proposing exactly those structured sequences from a natural-language patch, but
letting a model generate code that runs against a kernel is an obvious security
and safety hazard.

## What is novel here

1. **A hard trust boundary: model output is data, never code.** The LLM emits a
   typed, inert proposal. A deterministic validator compiles it to op-script bytes
   against a *hash-pinned harness contract*; nothing the model produces is ever
   executed — only validated bytes run, and only inside isolated snapshot VMs. If
   the harness, compiler, or op-table drifts by a single byte, the pipeline fails
   closed. This is a general pattern for safely using untrusted model output in a
   privileged system, demonstrated end to end.

2. **Signed, attributable, autonomous promotion.** The system can approve and
   promote its own fuzzing seeds to a live fleet with no human in the loop — but
   every decision is HMAC-signed with a *distinct* signer identity
   (`relay:telegram-v1` human, `operator:local-v1` console, `operator:auto-v1`
   policy), and every stage independently re-verifies the full authority chain
   (envelope → artifact → validation → canary → candidate → target hashes). The
   audit trail can never confuse a machine approval for a human one. This is an
   operational-security model for autonomous AI agents, not just a fuzzer feature.

3. **Fresh-code, patch-targeted fuzzing that maintains itself.** The guest kernel
   auto-tracks the newest `io_uring-next` development branch: a daily check
   rebuilds, validates boot in an isolated VM, and rotates the live fleet with
   backup and automatic rollback — only when the branch advances. The fuzzer is
   always pointed at this-week's code, where the odds of an undiscovered defect are
   highest.

4. **Bounded, hands-off autonomy.** The paid model calls are governed by a SQLite
   budget ledger with worst-case pre-reservation and hard daily/monthly caps; the
   whole system runs on systemd timers with per-lane kill switches and alerts for
   crashes, fleet health, provider funds, and failed kernel updates.

## The open experiment

The measurable question — deliberately not yet claimed as answered — is whether
AI-directed seeds produce **coverage or reproducible findings beyond the non-AI
baseline** on the same target and hardware. The honest current state:

- The full loop works and has run unattended end to end.
- The fuzzer is saturated on old, stable code (0 crashes in ~11.4B executions) —
  the expected base case for a subsystem syzbot has fuzzed for years — which is
  precisely why the design pivots to fresh code and structured depth.
- Whether the AI lane's seeds add live-fleet coverage is instrumented but **not
  yet demonstrated**. That is the next result to report, positive or negative.

A negative result would still be a result: evidence about the limits of
LLM-directed fuzzing on a mature target. A positive result would be evidence for a
genuinely more efficient, AI-guided fuzzing architecture. Either way the safety
architecture — untrusted model output confined behind a deterministic, fail-closed
boundary — is reusable well beyond fuzzing.

## Reproducibility and honesty commitments

- Every claim in this repository is CI-verified or explicitly marked as an open
  question. No fabricated crashes, coverage numbers, or "AI beat baseline" results.
- Any confirmed kernel memory-safety finding is handled through coordinated
  disclosure ([`../SECURITY.md`](../SECURITY.md)); AI-assisted findings are treated
  as effectively public, per kernel guidance.
- The control plane is public and testable; the host-specific fuzzer engine is
  documented in [`FUZZER.md`](FUZZER.md) and its performance history in
  [`METRICS.md`](METRICS.md).
