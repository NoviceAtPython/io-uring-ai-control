# io-uring-ai-control

**A fail-closed, AI-guided control plane for coverage-guided fuzzing of the Linux
`io_uring` subsystem.**

[![CI](https://github.com/NoviceAtPython/io-uring-ai-control/actions/workflows/ci.yml/badge.svg)](https://github.com/NoviceAtPython/io-uring-ai-control/actions/workflows/ci.yml)
[![License: PolyForm NC 1.0.0](https://img.shields.io/badge/license-PolyForm%20Noncommercial%201.0.0-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)
![Tests](https://img.shields.io/badge/tests-211%20passing-brightgreen.svg)

An LLM reads new `io_uring` patches from LKML, writes fuzzing programs targeting
the changed logic, an independent model reviews them, a deterministic compiler
turns them into bytes under a hash-pinned contract, an isolated Nyx VM proves each
one safe, a signed approval (human *or* the machine's own policy) authorizes it,
and a promoter feeds it to a live AFL++/Nyx fuzzing fleet — every stage
re-verifying the whole authority chain and failing closed.

> Authorized defensive security research. Any confirmed memory-safety finding is
> routed to the upstream maintainers through coordinated disclosure ([`SECURITY.md`](SECURITY.md)).
> LLM output is treated as data. Never executed, it is only validated into bytes
> that run inside sandboxed VMs.

**Ongoing research project.** The novel part is the architecture, which is to say a hard,
fail-closed boundary that lets an LLM steer kernel fuzzing without its output ever
executing; and an open experiment into whether AI-directed, patch-targeted seeding
beats undirected mutation on fresh code. See [`docs/RESEARCH.md`](docs/RESEARCH.md)
for the framing, what's novel, and the honest open question.

## Pipeline at a glance

```mermaid
flowchart LR
    LKML[LKML io_uring patch] --> P[Planner LLM]
    P --> R[Independent reviewer]
    R --> A[Sampled auditor]
    A --> C[Deterministic compiler<br/>hash-pinned contract]
    C --> Q[Quarantine]
    Q --> K[Isolated Nyx canary<br/>throwaway VM]
    K --> S[Signed approval<br/>human / console / auto]
    S --> PR[Promoter]
    PR --> F[Live AFL++/Nyx fleet<br/>foreign-sync inbox]
    style K fill:#2d6,stroke:#161,color:#000
    style S fill:#fd6,stroke:#a80,color:#000
    style C fill:#6cf,stroke:#048,color:#000
```

Every arrow crosses a gate that independently re-verifies the immutable authority
chain and **fails closed** on any drift. LLM output never executes on the host —
only validated bytes run, and only inside the isolated VMs.

## Project status

A **running research campaign**, honestly reported.

- Fuzzer: 10 workers, ~24k–31k exec/s, KASAN-armed, **0 crashes to date**
  (expected for a heavily-fuzzed subsystem — see [`docs/METRICS.md`](docs/METRICS.md)).
- **Targets fresh code:** the guest kernel tracks the newest `io_uring-next` dev
  branch and auto-updates — a daily check rebuilds, validates boot in an isolated
  VM, and rotates the fleet with backup + rollback, only when the branch advances.
- Control plane: the full pipeline runs unattended and has closed the loop
  end-to-end (AI-authored seed -> canary -> auto approval -> promotion, no human);
  the planner is steered toward async completion-ordering and resource-lifecycle
  shapes (where io_uring memory-safety defects concentrate).
- Open, measurable question: whether AI-directed seeds add coverage or
  reproducible findings beyond the non-AI baseline. Tracked; not yet answered.

The value on display here is the **engineering and safety architecture**, verified
by CI. The bug hunt is a standing, fresh-code, patch-targeted shot.

## Quick start (control plane, no fuzzer needed)

The control plane is pure Python and runs anywhere; the fuzzer/client it drives is
host-specific and **not** bundled (see [`docs/FUZZER.md`](docs/FUZZER.md)).

```bash
git clone https://github.com/NoviceAtPython/io-uring-ai-control
cd io-uring-ai-control
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e . pytest
python -m pytest -q                                # 211 tests + 7 subtests
```

A fresh checkout does **nothing** on its own: with no config, no credentials, and
no harness contract, every entry point fails closed rather than fuzzing or
spending API budget. Host deployment (`deploy/remote/`) is a separate, deliberate
step that provisions users, state directories, and systemd units but enables no
timers and never touches a fuzzer.

---

## Architecture — four layers

This repository is the **orchestration + API + operations** of the system. The
**fuzzer/client** it steers runs on a dedicated bare-metal host (see below).

```
                          +-------------------------------------------+
   LKML io_uring feed --->|  CONTROL PLANE  (Python, src/iou_ai/)      |
                          |  scrape . plan . review . audit . compile  |
                          |  quarantine . canary . approve . promote   |
                          +---------------+---------------+------------+
                                          |               |
        +---------------------------------+               +-------------------+
        v                                                                     v
+---------------------------+                        +----------------------------+
|  API INTEGRATION          |   -- planning ------>  |  FUZZER / CLIENT  (on host) |
|  src/iou_ai/providers/    |                        |  C harness (61 io_uring ops)|
|    openai.py, anthropic.py|   -- approvals ----->  |  AFL++ . QEMU-Nyx . KVM-Nyx |
|  relay/cloudflare/ Worker |                        |  Intel-PT coverage, 10 wkrs |
|    Telegram/SMS, HMAC, D1  |   -- alerts ------->  |  foreign-sync inbox (afl -F)|
+---------------------------+                        +----------------------------+
        ^                                                                     ^
        +----------------- DEPLOY + MONITORING (Bash + systemd) --------------+
             deploy/remote/ . deploy/systemd/ . deploy/monitoring/
```

### 1. Control plane — Python (`src/iou_ai/`)
The orchestration and every security gate. Pure Python, no ambient trust:
`lkml`, `pipeline`, `prompts`, `validator`, `compiler`, `quarantine`, `canary`,
`decisions`, `promoter`, `execution`, `budget`, `contract`. Each stage
independently re-verifies the immutable authority chain (envelope -> artifact ->
validation -> canary -> candidate -> target hashes) and fails closed.

### 2. API integration — Python adapters + a Cloudflare Worker
This is the custom API surface:
- **`src/iou_ai/providers/`** — hardened adapters for the OpenAI and Anthropic
  APIs: strict model allowlists, request shaping, refusal detection, and error
  handling that surfaces the *structural* cause of a provider 4xx **without ever
  logging provider prose** (it matches an allowlist of parameter names, never
  copies the message). A provider-failover chain keeps the planner alive when one
  vendor's policy filter declines a kernel-fuzzing prompt.
- **`relay/cloudflare/`** — a Cloudflare Worker exposing a two-way approval API:
  signed challenges out (Telegram/SMS), HMAC-verified decisions back, stored in
  D1, polled by cursor. (One-way crash alerts skip the relay and hit
  `api.telegram.org` directly — see `deploy/monitoring/`.)

### 3. Fuzzer / client — C + Bash, on the bare-metal host
The thing being *driven*. A native Nyx-agent harness
(`io_uring_harness_native.c`, ~61 ops, persistent-mode) runs inside a snapshotted
guest kernel; AFL++ drives it in Nyx mode with Intel-PT coverage across 10
workers (8 fast explorers + 2 KASAN detectors). This lives under
`/root/fuzzer_workspace` on the host, not in this repo — it is
hardware-and-host-specific (KVM-Nyx substrate, pinned QEMU-Nyx, guest bzImages).
See [`docs/FUZZER.md`](docs/FUZZER.md) for its full design, the op-script byte
encoding the AI targets, and the hard-won landmines.

### 4. Deploy + monitoring — Bash + systemd
- **`deploy/remote/`** — versioned, immutable-release installer/activator; the
  isolated Nyx canary runner; the unattended `canary -> auto-approve -> promote`
  cycle.
- **`deploy/systemd/`** — every unit is offline-by-default, budget/kill-switch
  gated, and least-privilege (see `tests/test_systemd_isolation.py`).
- **`deploy/monitoring/`** — `iou-status` (one-shot dashboard), `iou-alert`
  (one-way Telegram), `iou-crashwatch` (grades crashes; "gold" = kernel
  memory-safety; pages only on sustained AI-lane failure).

---

## Safety model

- **LLM output is data, never code.** The validator sanitizes every proposal to
  op-script bytes against a hash-pinned harness contract; nothing the model emits
  is executed, only bytes that run in throwaway VMs.
- **Fail-closed everywhere.** Each gate re-verifies the full authority chain and
  refuses on any drift. The promoter can only ever write one immutable seed into
  a static allowlisted foreign-sync inbox.
- **Signed, attributable approvals.** Decisions are HMAC-signed with distinct
  signer identities — `relay:telegram-v1` (phone), `operator:local-v1` (console),
  `operator:auto-v1` (unattended policy) so the audit trail never conflates a
  human approval with a machine one.
- **Bounded spend.** A SQLite ledger reserves worst-case cost before each call and
  hard-caps daily/monthly spend, with an operator kill switch.

## Tests

```
python -m venv .venv && .venv/bin/pip install -e . pytest
python -m pytest
```

210+ tests, including the fail-closed authority checks, provider allowlists and
error redaction, decision signing/verification, and systemd isolation invariants.

## Third-party components

The fuzzer/client integrates AFL++, QEMU-Nyx / libnyx / KVM-Nyx, and `liburing`,
each under its own license (AFL++ is AGPL-3.0). Those are **not** vendored here;
this repository is the original control-plane, API, and operational code.

## License

**PolyForm Noncommercial 1.0.0** — see [`LICENSE`](LICENSE). The source is public
for research, study, and any noncommercial use. Commercial use requires a separate
license from the copyright holder.
