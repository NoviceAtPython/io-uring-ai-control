# io-uring-ai-control

**A fail-closed, AI-guided control plane for coverage-guided fuzzing of the Linux
`io_uring` subsystem.**

An LLM reads new `io_uring` patches from LKML, writes fuzzing programs targeting
the changed logic, an independent model reviews them, a deterministic compiler
turns them into bytes under a hash-pinned contract, an isolated Nyx VM proves each
one safe, a signed approval (human *or* the machine's own policy) authorizes it,
and a promoter feeds it to a live AFL++/Nyx fuzzing fleet — every stage
re-verifying the whole authority chain and failing closed.

> Authorized defensive security research. Any confirmed memory-safety finding is
> routed to the upstream maintainers through coordinated disclosure. LLM output is
> treated as data, never executed — it is only validated into bytes that run
> inside sandboxed VMs.

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
  `operator:auto-v1` (unattended policy) — so the audit trail never conflates a
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
