# Security policy

## Scope of this project

This is authorized defensive security research: an AI-guided, coverage-guided
fuzzer for the Linux `io_uring` subsystem, run on dedicated hardware. Its purpose
is to find memory-safety and logic defects so they can be fixed. LLM output is
treated as **data, never code** — it is validated into op-script bytes that run
only inside isolated, snapshotted VMs; nothing a model emits is executed on the
host.

## Handling of any finding

Any crash the campaign produces is triaged for reproducibility against a current
kernel before it is treated as a real finding. A confirmed memory-safety issue in
upstream Linux is reported through the kernel's **coordinated disclosure**
process (`security@kernel.org` and the subsystem maintainers), not published as a
surprise. The project does not weaponize findings, does not develop exploits for
offensive use, and does not target third-party systems.

Note: the kernel's own guidance treats AI-assisted findings as effectively public
and stresses a reproducible report on a current kernel. This project follows that
guidance — a raw fuzzer crash is a starting point, not a disclosure.

## Reporting an issue in *this software*

This repository is the control plane and operational tooling, not the kernel
under test. If you find a vulnerability in this code (for example, a way to defeat
the fail-closed authority chain, the budget ledger, or the approval signing),
please open a private report to the maintainer rather than a public issue. The
design intent is that every stage independently re-verifies the full authority
chain and fails closed; a bypass is a real bug and is treated as one.

## Safety properties this codebase is built to preserve

- LLM output is never executed — only validated bytes run, and only in sandboxed
  VMs.
- Every gate re-verifies the immutable authority chain (envelope -> artifact ->
  validation -> canary -> candidate -> target hashes) and refuses on drift.
- Promotion can only ever write one immutable seed into a static allowlisted
  inbox; it cannot reach the general filesystem or the network.
- Approvals are HMAC-signed with distinct human / console / auto signer
  identities, so the audit trail never conflates a machine approval with a human
  one.
- Spend is hard-capped by a ledger with an operator kill switch.
