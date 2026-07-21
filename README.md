# io-uring AI control plane

Fail-closed, shadow-only planner/reviewer control plane for the U-M io_uring
fuzzing campaign.

The deployed design has three independent cost stops: provider hard limits,
per-provider call quotas, and a local UTC calendar-month SQLite ledger. Model
output is strict semantic JSON. It is deterministically validated and retained
only in quarantine. Release 0.1.16 installs a semantic-only production contract
for the exact audited source and live ELF; it withholds all raw operands. An
inert local codec now round-trips canonical vectors for all 61 operations and
binds the four source-order ambiguities to that exact ELF hash. The production
compiler remains disabled until reviewed templates, artifact-bound approval,
and the isolated AFL/Nyx canary are complete.

Provider calls are single-attempt and never automatically retried. Each has a
bounded five-minute response window; timeouts and pre-response connection
failures are reported separately without logging provider-controlled details.
Anthropic structured-output requests use a flattened portable schema, while
the complete strict schema is still enforced locally after every response.

Gate A accepts only analysis-only research priorities while the compiler is
disabled. These priorities may identify unordered operation families, profiles,
lanes, evidence, and expected signals. They cannot contain programs, operation
ordering, operands, resources, grammar, seeds, or host actions.

The initial activation enables only public LKML intake and a read-only exporter
of allowlisted numeric AFL++ statistics. It does not stop, signal, reconfigure,
or write to the live AFL/Nyx fleet, and it does not enable the AI shadow timer.
Syzkaller is not part of this design; the existing AFL++/Nyx harness remains the
only execution engine.

Release 0.1.16 also includes a no-network event projector. It verifies immutable
quarantine envelopes, the local budget ledger, and sanitized crash/hang counters,
then emits strict redacted events into a create-only outbox. Approval challenges
expire and can authorize only offline validation; they cannot compile, execute,
enqueue, promote, or change the fleet. A high-value security alert is permitted
only for a future local classifier that has reproduced a kernel memory-safety
failure at least twice. A counter increase alone is always labelled untriaged.
The projector timer is installed but remains disabled until the notification relay is
ready, preventing short-lived approval codes from expiring before delivery.
Each notification pass reports only redacted disposition counters (seen,
delivered, already delivered/rejected/expired, newly expired, and failed), so
an idempotent skip can be diagnosed without exposing event bodies or credentials.
If notification delivery misses the first approval window, the projector may issue
exactly one fresh challenge for the same immutable envelope; further automatic
reissues are prohibited.

Claude reviewer outcomes now return to the next OpenAI planner cycle through a
lossy content-addressed feedback boundary. Only verdict/risk/finding enums,
evidence identifiers, and target/proposal hashes survive; provider prose and raw
artifacts do not. Rejected or escalated work remains ineligible for quarantine.

Human notification is intentionally separate from model execution. The checked-
in relay client can register only redacted fixed-template events at one exact
HTTPS endpoint and retains immutable receipts. In Telegram host-delivery mode,
the isolated Michigan notifier sends that same fixed text directly after the
relay has durably registered its approval binding; Approve/Deny callbacks still
terminate at the Cloudflare relay and return as signed decision bundles. An
optional Telnyx provider remains available. No destination, bot token, or chat
identifier belongs in source control or logs.

The installer creates two additional unprivileged accounts and installs their
units disabled. `iou-ai-notify` is the only notification-path component with network
access; it can read the redacted event outbox, store delivery receipts, and place
relay-signed bundles in the decision inbox. `iou-ai-decision` has no network and
can only verify those bundles against redacted event bindings and append them to
the decision archive. Neither account can read model credentials, quarantine,
contracts, controller runtime state, compiler artifacts, or fleet paths.

The notification timers remain disabled unless an operator separately configures
the external relay. For Telegram, after deployment and a user-initiated private
bot **Start**, `deploy/cloudflare/pair-telegram-locally.ps1` validates exactly
one private sender, creates the singular D1 binding, and installs the
callback-only webhook without printing the chat identifier. The remote
`configure-telegram-relay.sh` then verifies that binding and repeats the no-write
readiness proof; it does not enable a timer or send an event.
`deploy/remote/activate-relay.sh` accepts five staged single-line files outside
this repository—`relay-endpoint`, `relay.token`, `decision.key`,
`telegram-bot.token`, and `telegram-chat.id`—and installs the endpoint as
root-owned `0640` plus four root-only `0600` credentials exposed to services
only through systemd credential directories. Before any timer is enabled, it makes one authenticated
read-only `GET /v1/ready` request to the exact HTTPS relay. The request proves
the staged decision HMAC matches the relay without transmitting that key. The
route cannot submit an event, send a notification, or create a decision. A failed probe
leaves all three relay timers disabled; an already live set is refused instead
of being reconfigured in place. The endpoint contains the exact HTTPS
`/v1/events` URL. The Telegram credential and singular recipient binding are
available only to the sandboxed notifier through systemd credentials and to the
external relay's protected configuration.
Activation of the notification path is intentionally not part of
`activate-readonly.sh`.

The reference Cloudflare relay independently revalidates every fixed-template
event and approval binding, verifies provider callbacks, commits decisions and
replay markers atomically, and retains delivery status. In host mode it marks a
validated event registered before the sandboxed notifier calls Telegram;
Telegram callbacks are accepted only from the
single private chat paired from its `/start` update and with the exact webhook
secret; the pairing route returns no chat identifier and rejects ambiguous
candidate chats. The optional Telnyx path
also enforces a hard 200-message monthly attempt cap and uses final handset
delivery status as its delivery authority.

Local validation:

```text
python -m pytest -q
```

Remote activation, after staging the release and credentials:

```text
sudo sh deploy/remote/activate-readonly.sh
```

Once the independently deployed relay is ready, the Telegram bot has been
started privately, and its five relay files are staged outside the repository,
verify the preconfigured private binding while the timers remain disabled:

```text
sudo sh deploy/remote/configure-telegram-relay.sh
```

Then activate the notification path separately:

```text
sudo sh deploy/remote/activate-relay.sh
```
