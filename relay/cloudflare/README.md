# Human-notification relay

This Cloudflare Worker is the only component that knows the delivery-provider
credential and the private recipient binding. It accepts only strict redacted
controller events, recomputes their SHA-256 and fixed notification text, and
delivers them through exactly one configured provider. No phone number, bot
token, chat identifier, or HMAC key belongs in source control or logs.

Telegram is the recommended no-SMS configuration. A private bot chat receives
the fixed redacted alert, and a quarantined proposal carries bound **Approve**
and **Deny** buttons. Telegram callback updates are accepted only when they
carry the configured webhook secret and originate from the one configured
private chat. Telnyx remains an optional SMS provider; its inbound webhooks are
verified over the original body with Ed25519 and a five-minute timestamp window.

Approval creates an HMAC-signed `human-decision.v1` record for
`approve_for_offline_validation`. It does not call the fuzz host and cannot
execute, compile, enqueue, or promote an artifact. The Michigan host polls
`/v1/decisions` and independently verifies every binding before archiving it.
Before enabling its notification timers, the host performs one authenticated
`GET /v1/ready`. The request proves the staged decision HMAC matches the relay
without transmitting that key, then verifies the full relay configuration with
one read-only D1 query; it cannot submit an event, send an SMS, or create a
decision.

Required Cloudflare setup:

1. Create a D1 database and apply `schema.sql`.
2. Copy `wrangler.toml.example` to `wrangler.toml` and insert only the D1 ID.
3. Deploy the Worker and set the selected provider's secrets only in Cloudflare.

For a Telegram relay, set these secrets directly in the dashboard (never in
this repository):

```text
RELAY_PROVIDER=telegram
FUZZ_RELAY_TOKEN
DECISION_HMAC_KEY
TELEGRAM_BOT_TOKEN
TELEGRAM_WEBHOOK_SECRET
```

`TELEGRAM_WEBHOOK_SECRET` must be a fresh, 32-or-more-character URL-safe random
value. The chat identifier is not an environment secret and is never copied out
of Telegram: after the user presses **Start** in the bot's private chat, the
authenticated `POST /v1/telegram/pair` control route uses a one-time HMAC proof
to bind exactly that one private `/start` update in D1. It returns no chat ID,
refuses zero or multiple candidates, and cannot send a Telegram message or
write a decision. Then use the authenticated
`POST /v1/telegram/configure-webhook` route to install
`https://<worker>/webhooks/telegram`. It requests only `callback_query` updates
and cannot create a decision.

For the optional Telnyx SMS relay, set `RELAY_PROVIDER=telnyx` and the six
Telnyx secrets in `wrangler.toml.example`, then configure the Telnyx messaging
profile webhook as `https://<worker>/webhooks/telnyx`.

After the Worker is deployed, stage `relay-endpoint`, `relay.token`, and
`decision.key` as single-line files in a `0700` handoff directory outside this
repository (for example `/home/saedyn/iou-ai-relay-credentials`, each file
`0600`). The endpoint is the exact HTTPS `.../v1/events` Worker URL; the token
and decision key are the same values configured as `FUZZ_RELAY_TOKEN` and
`DECISION_HMAC_KEY`. For Telegram, first press **Start** in the bot's private
chat, then run the root-only `deploy/remote/configure-telegram-relay.sh`. It
performs private pairing, callback-only webhook registration, and a no-write
readiness proof while all relay timers stay disabled. Only after that succeeds
run `deploy/remote/activate-relay.sh`: it copies the values with least privilege,
repeats the authenticated no-write probe, and then enables the three relay
timers. Both scripts refuse live relay timers rather than reconfiguring a live
notification path.

The Worker Free plan is sufficient for this low-volume relay. A Telegram bot can
only message a user after that user has initiated the private chat. US
application-to-person SMS still requires the applicable Telnyx
registration/verification.
