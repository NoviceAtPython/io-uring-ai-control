import assert from "node:assert/strict";
import {
  timingSafeEqual as nodeTimingSafeEqual,
  webcrypto,
} from "node:crypto";

import worker, { canonical, renderEvent } from "./src/index.js";

if (!globalThis.crypto) globalThis.crypto = webcrypto;
// Cloudflare exposes this extension on SubtleCrypto. Node does not, so mirror
// the runtime primitive for local integration tests.
if (typeof crypto.subtle.timingSafeEqual !== "function") {
  Object.defineProperty(crypto.subtle, "timingSafeEqual", {
    configurable: true,
    value(left, right) {
      const a = Buffer.from(left);
      const b = Buffer.from(right);
      return a.byteLength === b.byteLength && nodeTimingSafeEqual(a, b);
    },
  });
}

const encoder = new TextEncoder();
const RELAY_TOKEN = "relay-token-for-local-tests-only-000000000000";
const HMAC_KEY = "decision-hmac-for-local-tests-only-000000000";
const FROM = "+15550001001";
const TO = "+15550001002";
const TELEGRAM_TOKEN = "123456789:telegram_bot_token_for_local_tests_only_000";
const TELEGRAM_CHAT_ID = "987654321";
const TELEGRAM_WEBHOOK_SECRET = "telegram_webhook_secret_for_local_tests_000000000";

function normalizeSql(sql) {
  return sql.replace(/\s+/g, " ").trim().toLowerCase();
}

function changes(count) {
  return { meta: { changes: count } };
}

class FakeStatement {
  constructor(db, sql, values = []) {
    this.db = db;
    this.sql = normalizeSql(sql);
    this.values = values;
  }

  bind(...values) {
    return new FakeStatement(this.db, this.sql, values);
  }

  first() {
    return this.db.first(this.sql, this.values);
  }

  all() {
    return this.db.all(this.sql, this.values);
  }

  run() {
    return this.db.run(this.sql, this.values);
  }
}

class FakeD1 {
  constructor() {
    this.events = new Map();
    this.decisions = [];
    this.webhookEvents = new Map();
    this.smsMonthly = new Map();
    this.telegramRecipient = null;
    this.nextDecisionSequence = 1;
    this.failNextBatchAfter = null;
  }

  prepare(sql) {
    return new FakeStatement(this, sql);
  }

  snapshot() {
    return structuredClone({
      events: this.events,
      decisions: this.decisions,
      webhookEvents: this.webhookEvents,
      smsMonthly: this.smsMonthly,
      telegramRecipient: this.telegramRecipient,
      nextDecisionSequence: this.nextDecisionSequence,
    });
  }

  restore(snapshot) {
    this.events = snapshot.events;
    this.decisions = snapshot.decisions;
    this.webhookEvents = snapshot.webhookEvents;
    this.smsMonthly = snapshot.smsMonthly;
    this.telegramRecipient = snapshot.telegramRecipient;
    this.nextDecisionSequence = snapshot.nextDecisionSequence;
  }

  async batch(statements) {
    const snapshot = this.snapshot();
    const failAfter = this.failNextBatchAfter;
    this.failNextBatchAfter = null;
    const results = [];
    try {
      if (failAfter === 0) throw new Error("injected D1 batch failure");
      for (const statement of statements) {
        results.push(await statement.run());
        if (failAfter === results.length) throw new Error("injected D1 batch failure");
      }
      return results;
    } catch (error) {
      this.restore(snapshot);
      throw error;
    }
  }

  async first(sql, values) {
    if (sql.startsWith("select 1 as ready")) return { ready: 1 };
    if (sql.startsWith("select event_json, telnyx_message_id, telnyx_final_status, delivery_state from events")) {
      const row = this.events.get(values[0]);
      return row ? structuredClone(row) : null;
    }
    if (sql.startsWith("select attempted_count from sms_monthly")) {
      const attemptedCount = this.smsMonthly.get(values[0]);
      return attemptedCount === undefined ? null : { attempted_count: attemptedCount };
    }
    if (sql.startsWith("select chat_id from telegram_recipient where singleton = 1")) {
      return this.telegramRecipient ? { chat_id: this.telegramRecipient } : null;
    }
    if (sql.startsWith("select webhook_id from webhook_events")) {
      const row = this.webhookEvents.get(values[0]);
      return row ? structuredClone(row) : null;
    }
    if (sql.startsWith("select event_digest,event_json,expires_at,state from events where human_code")) {
      for (const row of this.events.values()) {
        if (row.human_code === values[0]) return structuredClone(row);
      }
      return null;
    }
    throw new Error(`unsupported D1 first(): ${sql}`);
  }

  async all(sql, values) {
    if (sql.startsWith("select sequence,signed_json from decisions")) {
      return {
        results: this.decisions
          .filter((row) => row.sequence > values[0])
          .sort((left, right) => left.sequence - right.sequence)
          .slice(0, 100)
          .map((row) => structuredClone(row)),
      };
    }
    throw new Error(`unsupported D1 all(): ${sql}`);
  }

  async run(sql, values) {
    if (sql.startsWith("insert into events(")) {
      const [eventDigest, eventJson, humanCode, expiresAt, state, deliveryState, createdAt] = values;
      if (this.events.has(eventDigest)) throw new Error("UNIQUE events.event_digest");
      if (humanCode && [...this.events.values()].some((row) => row.human_code === humanCode)) {
        throw new Error("UNIQUE events.human_code");
      }
      this.events.set(eventDigest, {
        event_digest: eventDigest,
        event_json: eventJson,
        human_code: humanCode,
        expires_at: expiresAt,
        state,
        delivery_state: deliveryState,
        delivery_claimed_at: null,
        telnyx_message_id: null,
        telnyx_final_status: null,
        created_at: createdAt,
      });
      return changes(1);
    }
    if (sql.startsWith("update events set telnyx_message_id = ?, delivery_state = 'accepted'") && sql.includes("delivery_state = 'pending'")) {
      const [messageId, eventDigest] = values;
      const row = this.events.get(eventDigest);
      if (!row || row.delivery_state !== "pending") return changes(0);
      row.telnyx_message_id = messageId;
      row.delivery_state = "accepted";
      return changes(1);
    }
    if (sql.startsWith("update events set delivery_state = 'claimed'")) {
      const [claimedAt, eventDigest] = values;
      const row = this.events.get(eventDigest);
      if (!row || row.delivery_state !== "pending") return changes(0);
      row.delivery_state = "claimed";
      row.delivery_claimed_at = claimedAt;
      return changes(1);
    }
    if (sql.startsWith("insert into sms_monthly(")) {
      const [month, limit = 200] = values;
      const current = this.smsMonthly.get(month) || 0;
      if (current >= limit) return changes(0);
      const next = current + 1;
      if (next > 200) throw new Error("CHECK sms_monthly attempted_count");
      this.smsMonthly.set(month, next);
      return changes(1);
    }
    if (sql.startsWith("update events set delivery_state = ?, delivery_claimed_at = null")) {
      const [deliveryState, eventDigest] = values;
      const row = this.events.get(eventDigest);
      if (!row || row.delivery_state !== "claimed") return changes(0);
      row.delivery_state = deliveryState;
      row.delivery_claimed_at = null;
      return changes(1);
    }
    if (sql.startsWith("update events set delivery_state = 'pending', delivery_claimed_at = null")) {
      const row = this.events.get(values[0]);
      if (!row || row.delivery_state !== "claimed") return changes(0);
      row.delivery_state = "pending";
      row.delivery_claimed_at = null;
      return changes(1);
    }
    if (sql.startsWith("update events set delivery_state = 'failed', delivery_claimed_at = null, telnyx_final_status = 'provider_rejected'")) {
      const row = this.events.get(values[0]);
      if (!row || row.delivery_state !== "claimed") return changes(0);
      row.delivery_state = "failed";
      row.delivery_claimed_at = null;
      row.telnyx_final_status = "provider_rejected";
      return changes(1);
    }
    if (sql.startsWith("update events set delivery_state = 'failed', delivery_claimed_at = null, telnyx_final_status = ?")) {
      const [finalStatus, eventDigest] = values;
      const row = this.events.get(eventDigest);
      if (!row || row.delivery_state !== "claimed") return changes(0);
      row.delivery_state = "failed";
      row.delivery_claimed_at = null;
      row.telnyx_final_status = finalStatus;
      return changes(1);
    }
    if (sql.startsWith("update events set telnyx_message_id = ?, delivery_state = 'accepted'")) {
      const [messageId, eventDigest] = values;
      const row = this.events.get(eventDigest);
      if (!row || row.delivery_state !== "claimed") return changes(0);
      row.telnyx_message_id = messageId;
      row.delivery_state = "accepted";
      return changes(1);
    }
    if (sql.startsWith("insert into webhook_events(")) {
      const [webhookId, processedAt] = values;
      if (this.webhookEvents.has(webhookId)) throw new Error("UNIQUE webhook_events.webhook_id");
      this.webhookEvents.set(webhookId, { webhook_id: webhookId, processed_at: processedAt });
      return changes(1);
    }
    if (sql.startsWith("insert into telegram_recipient(singleton,chat_id,paired_at) values(1,?,?)")) {
      const [chatId] = values;
      if (this.telegramRecipient) throw new Error("UNIQUE telegram_recipient.singleton");
      this.telegramRecipient = chatId;
      return changes(1);
    }
    if (sql.startsWith("insert or ignore into webhook_events(")) {
      const [webhookId, processedAt] = values;
      if (this.webhookEvents.has(webhookId)) return changes(0);
      this.webhookEvents.set(webhookId, { webhook_id: webhookId, processed_at: processedAt });
      return changes(1);
    }
    if (sql.startsWith("insert into decisions(")) {
      const [decisionDigest, eventDigest, signedJson, createdAt] = values;
      if (this.decisions.some((row) => row.decision_digest === decisionDigest || row.event_digest === eventDigest)) {
        throw new Error("UNIQUE decisions");
      }
      this.decisions.push({
        sequence: this.nextDecisionSequence++,
        decision_digest: decisionDigest,
        event_digest: eventDigest,
        signed_json: signedJson,
        created_at: createdAt,
      });
      return changes(1);
    }
    if (sql.startsWith("update events set state = 'decided'")) {
      const row = this.events.get(values[0]);
      if (!row || row.state !== "pending") return changes(0);
      row.state = "decided";
      return changes(1);
    }
    if (sql.startsWith("update events set delivery_state = ?, telnyx_final_status = ? where telnyx_message_id = ?")) {
      const [deliveryState, finalStatus, messageId] = values;
      let count = 0;
      for (const row of this.events.values()) {
        if (row.telnyx_message_id !== messageId) continue;
        row.delivery_state = deliveryState;
        row.telnyx_final_status = finalStatus;
        count += 1;
      }
      return changes(count);
    }
    throw new Error(`unsupported D1 run(): ${sql}`);
  }
}

async function sha256(value) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return Buffer.from(digest).toString("hex");
}

async function hmacHex(secret, value) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return Buffer.from(await crypto.subtle.sign("HMAC", key, encoder.encode(value))).toString("hex");
}

async function proposal(humanCode) {
  const now = Date.now();
  const createdAt = new Date(now - 1000).toISOString();
  const expiresAt = new Date(now + 30 * 60 * 1000).toISOString();
  const envelopeDigest = `sha256:${await sha256(`envelope:${humanCode}`)}`;
  const targetHashes = {
    compiler_hash: `sha256:${"a".repeat(64)}`,
    fleet_config_hash: `sha256:${"b".repeat(64)}`,
    harness_hash: `sha256:${"c".repeat(64)}`,
    op_table_hash: `sha256:${"d".repeat(64)}`,
  };
  const nonce = await sha256(`nonce:${humanCode}`);
  const approvalMaterial = {
    envelope_digest: envelopeDigest,
    expires_at: expiresAt,
    human_code: humanCode,
    nonce,
    target_hashes: targetHashes,
  };
  const event = {
    approval: {
      allowed_actions: ["approve_for_offline_validation", "deny"],
      binding_digest: `sha256:${await sha256(canonical(approvalMaterial))}`,
      expires_at: expiresAt,
      human_code: humanCode,
      nonce,
    },
    created_at: createdAt,
    envelope_digest: envelopeDigest,
    event_kind: "proposal_quarantined",
    proposal_hash: `sha256:${await sha256(`proposal:${humanCode}`)}`,
    schema_version: "redacted-event.v1",
    severity: "action_required",
    target_hashes: targetHashes,
  };
  return event;
}

async function execution(humanCode) {
  const now = Date.now();
  const createdAt = new Date(now - 1000).toISOString();
  const expiresAt = new Date(now + 30 * 60 * 1000).toISOString();
  const targetHashes = {
    compiler_hash: `sha256:${"a".repeat(64)}`,
    fleet_config_hash: `sha256:${"b".repeat(64)}`,
    harness_hash: `sha256:${"c".repeat(64)}`,
    op_table_hash: `sha256:${"d".repeat(64)}`,
  };
  const promotionScope = {
    campaign_id: "campaign:io-uring-native",
    destination_id: "native_ai_sync",
    max_artifacts: 1,
    mode: "afl_foreign_sync_seed",
    schema_version: "promotion-scope.v1",
    worker_set: "native_stable",
  };
  const values = {
    artifact_digest: `sha256:${await sha256(`artifact:${humanCode}`)}`,
    artifact_manifest_digest: `sha256:${await sha256(`manifest:${humanCode}`)}`,
    artifact_size_bytes: 19,
    candidate_digest: `sha256:${await sha256(`candidate:${humanCode}`)}`,
    canary_report_digest: `sha256:${await sha256(`canary:${humanCode}`)}`,
    envelope_digest: `sha256:${await sha256(`envelope:${humanCode}`)}`,
    validation_report_digest: `sha256:${await sha256(`validation:${humanCode}`)}`,
  };
  const nonce = await sha256(`nonce:${humanCode}`);
  const approvalMaterial = {
    artifact_digest: values.artifact_digest,
    artifact_manifest_digest: values.artifact_manifest_digest,
    artifact_size_bytes: values.artifact_size_bytes,
    binding_version: "execution-approval-binding.v1",
    candidate_digest: values.candidate_digest,
    canary_report_digest: values.canary_report_digest,
    envelope_digest: values.envelope_digest,
    event_kind: "execution_ready",
    expires_at: expiresAt,
    human_code: humanCode,
    nonce,
    positive_action: "approve_for_live_execution",
    promotion_scope: promotionScope,
    target_hashes: targetHashes,
    validation_report_digest: values.validation_report_digest,
  };
  return {
    approval: {
      allowed_actions: ["approve_for_live_execution", "deny"],
      binding_digest: `sha256:${await sha256(canonical(approvalMaterial))}`,
      expires_at: expiresAt,
      human_code: humanCode,
      nonce,
    },
    ...values,
    created_at: createdAt,
    event_kind: "execution_ready",
    promotion_scope: promotionScope,
    schema_version: "redacted-event.v2",
    severity: "action_required",
    target_hashes: targetHashes,
  };
}

function budgetEvent(severity) {
  const hardLimit = 7_500_000;
  const threshold = severity === "critical" ? 7_000_000 : 5_000_000;
  const effectiveSpend = threshold + 100_000;
  return {
    created_at: new Date().toISOString(),
    effective_spend_microdollars: effectiveSpend,
    event_kind: "budget_threshold",
    hard_limit_microdollars: hardLimit,
    month: new Date().toISOString().slice(0, 7),
    remaining_microdollars: hardLimit - effectiveSpend,
    schema_version: "redacted-event.v1",
    severity,
    threshold_microdollars: threshold,
  };
}

function highValueTriageEvent() {
  return {
    bug_class: "kasan_use_after_free",
    campaign_id: "native",
    created_at: new Date().toISOString(),
    event_kind: "crash_triage",
    kernel_context_confirmed: true,
    potential_high_value: true,
    reproductions: 2,
    schema_version: "redacted-event.v1",
    severity: "urgent",
    stack_signature: `sha256:${"e".repeat(64)}`,
    target_hashes: {
      compiler_hash: `sha256:${"a".repeat(64)}`,
      fleet_config_hash: `sha256:${"b".repeat(64)}`,
      harness_hash: `sha256:${"c".repeat(64)}`,
      op_table_hash: `sha256:${"d".repeat(64)}`,
    },
    telemetry_packet_digest: `sha256:${"f".repeat(64)}`,
  };
}

async function submission(event) {
  return {
    event,
    event_digest: `sha256:${await sha256(canonical(event))}`,
    fixed_message: renderEvent(event),
    schema_version: "relay-submission.v1",
  };
}

function makeEnv(db, publicKey) {
  return {
    ALERT_TO: TO,
    DB: db,
    DECISION_HMAC_KEY: HMAC_KEY,
    FUZZ_RELAY_TOKEN: RELAY_TOKEN,
    RELAY_PROVIDER: "telnyx",
    TELNYX_API_KEY: "KEY_for_local_tests_only",
    TELNYX_FROM: FROM,
    TELNYX_PUBLIC_KEY: Buffer.from(publicKey).toString("base64"),
  };
}

function makeTelegramEnv(db) {
  return {
    DB: db,
    DECISION_HMAC_KEY: HMAC_KEY,
    FUZZ_RELAY_TOKEN: RELAY_TOKEN,
    RELAY_PROVIDER: "telegram",
    TELEGRAM_BOT_TOKEN: TELEGRAM_TOKEN,
    TELEGRAM_DELIVERY_MODE: "worker",
    TELEGRAM_WEBHOOK_SECRET,
  };
}

async function postEvent(env, value) {
  return worker.fetch(new Request("https://relay.test/v1/events", {
    method: "POST",
    headers: {
      authorization: `Bearer ${RELAY_TOKEN}`,
      "content-type": "application/json",
    },
    body: JSON.stringify(value),
  }), env);
}

async function relayReady(
  env,
  {
    authorization = `Bearer ${RELAY_TOKEN}`,
    decisionKey = HMAC_KEY,
  } = {},
) {
  const nonce = "a".repeat(64);
  const proof = await hmacHex(decisionKey, `relay-ready.v1:${nonce}`);
  return worker.fetch(new Request("https://relay.test/v1/ready", {
    method: "GET",
    headers: {
      authorization,
      "x-iou-relay-nonce": nonce,
      "x-iou-relay-proof": proof,
    },
  }), env);
}

async function signedWebhook(env, privateKey, data) {
  const body = JSON.stringify({ data });
  const timestamp = String(Math.floor(Date.now() / 1000));
  const signature = await crypto.subtle.sign(
    "Ed25519",
    privateKey,
    encoder.encode(`${timestamp}|${body}`),
  );
  return worker.fetch(new Request("https://relay.test/webhooks/telnyx", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "telnyx-signature-ed25519": Buffer.from(signature).toString("base64"),
      "telnyx-timestamp": timestamp,
    },
    body,
  }), env);
}

function receivedData(id, humanCode, command = "APPROVE") {
  return {
    event_type: "message.received",
    id,
    payload: {
      from: { phone_number: TO },
      text: `${command} ${humanCode}`,
      to: [{ phone_number: FROM }],
    },
  };
}

function finalizedData(id, messageId, status, clientState = undefined) {
  const payload = {
    id: messageId,
    to: [{ status }],
  };
  if (clientState !== undefined) payload.client_state = clientState;
  return {
    event_type: "message.finalized",
    id,
    payload,
  };
}

class FakeTelnyx {
  constructor() {
    this.calls = [];
    this.responses = [];
  }

  queue(status, value) {
    this.responses.push({ status, value });
  }

  queueRaw(status, raw) {
    this.responses.push({ raw, status });
  }

  queueError(error = new Error("injected network failure")) {
    this.responses.push({ error });
  }

  async fetch(url, init) {
    assert.equal(url, "https://api.telnyx.com/v2/messages");
    assert.equal(init.method, "POST");
    assert.equal(init.redirect, "error");
    this.calls.push({ url, init });
    const next = this.responses.shift();
    assert.ok(next, "an unexpected Telnyx request would have escaped the test");
    if (next.error) throw next.error;
    return new Response(next.raw ?? JSON.stringify(next.value), { status: next.status });
  }
}

class FakeTelegram {
  constructor() {
    this.calls = [];
    this.responses = [];
  }

  queue(status, value) {
    this.responses.push({ status, value });
  }

  async fetch(url, init) {
    assert.ok(url.startsWith(`https://api.telegram.org/bot${TELEGRAM_TOKEN}/`));
    assert.equal(init.method, "POST");
    assert.equal(init.redirect, "error");
    this.calls.push({ url, init });
    const next = this.responses.shift();
    assert.ok(next, "an unexpected Telegram request would have escaped the test");
    return new Response(JSON.stringify(next.value), { status: next.status });
  }
}

async function telegramWebhook(env, update, { secret = TELEGRAM_WEBHOOK_SECRET } = {}) {
  return worker.fetch(new Request("https://relay.test/webhooks/telegram", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-telegram-bot-api-secret-token": secret,
    },
    body: JSON.stringify(update),
  }), env);
}

function telegramCallback(updateId, humanCode, chatId = Number(TELEGRAM_CHAT_ID), command = "approve") {
  return {
    callback_query: {
      data: `iou-ai:${command}:${humanCode}`,
      id: `callback-${updateId}`,
      message: { chat: { id: chatId } },
    },
    update_id: updateId,
  };
}

function telegramStart(updateId, chatId = Number(TELEGRAM_CHAT_ID)) {
  return {
    message: {
      chat: { id: chatId, type: "private" },
      from: { id: chatId, is_bot: false },
      text: "/start",
    },
    update_id: updateId,
  };
}

async function pairTelegram(env) {
  const nonce = "c".repeat(64);
  const proof = await hmacHex(HMAC_KEY, `telegram-pair.v1:${nonce}`);
  return worker.fetch(new Request("https://relay.test/v1/telegram/pair", {
    method: "POST",
    headers: {
      authorization: `Bearer ${RELAY_TOKEN}`,
      "x-iou-relay-nonce": nonce,
      "x-iou-relay-proof": proof,
    },
  }), env);
}

async function configureTelegram(env) {
  const nonce = "b".repeat(64);
  const proof = await hmacHex(HMAC_KEY, `telegram-webhook.v1:${nonce}`);
  return worker.fetch(new Request("https://relay.test/v1/telegram/configure-webhook", {
    method: "POST",
    headers: {
      authorization: `Bearer ${RELAY_TOKEN}`,
      "x-iou-relay-nonce": nonce,
      "x-iou-relay-proof": proof,
    },
  }), env);
}

const keyPair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
const publicKey = await crypto.subtle.exportKey("raw", keyPair.publicKey);
const telnyx = new FakeTelnyx();
const originalFetch = globalThis.fetch;
globalThis.fetch = telnyx.fetch.bind(telnyx);

const cases = [];
async function test(name, run) {
  await run();
  cases.push(name);
  console.log(`ok - ${name}`);
}

try {
  await test("authenticated readiness is a D1 read that cannot send SMS or create a decision", async () => {
    const db = new FakeD1();
    const env = makeEnv(db, publicKey);
    const callsBefore = telnyx.calls.length;

    const result = await relayReady(env);
    assert.equal(result.status, 200);
    assert.deepEqual(await result.json(), { schema_version: "relay-ready.v1", status: "ready" });
    assert.equal(db.events.size, 0);
    assert.equal(db.decisions.length, 0);
    assert.equal(db.webhookEvents.size, 0);
    assert.equal(db.smsMonthly.size, 0);
    assert.equal(telnyx.calls.length, callsBefore);

    const unauthorized = await relayReady(env, { authorization: "Bearer wrong-token" });
    assert.equal(unauthorized.status, 401);
    const mismatchedKey = await relayReady(env, {
      decisionKey: "different-decision-hmac-key-material-00000000",
    });
    assert.equal(mismatchedKey.status, 401);
    assert.equal(db.events.size, 0);
    assert.equal(db.decisions.length, 0);
  });

  await test("proposal approval binding is rejected before any D1 or SMS mutation", async () => {
    const db = new FakeD1();
    const env = makeEnv(db, publicKey);
    const event = await proposal("BINDTEST");
    event.approval.binding_digest = `sha256:${"0".repeat(64)}`;
    const result = await postEvent(env, await submission(event));
    assert.equal(result.status, 400);
    assert.deepEqual(await result.json(), { error: "invalid_event" });
    assert.equal(db.events.size, 0);
    assert.equal(db.smsMonthly.size, 0);
    assert.equal(telnyx.calls.length, 0);

    const executionEvent = await execution("BINDEXE2");
    executionEvent.artifact_size_bytes += 1;
    const executionResult = await postEvent(env, await submission(executionEvent));
    assert.equal(executionResult.status, 400);
    assert.deepEqual(await executionResult.json(), { error: "invalid_event" });
    assert.equal(db.events.size, 0);
    assert.equal(db.smsMonthly.size, 0);
    assert.equal(telnyx.calls.length, 0);
  });

  await test("accepted duplicate event never sends a second SMS", async () => {
    const db = new FakeD1();
    const env = makeEnv(db, publicKey);
    const value = await submission(await proposal("DUPETEST"));
    telnyx.queue(200, { data: { id: "msg-duplicate" } });

    const first = await postEvent(env, value);
    assert.equal(first.status, 201);
    assert.equal((await first.json()).status, "accepted");
    const callCount = telnyx.calls.length;
    const outbound = JSON.parse(telnyx.calls.at(-1).init.body);
    assert.deepEqual(Object.keys(outbound).sort(), ["from", "text", "to", "webhook_url"]);
    assert.equal(Object.hasOwn(outbound, "client_state"), false);

    const second = await postEvent(env, value);
    assert.equal(second.status, 200);
    assert.equal((await second.json()).status, "duplicate");
    assert.equal(telnyx.calls.length, callCount);
    assert.equal(db.events.size, 1);
    assert.equal(db.events.get(value.event_digest).delivery_state, "accepted");
  });

  await test("definitive provider rejection is terminal, stable, and consumes one attempt", async () => {
    const db = new FakeD1();
    const env = makeEnv(db, publicKey);
    const value = await submission(await proposal("REJECT22"));
    telnyx.queue(422, { errors: [{ detail: "definitive rejection" }] });

    const rejected = await postEvent(env, value);
    const expectedAck = {
      schema_version: "relay-ack.v1",
      event_digest: value.event_digest,
      receipt_id: `receipt:${value.event_digest.slice(7, 31)}`,
      status: "rejected",
    };
    assert.equal(rejected.status, 200);
    assert.deepEqual(await rejected.json(), expectedAck);
    assert.equal(db.events.get(value.event_digest).delivery_state, "failed");
    assert.equal(db.events.get(value.event_digest).delivery_claimed_at, null);
    assert.equal(db.events.get(value.event_digest).telnyx_message_id, null);
    assert.equal(db.events.get(value.event_digest).telnyx_final_status, "provider_rejected");
    assert.equal([...db.smsMonthly.values()].reduce((sum, count) => sum + count, 0), 1);

    const callCount = telnyx.calls.length;
    const repeated = await postEvent(env, value);
    assert.equal(repeated.status, 200);
    assert.deepEqual(await repeated.json(), expectedAck);
    assert.equal(telnyx.calls.length, callCount);
    assert.equal([...db.smsMonthly.values()].reduce((sum, count) => sum + count, 0), 1);
  });

  await test("5xx, 408, 429, network, and malformed success remain acceptance-uncertain", async () => {
    const scenarios = [
      ["UNCERTAA", () => telnyx.queue(500, { errors: [{ detail: "server failure" }] })],
      ["UNCERTBB", () => telnyx.queue(408, { errors: [{ detail: "timeout" }] })],
      ["UNCERTCC", () => telnyx.queue(429, { errors: [{ detail: "rate limited" }] })],
      ["UNCERTDD", () => telnyx.queueRaw(200, "not-json")],
      ["UNCERTEE", () => telnyx.queueError()],
    ];
    for (const [code, queue] of scenarios) {
      const db = new FakeD1();
      const env = makeEnv(db, publicKey);
      const value = await submission(await proposal(code));
      queue();

      const uncertain = await postEvent(env, value);
      assert.equal(uncertain.status, 503, code);
      assert.deepEqual(await uncertain.json(), { error: "delivery_acceptance_uncertain" });
      assert.equal(db.events.get(value.event_digest).delivery_state, "claimed");
      assert.equal([...db.smsMonthly.values()].reduce((sum, count) => sum + count, 0), 1);

      const callCount = telnyx.calls.length;
      const repeated = await postEvent(env, value);
      assert.equal(repeated.status, 503, code);
      assert.deepEqual(await repeated.json(), { error: "delivery_in_progress_or_uncertain" });
      assert.equal(telnyx.calls.length, callCount);
      assert.equal([...db.smsMonthly.values()].reduce((sum, count) => sum + count, 0), 1);
    }
  });

  await test("monthly cap reserves 20 attempts for all three priority event classes", async () => {
    const db = new FakeD1();
    const env = makeEnv(db, publicKey);
    const month = new Date().toISOString().slice(0, 7);
    db.smsMonthly.set(month, 180);

    const lowPriority = await submission(budgetEvent("warning"));
    const callsBeforeReserve = telnyx.calls.length;
    const reserved = await postEvent(env, lowPriority);
    assert.equal(reserved.status, 429);
    assert.deepEqual(await reserved.json(), { error: "monthly_sms_priority_reserve" });
    assert.equal(telnyx.calls.length, callsBeforeReserve);
    assert.equal(db.smsMonthly.get(month), 180);
    assert.equal(db.events.get(lowPriority.event_digest).delivery_state, "failed");
    assert.equal(db.events.get(lowPriority.event_digest).telnyx_final_status, "monthly_priority_reserve");

    const reserveReplay = await postEvent(env, lowPriority);
    assert.equal(reserveReplay.status, 429);
    assert.deepEqual(await reserveReplay.json(), { error: "monthly_sms_priority_reserve" });
    assert.equal(telnyx.calls.length, callsBeforeReserve);
    assert.equal(db.smsMonthly.get(month), 180);

    const approval = await submission(await proposal("PRIORITY"));
    telnyx.queue(200, { data: { id: "msg-priority-approval" } });
    assert.equal((await postEvent(env, approval)).status, 201);
    assert.equal(db.smsMonthly.get(month), 181);

    const highValue = await submission(highValueTriageEvent());
    telnyx.queue(200, { data: { id: "msg-priority-crash" } });
    assert.equal((await postEvent(env, highValue)).status, 201);
    assert.equal(db.smsMonthly.get(month), 182);

    db.smsMonthly.set(month, 199);
    const criticalBudget = await submission(budgetEvent("critical"));
    telnyx.queue(200, { data: { id: "msg-priority-budget" } });
    assert.equal((await postEvent(env, criticalBudget)).status, 201);
    assert.equal(db.smsMonthly.get(month), 200);

    const overLimit = await submission(await proposal("LIMITAAA"));
    const callsAtLimit = telnyx.calls.length;
    const limited = await postEvent(env, overLimit);
    assert.equal(limited.status, 429);
    assert.deepEqual(await limited.json(), { error: "monthly_sms_limit" });
    assert.equal(telnyx.calls.length, callsAtLimit);
    assert.equal(db.smsMonthly.get(month), 200);
  });

  await test("finalized webhook correlates only by returned Telnyx message ID", async () => {
    const db = new FakeD1();
    const env = makeEnv(db, publicKey);
    const firstValue = await submission(await proposal("FINALAAA"));
    const secondValue = await submission(await proposal("FINALBBB"));
    telnyx.queue(200, { data: { id: "msg-final-a" } });
    telnyx.queue(200, { data: { id: "msg-final-b" } });
    assert.equal((await postEvent(env, firstValue)).status, 201);
    assert.equal((await postEvent(env, secondValue)).status, 201);

    const misleadingClientState = btoa(firstValue.event_digest);
    const unknown = await signedWebhook(
      env,
      keyPair.privateKey,
      finalizedData("webhook-final-unknown", "msg-not-returned", "delivered", misleadingClientState),
    );
    assert.equal(unknown.status, 200);
    assert.equal(db.events.get(firstValue.event_digest).delivery_state, "accepted");
    assert.equal(db.events.get(secondValue.event_digest).delivery_state, "accepted");

    const matched = await signedWebhook(
      env,
      keyPair.privateKey,
      finalizedData("webhook-final-matched", "msg-final-b", "delivered", misleadingClientState),
    );
    assert.equal(matched.status, 200);
    assert.equal(db.events.get(firstValue.event_digest).delivery_state, "accepted");
    assert.equal(db.events.get(secondValue.event_digest).delivery_state, "delivered");
    assert.equal(db.events.get(secondValue.event_digest).telnyx_final_status, "delivered");
  });

  await test("failed decision transaction returns 503 and leaves no replay marker", async () => {
    const db = new FakeD1();
    const env = makeEnv(db, publicKey);
    const value = await submission(await proposal("ROLLBACK"));
    telnyx.queue(200, { data: { id: "msg-rollback" } });
    assert.equal((await postEvent(env, value)).status, 201);

    db.failNextBatchAfter = 1;
    const result = await signedWebhook(env, keyPair.privateKey, receivedData("webhook-rollback", "ROLLBACK"));
    assert.equal(result.status, 503);
    assert.deepEqual(await result.json(), { error: "temporary_decision_failure" });
    assert.equal(db.webhookEvents.has("webhook-rollback"), false);
    assert.equal(db.decisions.length, 0);
    assert.equal(db.events.get(value.event_digest).state, "pending");
  });

  await test("valid signed inbound approval stores marker, decision, and state atomically", async () => {
    const db = new FakeD1();
    const env = makeEnv(db, publicKey);
    const value = await submission(await proposal("ATOMIC22"));
    telnyx.queue(200, { data: { id: "msg-atomic" } });
    assert.equal((await postEvent(env, value)).status, 201);

    const result = await signedWebhook(env, keyPair.privateKey, receivedData("webhook-atomic", "ATOMIC22"));
    assert.equal(result.status, 200);
    assert.deepEqual(await result.json(), { status: "decision_recorded" });
    assert.equal(db.webhookEvents.has("webhook-atomic"), true);
    assert.equal(db.decisions.length, 1);
    assert.equal(db.events.get(value.event_digest).state, "decided");

    const stored = JSON.parse(db.decisions[0].signed_json);
    assert.equal(stored.decision.event_digest, value.event_digest);
    assert.equal(stored.decision.action, "approve_for_offline_validation");
    assert.equal(stored.decision.approval_binding_digest, value.event.approval.binding_digest);
    assert.equal(
      stored.signature_hmac_sha256,
      await hmacHex(HMAC_KEY, canonical(stored.decision)),
    );

    const replay = await signedWebhook(env, keyPair.privateKey, receivedData("webhook-atomic", "ATOMIC22"));
    assert.equal(replay.status, 200);
    assert.deepEqual(await replay.json(), { status: "duplicate" });
    assert.equal(db.decisions.length, 1);
  });

  await test("execution approval is v2, exact-artifact bound, and command separated", async () => {
    const db = new FakeD1();
    const env = makeEnv(db, publicKey);
    const event = await execution("EXECUTE2");
    const value = await submission(event);
    telnyx.queue(200, { data: { id: "msg-execution" } });
    assert.equal((await postEvent(env, value)).status, 201);

    const wrongCommand = await signedWebhook(
      env,
      keyPair.privateKey,
      receivedData("webhook-execution-wrong", "EXECUTE2", "APPROVE"),
    );
    assert.equal(wrongCommand.status, 200);
    assert.deepEqual(await wrongCommand.json(), { status: "command_event_mismatch" });
    assert.equal(db.decisions.length, 0);
    assert.equal(db.events.get(value.event_digest).state, "pending");

    const executed = await signedWebhook(
      env,
      keyPair.privateKey,
      receivedData("webhook-execution", "EXECUTE2", "EXECUTE"),
    );
    assert.equal(executed.status, 200);
    assert.deepEqual(await executed.json(), { status: "decision_recorded" });
    assert.equal(db.decisions.length, 1);
    const stored = JSON.parse(db.decisions[0].signed_json);
    assert.equal(stored.decision.schema_version, "human-decision.v2");
    assert.equal(stored.decision.action, "approve_for_live_execution");
    assert.equal(stored.decision.candidate_digest, event.candidate_digest);
    assert.equal(stored.decision.artifact_digest, event.artifact_digest);
    assert.deepEqual(stored.decision.promotion_scope, event.promotion_scope);
    assert.equal(
      stored.signature_hmac_sha256,
      await hmacHex(HMAC_KEY, canonical(stored.decision)),
    );
  });

  await test("Telegram pairs exactly one private /start chat, then sends bound redacted approvals only to it", async () => {
    const db = new FakeD1();
    const env = makeTelegramEnv(db);
    const telegram = new FakeTelegram();
    const previousFetch = globalThis.fetch;
    globalThis.fetch = telegram.fetch.bind(telegram);
    try {
      const beforePair = await relayReady(env);
      assert.equal(beforePair.status, 503);
      assert.equal(telegram.calls.length, 0);

      telegram.queue(200, { ok: true, result: [telegramStart(9)] });
      const paired = await pairTelegram(env);
      assert.equal(paired.status, 200);
      assert.deepEqual(await paired.json(), { schema_version: "telegram-pair.v1", status: "paired" });
      assert.equal(db.telegramRecipient, TELEGRAM_CHAT_ID);
      assert.equal(telegram.calls.length, 1);
      assert.equal(telegram.calls[0].url, `https://api.telegram.org/bot${TELEGRAM_TOKEN}/getUpdates`);
      assert.deepEqual(JSON.parse(telegram.calls[0].init.body), { allowed_updates: ["message"], limit: 10, timeout: 0 });

      const callsBeforePairReplay = telegram.calls.length;
      const pairReplay = await pairTelegram(env);
      assert.equal(pairReplay.status, 200);
      assert.deepEqual(await pairReplay.json(), { schema_version: "telegram-pair.v1", status: "paired" });
      assert.equal(telegram.calls.length, callsBeforePairReplay);

      const value = await submission(await proposal("TELEGRAM"));
      telegram.queue(200, { ok: true, result: { message_id: 41 } });
      const sent = await postEvent(env, value);
      assert.equal(sent.status, 201);
      assert.equal((await sent.json()).status, "accepted");
      assert.equal(telegram.calls.length, 2);
      assert.equal(telegram.calls.at(-1).url, `https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage`);
      const outbound = JSON.parse(telegram.calls.at(-1).init.body);
      assert.deepEqual(Object.keys(outbound).sort(), ["chat_id", "disable_web_page_preview", "reply_markup", "text"]);
      assert.equal(outbound.chat_id, TELEGRAM_CHAT_ID);
      assert.equal(outbound.text, value.fixed_message);
      assert.deepEqual(outbound.reply_markup, {
        inline_keyboard: [
          [{ text: "Approve (offline validation only)", callback_data: "iou-ai:approve:TELEGRAM" }],
          [{ text: "Deny", callback_data: "iou-ai:deny:TELEGRAM" }],
        ],
      });
      assert.equal(db.events.get(value.event_digest).telnyx_message_id, "telegram:41");

      const hostDb = new FakeD1();
      hostDb.telegramRecipient = TELEGRAM_CHAT_ID;
      const hostEnv = makeTelegramEnv(hostDb);
      hostEnv.TELEGRAM_DELIVERY_MODE = "host";
      const hostValue = await submission(await proposal("HOSTSEND"));
      const callsBeforeHostRegistration = telegram.calls.length;
      const hostRegistered = await postEvent(hostEnv, hostValue);
      assert.equal(hostRegistered.status, 201);
      assert.deepEqual(await hostRegistered.json(), {
        schema_version: "relay-ack.v1",
        event_digest: hostValue.event_digest,
        receipt_id: `receipt:${hostValue.event_digest.slice(7, 31)}`,
        status: "accepted",
      });
      assert.equal(telegram.calls.length, callsBeforeHostRegistration);
      assert.equal(hostDb.events.get(hostValue.event_digest).delivery_state, "accepted");
      assert.equal(hostDb.events.get(hostValue.event_digest).telnyx_message_id, `telegram-host:${hostValue.event_digest.slice(7, 31)}`);

      const callsBeforeReady = telegram.calls.length;
      const ready = await relayReady(env);
      assert.equal(ready.status, 200);
      assert.equal(telegram.calls.length, callsBeforeReady);

      const forged = await telegramWebhook(env, telegramCallback(1, "TELEGRAM"), { secret: "wrong-secret" });
      assert.equal(forged.status, 403);
      assert.equal(db.decisions.length, 0);

      telegram.queue(200, { ok: true, result: true });
      const wrongChat = await telegramWebhook(env, telegramCallback(2, "TELEGRAM", 123));
      assert.equal(wrongChat.status, 200);
      assert.deepEqual(await wrongChat.json(), { status: "ignored" });
      assert.equal(db.decisions.length, 0);
      assert.equal(telegram.calls.at(-1).url, `https://api.telegram.org/bot${TELEGRAM_TOKEN}/answerCallbackQuery`);
      assert.deepEqual(JSON.parse(telegram.calls.at(-1).init.body), {
        callback_query_id: "callback-2",
        show_alert: true,
        text: "Approval could not be recorded.",
      });

      telegram.queue(200, { ok: true, result: true });
      const decision = await telegramWebhook(env, telegramCallback(3, "TELEGRAM"));
      assert.equal(decision.status, 200);
      assert.deepEqual(await decision.json(), { status: "decision_recorded" });
      assert.equal(db.decisions.length, 1);
      assert.equal(telegram.calls.at(-1).url, `https://api.telegram.org/bot${TELEGRAM_TOKEN}/answerCallbackQuery`);
      assert.deepEqual(JSON.parse(telegram.calls.at(-1).init.body), {
        callback_query_id: "callback-3",
        show_alert: false,
        text: "Approved for offline validation.",
      });
      const stored = JSON.parse(db.decisions[0].signed_json);
      assert.equal(stored.decision.channel, "telegram");
      assert.equal(stored.decision.signer_id, "relay:telegram-v1");
      assert.equal(stored.decision.action, "approve_for_offline_validation");
      assert.equal(db.events.get(value.event_digest).state, "decided");

      telegram.queue(200, { ok: true, result: true });
      const replay = await telegramWebhook(env, telegramCallback(3, "TELEGRAM"));
      assert.equal(replay.status, 200);
      assert.deepEqual(await replay.json(), { status: "duplicate" });
      assert.deepEqual(JSON.parse(telegram.calls.at(-1).init.body), {
        callback_query_id: "callback-3",
        show_alert: false,
        text: "Already processed.",
      });

      const executionValue = await submission(await execution("LIVEEXEC"));
      telegram.queue(200, { ok: true, result: { message_id: 42 } });
      const executionSent = await postEvent(env, executionValue);
      assert.equal(executionSent.status, 201);
      const executionOutbound = JSON.parse(telegram.calls.at(-1).init.body);
      assert.deepEqual(executionOutbound.reply_markup, {
        inline_keyboard: [
          [{ text: "Execute exact canaried artifact", callback_data: "iou-ai:execute:LIVEEXEC" }],
          [{ text: "Deny", callback_data: "iou-ai:deny:LIVEEXEC" }],
        ],
      });

      telegram.queue(200, { ok: true, result: true });
      const executionDecision = await telegramWebhook(
        env,
        telegramCallback(4, "LIVEEXEC", Number(TELEGRAM_CHAT_ID), "execute"),
      );
      assert.equal(executionDecision.status, 200);
      assert.deepEqual(await executionDecision.json(), { status: "decision_recorded" });
      assert.deepEqual(JSON.parse(telegram.calls.at(-1).init.body), {
        callback_query_id: "callback-4",
        show_alert: false,
        text: "Approved exact artifact for live execution.",
      });
      assert.equal(db.decisions.length, 2);
      const liveStored = JSON.parse(db.decisions[1].signed_json);
      assert.equal(liveStored.decision.schema_version, "human-decision.v2");
      assert.equal(liveStored.decision.action, "approve_for_live_execution");

      telegram.queue(200, { ok: true, result: true });
      const configured = await configureTelegram(env);
      assert.equal(configured.status, 200);
      assert.deepEqual(await configured.json(), { schema_version: "telegram-webhook.v1", status: "configured" });
      const setup = JSON.parse(telegram.calls.at(-1).init.body);
      assert.deepEqual(setup.allowed_updates, ["callback_query"]);
      assert.equal(setup.url, "https://relay.test/webhooks/telegram");
      assert.equal(setup.secret_token, TELEGRAM_WEBHOOK_SECRET);

      telegram.queue(401, { ok: false, error_code: 401 });
      const setupFailure = await configureTelegram(env);
      assert.equal(setupFailure.status, 503);
      assert.deepEqual(await setupFailure.json(), { error: "telegram_setup_upstream_http_401" });

      const upstreamFailureDb = new FakeD1();
      const upstreamFailureEnv = makeTelegramEnv(upstreamFailureDb);
      telegram.queue(404, { ok: false, error_code: 404 });
      const upstreamFailure = await pairTelegram(upstreamFailureEnv);
      assert.equal(upstreamFailure.status, 503);
      assert.deepEqual(await upstreamFailure.json(), { error: "telegram_pairing_upstream_http_404" });
      assert.equal(upstreamFailureDb.telegramRecipient, null);

      const ambiguousDb = new FakeD1();
      const ambiguousEnv = makeTelegramEnv(ambiguousDb);
      telegram.queue(200, { ok: true, result: [telegramStart(10, 123), telegramStart(11, 456)] });
      const ambiguous = await pairTelegram(ambiguousEnv);
      assert.equal(ambiguous.status, 409);
      assert.deepEqual(await ambiguous.json(), { error: "telegram_pairing_ambiguous" });
      assert.equal(ambiguousDb.telegramRecipient, null);
    } finally {
      globalThis.fetch = previousFetch;
    }
  });
} finally {
  globalThis.fetch = originalFetch;
}

console.log(`cloudflare relay integration: ${cases.length}/${cases.length} passed`);
