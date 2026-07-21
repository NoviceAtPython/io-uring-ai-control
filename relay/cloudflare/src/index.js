const enc = new TextEncoder();
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const CODE = /^[A-Z2-7]{8}$/;
const E164 = /^\+[1-9][0-9]{7,14}$/;
const TELEGRAM_BOT_TOKEN = /^[0-9]{6,20}:[A-Za-z0-9_-]{30,}$/;
const TELEGRAM_CHAT_ID = /^[1-9][0-9]{0,18}$/;
const TELEGRAM_WEBHOOK_SECRET = /^[A-Za-z0-9_-]{32,128}$/;
const IDENTIFIER = /^[a-z0-9][a-z0-9._:-]{0,95}$/;
const MONTH = /^\d{4}-(?:0[1-9]|1[0-2])$/;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$/;
const MONTHLY_SMS_LIMIT = 200;
const PRIORITY_SMS_RESERVE = 20;
const TRIAGE_CLASSES = new Set([
  "kasan_use_after_free", "kasan_out_of_bounds", "kasan_double_free",
  "kernel_null_dereference", "kernel_general_protection_fault",
  "kernel_oops_other", "harness_exit", "timeout", "unknown",
]);

function response(status, value) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}

function canonical(value) {
  if (value === null || typeof value === "boolean" || typeof value === "number") {
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  }
  throw new Error("unsupported JSON value");
}

function exactKeys(value, allowed) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("object required");
  const actual = Object.keys(value).sort();
  const expected = [...allowed].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error("unexpected object fields");
  }
}

function bytesFromBase64(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) throw new Error("invalid base64");
  const raw = atob(value);
  return Uint8Array.from(raw, (character) => character.charCodeAt(0));
}

function hex(bytes) {
  return [...new Uint8Array(bytes)].map((value) => value.toString(16).padStart(2, "0")).join("");
}

async function sha256(value) {
  return hex(await crypto.subtle.digest("SHA-256", enc.encode(value)));
}

async function hmacHex(secret, value) {
  if (typeof secret !== "string" || enc.encode(secret).byteLength < 32) throw new Error("invalid HMAC secret");
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  return hex(await crypto.subtle.sign("HMAC", key, enc.encode(value)));
}

async function timingSafeText(left, right) {
  const a = enc.encode(left);
  const b = enc.encode(right);
  const [aDigest, bDigest] = await Promise.all([
    crypto.subtle.digest("SHA-256", a),
    crypto.subtle.digest("SHA-256", b),
  ]);
  const digestsMatch = crypto.subtle.timingSafeEqual(aDigest, bDigest);
  return digestsMatch && a.byteLength === b.byteLength;
}

async function authorized(request, env) {
  const header = request.headers.get("authorization") || "";
  return typeof env.FUZZ_RELAY_TOKEN === "string"
    && enc.encode(env.FUZZ_RELAY_TOKEN).byteLength >= 32
    && await timingSafeText(header, `Bearer ${env.FUZZ_RELAY_TOKEN}`);
}

function configurationReady(env) {
  try {
    if (typeof env.FUZZ_RELAY_TOKEN !== "string" || enc.encode(env.FUZZ_RELAY_TOKEN).byteLength < 32) return false;
    if (typeof env.DECISION_HMAC_KEY !== "string" || enc.encode(env.DECISION_HMAC_KEY).byteLength < 32) return false;
    if (!(env.DB && typeof env.DB.prepare === "function" && typeof env.DB.batch === "function")) return false;
    if (env.RELAY_PROVIDER === "telegram") {
      return TELEGRAM_BOT_TOKEN.test(env.TELEGRAM_BOT_TOKEN || "")
        && TELEGRAM_WEBHOOK_SECRET.test(env.TELEGRAM_WEBHOOK_SECRET || "")
        && ["host", "worker"].includes(env.TELEGRAM_DELIVERY_MODE);
    }
    if (env.RELAY_PROVIDER === "telnyx") {
      if (typeof env.TELNYX_API_KEY !== "string" || enc.encode(env.TELNYX_API_KEY).byteLength < 16) return false;
      if (!E164.test(env.TELNYX_FROM || "") || !E164.test(env.ALERT_TO || "")) return false;
      if (bytesFromBase64(env.TELNYX_PUBLIC_KEY).byteLength !== 32) return false;
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

function deliveryProvider(env) {
  return env.RELAY_PROVIDER === "telegram" || env.RELAY_PROVIDER === "telnyx" ? env.RELAY_PROVIDER : null;
}

function safeTelegramStatus(status) {
  return [400, 401, 403, 404, 409, 429].includes(status) ? String(status) : "other";
}

async function answerTelegramCallback(env, callbackId, text, showAlert = false) {
  if (typeof callbackId !== "string" || callbackId.length < 1 || callbackId.length > 128
      || typeof text !== "string" || text.length < 1 || text.length > 200) return false;
  try {
    const result = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/answerCallbackQuery`, {
      method: "POST",
      redirect: "error",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        callback_query_id: callbackId,
        show_alert: showAlert,
        text,
      }),
    });
    const body = await result.text();
    if (!result.ok || enc.encode(body).byteLength > 4096) return false;
    const decoded = JSON.parse(body);
    return decoded?.ok === true && decoded?.result === true;
  } catch {
    // The signed decision remains authoritative even if Telegram cannot render
    // its best-effort UI acknowledgement.
    return false;
  }
}

async function telegramRecipient(env) {
  if (deliveryProvider(env) !== "telegram") return null;
  try {
    const row = await env.DB.prepare("SELECT chat_id FROM telegram_recipient WHERE singleton = 1").first();
    const chatId = String(row?.chat_id || "");
    return TELEGRAM_CHAT_ID.test(chatId) ? chatId : null;
  } catch {
    return null;
  }
}

async function deliveryReady(env) {
  if (!configurationReady(env)) return false;
  return deliveryProvider(env) !== "telegram" || (await telegramRecipient(env)) !== null;
}

function timestampMillis(value, label) {
  if (typeof value !== "string" || !TIMESTAMP.test(value)) throw new Error(`invalid ${label}`);
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) throw new Error(`invalid ${label}`);
  return parsed;
}

function validateTargetHashes(value) {
  exactKeys(value, ["compiler_hash", "fleet_config_hash", "harness_hash", "op_table_hash"]);
  for (const item of Object.values(value)) if (!DIGEST.test(item)) throw new Error("invalid target hash");
}

function validatePromotionScope(value) {
  exactKeys(value, ["campaign_id", "destination_id", "max_artifacts", "mode", "schema_version", "worker_set"]);
  if (value.schema_version !== "promotion-scope.v1"
      || !IDENTIFIER.test(value.campaign_id)
      || value.mode !== "afl_foreign_sync_seed"
      || value.max_artifacts !== 1) throw new Error("invalid promotion scope");
  const destinations = {
    native_stable: "native_ai_sync",
    kasan_triage: "kasan_ai_sync",
  };
  if (!(value.worker_set in destinations)
      || value.destination_id !== destinations[value.worker_set]) throw new Error("invalid promotion destination");
}

function isApprovalEvent(event) {
  return event.event_kind === "proposal_quarantined" || event.event_kind === "execution_ready";
}

function validateEvent(event) {
  const expectedSchema = event.event_kind === "execution_ready" ? "redacted-event.v2" : "redacted-event.v1";
  if (event.schema_version !== expectedSchema) throw new Error("invalid event schema");
  const createdAt = timestampMillis(event.created_at, "event time");
  switch (event.event_kind) {
    case "proposal_quarantined":
      exactKeys(event, ["approval", "created_at", "envelope_digest", "event_kind", "proposal_hash", "schema_version", "severity", "target_hashes"]);
      if (event.severity !== "action_required" || !DIGEST.test(event.envelope_digest) || !DIGEST.test(event.proposal_hash)) throw new Error("invalid proposal event");
      validateTargetHashes(event.target_hashes);
      exactKeys(event.approval, ["allowed_actions", "binding_digest", "expires_at", "human_code", "nonce"]);
      if (!CODE.test(event.approval.human_code) || !/^[0-9a-f]{64}$/.test(event.approval.nonce) || !DIGEST.test(event.approval.binding_digest)) throw new Error("invalid approval challenge");
      if (canonical(event.approval.allowed_actions) !== canonical(["approve_for_offline_validation", "deny"])) throw new Error("invalid approval actions");
      {
        const expiresAt = timestampMillis(event.approval.expires_at, "approval expiration");
        const ttl = expiresAt - createdAt;
        if (ttl < 5 * 60 * 1000 || ttl > 60 * 60 * 1000 || expiresAt <= Date.now()) throw new Error("invalid approval lifetime");
      }
      break;
    case "execution_ready":
      exactKeys(event, [
        "approval", "artifact_digest", "artifact_manifest_digest", "artifact_size_bytes",
        "candidate_digest", "canary_report_digest", "created_at", "envelope_digest",
        "event_kind", "promotion_scope", "schema_version", "severity", "target_hashes",
        "validation_report_digest",
      ]);
      for (const key of [
        "artifact_digest", "artifact_manifest_digest", "candidate_digest",
        "canary_report_digest", "envelope_digest", "validation_report_digest",
      ]) if (!DIGEST.test(event[key])) throw new Error("invalid execution digest");
      if (event.severity !== "action_required"
          || !Number.isSafeInteger(event.artifact_size_bytes)
          || event.artifact_size_bytes < 1
          || event.artifact_size_bytes > 2048) throw new Error("invalid execution event");
      validateTargetHashes(event.target_hashes);
      validatePromotionScope(event.promotion_scope);
      exactKeys(event.approval, ["allowed_actions", "binding_digest", "expires_at", "human_code", "nonce"]);
      if (!CODE.test(event.approval.human_code)
          || !/^[0-9a-f]{64}$/.test(event.approval.nonce)
          || !DIGEST.test(event.approval.binding_digest)) throw new Error("invalid execution approval challenge");
      if (canonical(event.approval.allowed_actions) !== canonical(["approve_for_live_execution", "deny"])) throw new Error("invalid execution approval actions");
      {
        const expiresAt = timestampMillis(event.approval.expires_at, "execution approval expiration");
        const ttl = expiresAt - createdAt;
        if (ttl < 5 * 60 * 1000 || ttl > 60 * 60 * 1000 || expiresAt <= Date.now()) throw new Error("invalid execution approval lifetime");
      }
      break;
    case "budget_threshold":
      exactKeys(event, ["created_at", "effective_spend_microdollars", "event_kind", "hard_limit_microdollars", "month", "remaining_microdollars", "schema_version", "severity", "threshold_microdollars"]);
      if (!/^(warning|critical)$/.test(event.severity) || !MONTH.test(event.month)) throw new Error("invalid budget metadata");
      for (const key of ["effective_spend_microdollars", "hard_limit_microdollars", "remaining_microdollars", "threshold_microdollars"]) if (!Number.isSafeInteger(event[key]) || event[key] < 0) throw new Error("invalid budget amount");
      if (event.hard_limit_microdollars <= 0
          || event.threshold_microdollars >= event.hard_limit_microdollars
          || event.effective_spend_microdollars < event.threshold_microdollars
          || event.remaining_microdollars !== Math.max(0, event.hard_limit_microdollars - event.effective_spend_microdollars)) throw new Error("inconsistent budget amounts");
      break;
    case "crash_counter_increase":
    case "hang_counter_increase":
      exactKeys(event, ["campaign_id", "created_at", "current_count", "event_kind", "increase", "previous_count", "schema_version", "severity", "target_hashes", "telemetry_packet_digest"]);
      if (event.severity !== "attention" || !IDENTIFIER.test(event.campaign_id) || !DIGEST.test(event.telemetry_packet_digest)) throw new Error("invalid counter event");
      validateTargetHashes(event.target_hashes);
      if (![event.previous_count, event.current_count, event.increase].every(Number.isSafeInteger)
          || event.previous_count < 0 || event.current_count <= 0 || event.increase <= 0
          || event.current_count - event.previous_count !== event.increase) throw new Error("invalid counter delta");
      break;
    case "crash_triage":
      exactKeys(event, ["bug_class", "campaign_id", "created_at", "event_kind", "kernel_context_confirmed", "potential_high_value", "reproductions", "schema_version", "severity", "stack_signature", "target_hashes", "telemetry_packet_digest"]);
      if (!IDENTIFIER.test(event.campaign_id) || !DIGEST.test(event.telemetry_packet_digest) || !DIGEST.test(event.stack_signature)) throw new Error("invalid triage event");
      validateTargetHashes(event.target_hashes);
      if (!TRIAGE_CLASSES.has(event.bug_class)
          || !["attention", "urgent"].includes(event.severity)
          || typeof event.kernel_context_confirmed !== "boolean"
          || typeof event.potential_high_value !== "boolean") throw new Error("invalid triage classification");
      if (!Number.isSafeInteger(event.reproductions) || event.reproductions < 1 || event.reproductions > 16) throw new Error("invalid reproduction count");
      {
        const qualifies = event.reproductions >= 2
          && event.kernel_context_confirmed
          && ["kasan_use_after_free", "kasan_out_of_bounds", "kasan_double_free"].includes(event.bug_class);
        if (event.potential_high_value !== qualifies || (event.severity === "urgent") !== qualifies) throw new Error("invalid triage severity");
      }
      break;
    default:
      throw new Error("unsupported event kind");
  }
}

function formatUsd(microdollars) {
  if (!Number.isSafeInteger(microdollars) || microdollars < 0) throw new Error("invalid microdollar amount");
  const cents = Math.floor((microdollars + 5000) / 10000);
  return `${Math.floor(cents / 100)}.${String(cents % 100).padStart(2, "0")}`;
}

function renderEvent(event) {
  switch (event.event_kind) {
    case "proposal_quarantined":
      return `IOU-AI APPROVAL: GPT plan passed Claude and local checks. Ref ${event.envelope_digest.slice(7, 19)}. Reply APPROVE ${event.approval.human_code} or DENY ${event.approval.human_code} by ${event.approval.expires_at}. Offline validation only; AFL/Nyx fleet unchanged.`;
    case "execution_ready":
      return `IOU-AI LIVE EXECUTION APPROVAL: exact artifact ${event.artifact_digest.slice(7, 19)} (${event.artifact_size_bytes} bytes) passed GPT planning, Claude review, deterministic checks, byte round-trip, and isolated Nyx canary. Scope=${event.promotion_scope.destination_id}; one artifact. Reply EXECUTE ${event.approval.human_code} or DENY ${event.approval.human_code} by ${event.approval.expires_at}.`;
    case "budget_threshold":
      return `IOU-AI BUDGET: monthly spend crossed $${formatUsd(event.threshold_microdollars)}; $${formatUsd(event.remaining_microdollars)} remains of $${formatUsd(event.hard_limit_microdollars)}.`;
    case "crash_counter_increase":
      return `IOU-AI CRASH COUNTER ALERT: campaign ${event.campaign_id} increased by ${event.increase} (${event.previous_count} to ${event.current_count}). Untriaged; impact and bounty status are not yet established.`;
    case "hang_counter_increase":
      return `IOU-AI HANG COUNTER ALERT: campaign ${event.campaign_id} increased by ${event.increase} (${event.previous_count} to ${event.current_count}). Untriaged.`;
    case "crash_triage": {
      const signature = event.stack_signature.slice(7, 19);
      if (event.potential_high_value) return `POTENTIAL HIGH-VALUE SECURITY IMPACT - PRESERVE/REPRODUCE NOW. Class=${event.bug_class}; reproductions=${event.reproductions}; signature=${signature}. Not a confirmed bounty.`;
      return `IOU-AI SECURITY TRIAGE: class=${event.bug_class}; reproductions=${event.reproductions}; signature=${signature}; high-value criteria not met.`;
    }
    default:
      throw new Error("unsupported event");
  }
}

function isPriorityEvent(event) {
  return event.event_kind === "proposal_quarantined"
    || event.event_kind === "execution_ready"
    || (event.event_kind === "crash_triage" && event.potential_high_value)
    || (event.event_kind === "budget_threshold" && event.severity === "critical");
}

async function readJson(request, limit = 65536) {
  const declared = request.headers.get("content-length");
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > limit)) throw new Error("request too large");
  const body = await request.text();
  if (enc.encode(body).byteLength > limit) throw new Error("request too large");
  return { body, value: JSON.parse(body) };
}

class DeliveryError extends Error {
  constructor(message, { retrySafe }) {
    super(message);
    this.retrySafe = retrySafe;
  }
}

async function sendTelnyx(env, text, webhookUrl) {
  if (!E164.test(env.TELNYX_FROM || "") || !E164.test(env.ALERT_TO || "")) throw new Error("invalid SMS configuration");
  let result;
  try {
    result = await fetch("https://api.telnyx.com/v2/messages", {
      method: "POST",
      redirect: "error",
      headers: { authorization: `Bearer ${env.TELNYX_API_KEY}`, "content-type": "application/json" },
      body: JSON.stringify({
        from: env.TELNYX_FROM,
        to: env.ALERT_TO,
        text,
        webhook_url: webhookUrl,
      }),
    });
  } catch {
    throw new DeliveryError("SMS acceptance is uncertain", { retrySafe: false });
  }
  const body = await result.text();
  if (!result.ok) {
    const definitiveClientRejection = result.status >= 400
      && result.status < 500
      && ![408, 429].includes(result.status);
    throw new DeliveryError(
      definitiveClientRejection ? "SMS provider rejected the event" : "SMS acceptance is uncertain",
      { retrySafe: definitiveClientRejection },
    );
  }
  if (enc.encode(body).byteLength > 65536) throw new DeliveryError("SMS acceptance is uncertain", { retrySafe: false });
  let decoded;
  try { decoded = JSON.parse(body); } catch { throw new DeliveryError("SMS acceptance is uncertain", { retrySafe: false }); }
  if (!decoded?.data?.id || typeof decoded.data.id !== "string") throw new DeliveryError("SMS acceptance is uncertain", { retrySafe: false });
  return decoded.data.id;
}

function telegramReplyMarkup(event) {
  if (!isApprovalEvent(event)) return undefined;
  const code = event.approval.human_code;
  if (event.event_kind === "execution_ready") {
    return {
      inline_keyboard: [
        [{ text: "Execute exact canaried artifact", callback_data: `iou-ai:execute:${code}` }],
        [{ text: "Deny", callback_data: `iou-ai:deny:${code}` }],
      ],
    };
  }
  return {
    inline_keyboard: [
      [{ text: "Approve (offline validation only)", callback_data: `iou-ai:approve:${code}` }],
      [{ text: "Deny", callback_data: `iou-ai:deny:${code}` }],
    ],
  };
}

async function sendTelegram(env, event, text) {
  const chatId = await telegramRecipient(env);
  if (!chatId) throw new DeliveryError("Telegram recipient is not paired", { retrySafe: false });
  let result;
  try {
    const payload = {
      chat_id: chatId,
      disable_web_page_preview: true,
      text,
    };
    const replyMarkup = telegramReplyMarkup(event);
    if (replyMarkup) payload.reply_markup = replyMarkup;
    result = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
      method: "POST",
      redirect: "error",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });
  } catch {
    throw new DeliveryError("Telegram acceptance is uncertain", { retrySafe: false });
  }
  const body = await result.text();
  if (!result.ok) {
    const definitiveClientRejection = result.status >= 400
      && result.status < 500
      && ![408, 429].includes(result.status);
    throw new DeliveryError(
      definitiveClientRejection ? "Telegram rejected the event" : "Telegram acceptance is uncertain",
      { retrySafe: definitiveClientRejection },
    );
  }
  if (enc.encode(body).byteLength > 65536) throw new DeliveryError("Telegram acceptance is uncertain", { retrySafe: false });
  let decoded;
  try { decoded = JSON.parse(body); } catch { throw new DeliveryError("Telegram acceptance is uncertain", { retrySafe: false }); }
  if (decoded?.ok !== true || !Number.isSafeInteger(decoded?.result?.message_id) || decoded.result.message_id <= 0) {
    throw new DeliveryError("Telegram acceptance is uncertain", { retrySafe: false });
  }
  return `telegram:${decoded.result.message_id}`;
}

async function sendDelivery(env, event, text, webhookUrl) {
  if (deliveryProvider(env) === "telegram") return sendTelegram(env, event, text);
  if (deliveryProvider(env) === "telnyx") return sendTelnyx(env, text, webhookUrl);
  throw new Error("unsupported delivery provider");
}

async function acceptEvent(request, env) {
  if (!(await authorized(request, env))) return response(401, { error: "unauthorized" });
  if (!(await deliveryReady(env))) return response(503, { error: "not_ready" });
  let submission;
  try {
    submission = (await readJson(request)).value;
    exactKeys(submission, ["event", "event_digest", "fixed_message", "schema_version"]);
    if (submission.schema_version !== "relay-submission.v1" || !DIGEST.test(submission.event_digest)) throw new Error("invalid submission");
    validateEvent(submission.event);
    if (`sha256:${await sha256(canonical(submission.event))}` !== submission.event_digest) throw new Error("event digest mismatch");
    if (submission.fixed_message !== renderEvent(submission.event) || submission.fixed_message.length > 480) throw new Error("message is not fixed");
    if (submission.event.event_kind === "proposal_quarantined") {
      const approvalMaterial = {
        envelope_digest: submission.event.envelope_digest,
        expires_at: submission.event.approval.expires_at,
        human_code: submission.event.approval.human_code,
        nonce: submission.event.approval.nonce,
        target_hashes: submission.event.target_hashes,
      };
      if (`sha256:${await sha256(canonical(approvalMaterial))}` !== submission.event.approval.binding_digest) throw new Error("approval binding mismatch");
    } else if (submission.event.event_kind === "execution_ready") {
      const approvalMaterial = {
        artifact_digest: submission.event.artifact_digest,
        artifact_manifest_digest: submission.event.artifact_manifest_digest,
        artifact_size_bytes: submission.event.artifact_size_bytes,
        binding_version: "execution-approval-binding.v1",
        candidate_digest: submission.event.candidate_digest,
        canary_report_digest: submission.event.canary_report_digest,
        envelope_digest: submission.event.envelope_digest,
        event_kind: "execution_ready",
        expires_at: submission.event.approval.expires_at,
        human_code: submission.event.approval.human_code,
        nonce: submission.event.approval.nonce,
        positive_action: "approve_for_live_execution",
        promotion_scope: submission.event.promotion_scope,
        target_hashes: submission.event.target_hashes,
        validation_report_digest: submission.event.validation_report_digest,
      };
      if (`sha256:${await sha256(canonical(approvalMaterial))}` !== submission.event.approval.binding_digest) throw new Error("execution approval binding mismatch");
    }
  } catch {
    return response(400, { error: "invalid_event" });
  }

  const eventJson = canonical(submission.event);
  const prior = await env.DB.prepare("SELECT event_json, telnyx_message_id, telnyx_final_status, delivery_state FROM events WHERE event_digest = ?").bind(submission.event_digest).first();
  let duplicate = false;
  if (prior) {
    if (prior.event_json !== eventJson) return response(409, { error: "event_binding_changed" });
    duplicate = true;
  } else {
    const humanCode = isApprovalEvent(submission.event) ? submission.event.approval.human_code : null;
    const expiresAt = isApprovalEvent(submission.event) ? submission.event.approval.expires_at : null;
    try {
      await env.DB.prepare("INSERT INTO events(event_digest,event_json,human_code,expires_at,state,delivery_state,created_at) VALUES(?,?,?,?,?,?,?)")
        .bind(submission.event_digest, eventJson, humanCode, expiresAt, "pending", "pending", new Date().toISOString()).run();
    } catch {
      return response(409, { error: "event_or_code_already_exists" });
    }
  }

  if (prior?.telnyx_message_id && ["accepted", "delivered"].includes(prior.delivery_state)) {
    return response(200, {
      schema_version: "relay-ack.v1",
      event_digest: submission.event_digest,
      receipt_id: `receipt:${submission.event_digest.slice(7, 31)}`,
      status: "duplicate",
    });
  }
  if (prior?.delivery_state === "failed" && prior.telnyx_final_status === "provider_rejected") {
    return response(200, {
      schema_version: "relay-ack.v1",
      event_digest: submission.event_digest,
      receipt_id: `receipt:${submission.event_digest.slice(7, 31)}`,
      status: "rejected",
    });
  }
  if (prior?.delivery_state === "failed" && prior.telnyx_final_status === "monthly_priority_reserve") {
    return response(429, { error: "monthly_sms_priority_reserve" });
  }
  if (prior?.delivery_state === "failed" && prior.telnyx_final_status === "monthly_sms_limit") {
    return response(429, { error: "monthly_sms_limit" });
  }

  // Cloudflare egress to Telegram is not reliable on every account/region.
  // In host mode the relay remains the approval authority and records the
  // validated event before the isolated Michigan notifier sends the exact
  // fixed text through Telegram. No model text or fuzzer artifact is added.
  if (deliveryProvider(env) === "telegram" && env.TELEGRAM_DELIVERY_MODE === "host") {
    const hostReceipt = `telegram-host:${submission.event_digest.slice(7, 31)}`;
    try {
      const stored = await env.DB.prepare("UPDATE events SET telnyx_message_id = ?, delivery_state = 'accepted' WHERE event_digest = ? AND delivery_state = 'pending'")
        .bind(hostReceipt, submission.event_digest).run();
      if (stored.meta.changes !== 1) return response(503, { error: "host_registration_uncertain" });
    } catch {
      return response(503, { error: "host_registration_uncertain" });
    }
    return response(duplicate ? 200 : 201, {
      schema_version: "relay-ack.v1",
      event_digest: submission.event_digest,
      receipt_id: `receipt:${submission.event_digest.slice(7, 31)}`,
      status: duplicate ? "duplicate" : "accepted",
    });
  }

  let claimed;
  try {
    claimed = await env.DB.prepare("UPDATE events SET delivery_state = 'claimed', delivery_claimed_at = ? WHERE event_digest = ? AND delivery_state = 'pending'")
      .bind(new Date().toISOString(), submission.event_digest).run();
  } catch {
    return response(503, { error: "temporary_storage_failure" });
  }
  if (claimed.meta.changes !== 1) return response(503, { error: "delivery_in_progress_or_uncertain" });

  const deliveryMonth = new Date().toISOString().slice(0, 7);
  const priority = isPriorityEvent(submission.event);
  const attemptLimit = priority ? MONTHLY_SMS_LIMIT : MONTHLY_SMS_LIMIT - PRIORITY_SMS_RESERVE;
  let counted;
  try {
    counted = await env.DB.prepare("INSERT INTO sms_monthly(month,attempted_count) VALUES(?,1) ON CONFLICT(month) DO UPDATE SET attempted_count = attempted_count + 1 WHERE attempted_count < ?")
      .bind(deliveryMonth, attemptLimit).run();
  } catch {
    try {
      await env.DB.prepare("UPDATE events SET delivery_state = 'pending', delivery_claimed_at = NULL WHERE event_digest = ? AND delivery_state = 'claimed'")
        .bind(submission.event_digest).run();
    } catch {
      return response(503, { error: "temporary_storage_failure" });
    }
    return response(503, { error: "temporary_storage_failure" });
  }
  if (counted.meta.changes !== 1) {
    const finalStatus = priority ? "monthly_sms_limit" : "monthly_priority_reserve";
    const error = priority ? "monthly_sms_limit" : "monthly_sms_priority_reserve";
    try {
      const stored = await env.DB.prepare("UPDATE events SET delivery_state = 'failed', delivery_claimed_at = NULL, telnyx_final_status = ? WHERE event_digest = ? AND delivery_state = 'claimed'")
        .bind(finalStatus, submission.event_digest).run();
      if (stored.meta.changes !== 1) throw new Error("SMS limit did not persist exactly once");
    } catch {
      return response(503, { error: "temporary_storage_failure" });
    }
    return response(429, { error });
  }

  try {
    const id = await sendDelivery(env, submission.event, submission.fixed_message, `${new URL(request.url).origin}/webhooks/telnyx`);
    try {
      const stored = await env.DB.prepare("UPDATE events SET telnyx_message_id = ?, delivery_state = 'accepted' WHERE event_digest = ? AND delivery_state = 'claimed'")
        .bind(id, submission.event_digest).run();
      if (stored.meta.changes !== 1) return response(503, { error: "delivery_accepted_storage_uncertain" });
    } catch {
      return response(503, { error: "delivery_accepted_storage_uncertain" });
    }
  } catch (error) {
    if (error instanceof DeliveryError && error.retrySafe) {
      try {
        const stored = await env.DB.prepare("UPDATE events SET delivery_state = 'failed', delivery_claimed_at = NULL, telnyx_final_status = 'provider_rejected' WHERE event_digest = ? AND delivery_state = 'claimed'")
          .bind(submission.event_digest).run();
        if (stored.meta.changes !== 1) throw new Error("terminal rejection did not persist exactly once");
      } catch {
        return response(503, { error: "delivery_rejection_storage_uncertain" });
      }
      return response(200, {
        schema_version: "relay-ack.v1",
        event_digest: submission.event_digest,
        receipt_id: `receipt:${submission.event_digest.slice(7, 31)}`,
        status: "rejected",
      });
    }
    return response(503, { error: "delivery_acceptance_uncertain" });
  }
  return response(duplicate ? 200 : 201, {
    schema_version: "relay-ack.v1",
    event_digest: submission.event_digest,
    receipt_id: `receipt:${submission.event_digest.slice(7, 31)}`,
    status: duplicate ? "duplicate" : "accepted",
  });
}

async function verifyTelnyx(request, env, rawBody) {
  const timestamp = request.headers.get("telnyx-timestamp") || "";
  const signature = request.headers.get("telnyx-signature-ed25519") || "";
  if (!/^[0-9]{10,13}$/.test(timestamp)) return false;
  const seconds = Number(timestamp.length === 13 ? timestamp.slice(0, 10) : timestamp);
  if (!Number.isSafeInteger(seconds) || Math.abs(Math.floor(Date.now() / 1000) - seconds) > 300) return false;
  try {
    const publicKeyBytes = bytesFromBase64(env.TELNYX_PUBLIC_KEY);
    const signatureBytes = bytesFromBase64(signature);
    if (publicKeyBytes.byteLength !== 32 || signatureBytes.byteLength !== 64) return false;
    const publicKey = await crypto.subtle.importKey("raw", publicKeyBytes, "Ed25519", false, ["verify"]);
    return await crypto.subtle.verify("Ed25519", publicKey, signatureBytes, enc.encode(`${timestamp}|${rawBody}`));
  } catch {
    return false;
  }
}

function decisionForEvent(event, row, {
  channel,
  command,
  issuedAt,
  senderBinding,
}) {
  if (!isApprovalEvent(event) || !["approve", "execute", "deny"].includes(command)) {
    throw new Error("unsupported decision command");
  }
  if ((event.event_kind === "proposal_quarantined" && command === "execute")
      || (event.event_kind === "execution_ready" && command === "approve")) {
    throw new Error("decision command does not match event kind");
  }
  const deny = command === "deny";
  const common = {
    approval_binding_digest: event.approval.binding_digest,
    channel,
    decision_nonce: event.approval.nonce,
    envelope_digest: event.envelope_digest,
    event_digest: row.event_digest,
    expires_at: event.approval.expires_at,
    human_code: event.approval.human_code,
    issued_at: issuedAt,
    sender_binding: senderBinding,
    signer_id: channel === "telegram" ? "relay:telegram-v1" : "relay:sms-v1",
    target_hashes: event.target_hashes,
  };
  if (event.event_kind === "execution_ready") {
    return {
      action: deny ? "deny" : "approve_for_live_execution",
      artifact_digest: event.artifact_digest,
      artifact_manifest_digest: event.artifact_manifest_digest,
      artifact_size_bytes: event.artifact_size_bytes,
      candidate_digest: event.candidate_digest,
      canary_report_digest: event.canary_report_digest,
      ...common,
      promotion_scope: event.promotion_scope,
      reason_code: deny ? "operator_denied" : "operator_approved_live_execution",
      schema_version: "human-decision.v2",
      validation_report_digest: event.validation_report_digest,
    };
  }
  return {
    action: deny ? "deny" : "approve_for_offline_validation",
    ...common,
    reason_code: deny ? "operator_denied" : "operator_approved",
    schema_version: "human-decision.v1",
  };
}

async function receiveTelnyx(request, env) {
  if (deliveryProvider(env) !== "telnyx") return response(404, { error: "not_found" });
  if (!(await deliveryReady(env))) return response(503, { error: "not_ready" });
  let rawBody;
  try {
    rawBody = await request.text();
    if (enc.encode(rawBody).byteLength > 65536 || !(await verifyTelnyx(request, env, rawBody))) return response(403, { error: "invalid_signature" });
  } catch {
    return response(403, { error: "invalid_signature" });
  }
  let webhook;
  try { webhook = JSON.parse(rawBody); } catch { return response(400, { error: "invalid_webhook" }); }
  const data = webhook?.data;
  if (!data?.id || typeof data.id !== "string") return response(400, { error: "invalid_webhook" });
  try {
    const replay = await env.DB.prepare("SELECT webhook_id FROM webhook_events WHERE webhook_id = ?").bind(data.id).first();
    if (replay) return response(200, { status: "duplicate" });
  } catch {
    return response(503, { error: "temporary_storage_failure" });
  }
  const payload = data.payload;
  if (data.event_type === "message.finalized") return recordFinalizedWebhook(env, data.id, payload);
  if (data.event_type !== "message.received") return recordIgnoredWebhook(env, data.id, "ignored");

  const sender = payload?.from?.phone_number;
  const destination = payload?.to?.[0]?.phone_number;
  if (!(await timingSafeText(sender || "", env.ALERT_TO || "")) || !(await timingSafeText(destination || "", env.TELNYX_FROM || ""))) return recordIgnoredWebhook(env, data.id, "ignored");
  const match = /^\s*(APPROVE|EXECUTE|DENY)\s+([A-Z2-7]{8})\s*$/i.exec(payload?.text || "");
  if (!match) return recordIgnoredWebhook(env, data.id, "ignored");
  const command = match[1].toUpperCase();
  const code = match[2].toUpperCase();
  const row = await env.DB.prepare("SELECT event_digest,event_json,expires_at,state FROM events WHERE human_code = ?").bind(code).first();
  if (!row || row.state !== "pending" || !row.expires_at || Date.parse(row.expires_at) < Date.now()) return recordIgnoredWebhook(env, data.id, "expired_or_unknown");
  const event = JSON.parse(row.event_json);
  const now = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  let decision;
  try {
    decision = decisionForEvent(event, row, {
      channel: "sms",
      command: command.toLowerCase(),
      issuedAt: now,
      senderBinding: `sha256:${await hmacHex(env.DECISION_HMAC_KEY, `sender:${sender}`)}`,
    });
  } catch {
    return recordIgnoredWebhook(env, data.id, "command_event_mismatch");
  }
  const signature = await hmacHex(env.DECISION_HMAC_KEY, canonical(decision));
  const signed = { decision, signature_hmac_sha256: signature };
  const signedJson = canonical(signed);
  const decisionDigest = await sha256(signedJson);
  try {
    const results = await env.DB.batch([
      env.DB.prepare("INSERT INTO webhook_events(webhook_id,processed_at) VALUES(?,?)").bind(data.id, now),
      env.DB.prepare("INSERT INTO decisions(decision_digest,event_digest,signed_json,created_at) VALUES(?,?,?,?)").bind(decisionDigest, row.event_digest, signedJson, now),
      env.DB.prepare("UPDATE events SET state = 'decided' WHERE event_digest = ? AND state = 'pending'").bind(row.event_digest),
    ]);
    if (results[0]?.meta?.changes !== 1 || results[1]?.meta?.changes !== 1 || results[2]?.meta?.changes !== 1) throw new Error("decision transaction did not commit exactly once");
  } catch {
    try {
      const replay = await env.DB.prepare("SELECT webhook_id FROM webhook_events WHERE webhook_id = ?").bind(data.id).first();
      if (replay) return response(200, { status: "duplicate" });
    } catch {
      // Fall through to a retryable response.
    }
    return response(503, { error: "temporary_decision_failure" });
  }
  return response(200, { status: "decision_recorded" });
}

async function receiveTelegram(request, env) {
  if (deliveryProvider(env) !== "telegram") return response(404, { error: "not_found" });
  if (!(await deliveryReady(env))) return response(503, { error: "not_ready" });
  const webhookSecret = request.headers.get("x-telegram-bot-api-secret-token") || "";
  if (!(await timingSafeText(webhookSecret, env.TELEGRAM_WEBHOOK_SECRET))) return response(403, { error: "invalid_signature" });
  let update;
  try {
    update = (await readJson(request)).value;
  } catch {
    return response(400, { error: "invalid_webhook" });
  }
  if (!Number.isSafeInteger(update?.update_id) || update.update_id < 0) return response(400, { error: "invalid_webhook" });
  const webhookId = `telegram:${update.update_id}`;
  const callback = update.callback_query;
  const chatId = callback?.message?.chat?.id;
  const callbackId = callback?.id;
  try {
    const replay = await env.DB.prepare("SELECT webhook_id FROM webhook_events WHERE webhook_id = ?").bind(webhookId).first();
    if (replay) {
      await answerTelegramCallback(env, callbackId, "Already processed.");
      return response(200, { status: "duplicate" });
    }
  } catch {
    return response(503, { error: "temporary_storage_failure" });
  }
  const pairedChatId = await telegramRecipient(env);
  const match = /^iou-ai:(approve|execute|deny):([A-Z2-7]{8})$/.exec(callback?.data || "");
  if (typeof callbackId !== "string" || callbackId.length < 1 || callbackId.length > 128
      || !Number.isSafeInteger(chatId) || !TELEGRAM_CHAT_ID.test(String(chatId))
      || !(await timingSafeText(String(chatId), pairedChatId || "")) || !match) {
    const ignored = await recordIgnoredWebhook(env, webhookId, "ignored");
    await answerTelegramCallback(env, callbackId, "Approval could not be recorded.", true);
    return ignored;
  }
  const code = match[2];
  const row = await env.DB.prepare("SELECT event_digest,event_json,expires_at,state FROM events WHERE human_code = ?").bind(code).first();
  if (!row || row.state !== "pending" || !row.expires_at || Date.parse(row.expires_at) < Date.now()) {
    const ignored = await recordIgnoredWebhook(env, webhookId, "expired_or_unknown");
    await answerTelegramCallback(env, callbackId, "Approval window expired.", true);
    return ignored;
  }
  let event;
  try { event = JSON.parse(row.event_json); } catch { return response(503, { error: "temporary_storage_failure" }); }
  const command = match[1];
  const now = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  let decision;
  try {
    decision = decisionForEvent(event, row, {
      channel: "telegram",
      command,
      issuedAt: now,
      senderBinding: `sha256:${await hmacHex(env.DECISION_HMAC_KEY, `sender:telegram-chat:${chatId}`)}`,
    });
  } catch {
    const ignored = await recordIgnoredWebhook(env, webhookId, "command_event_mismatch");
    await answerTelegramCallback(env, callbackId, "Command does not match this approval.", true);
    return ignored;
  }
  const signature = await hmacHex(env.DECISION_HMAC_KEY, canonical(decision));
  const signed = { decision, signature_hmac_sha256: signature };
  const signedJson = canonical(signed);
  const decisionDigest = await sha256(signedJson);
  try {
    const results = await env.DB.batch([
      env.DB.prepare("INSERT INTO webhook_events(webhook_id,processed_at) VALUES(?,?)").bind(webhookId, now),
      env.DB.prepare("INSERT INTO decisions(decision_digest,event_digest,signed_json,created_at) VALUES(?,?,?,?)").bind(decisionDigest, row.event_digest, signedJson, now),
      env.DB.prepare("UPDATE events SET state = 'decided' WHERE event_digest = ? AND state = 'pending'").bind(row.event_digest),
    ]);
    if (results[0]?.meta?.changes !== 1 || results[1]?.meta?.changes !== 1 || results[2]?.meta?.changes !== 1) throw new Error("decision transaction did not commit exactly once");
  } catch {
    try {
      const replay = await env.DB.prepare("SELECT webhook_id FROM webhook_events WHERE webhook_id = ?").bind(webhookId).first();
      if (replay) {
        await answerTelegramCallback(env, callbackId, "Already processed.");
        return response(200, { status: "duplicate" });
      }
    } catch {
      // Fall through to a retryable response.
    }
    await answerTelegramCallback(env, callbackId, "Temporary error; please try again.", true);
    return response(503, { error: "temporary_decision_failure" });
  }
  await answerTelegramCallback(
    env,
    callbackId,
    command === "approve"
      ? "Approved for offline validation."
      : command === "execute"
        ? "Approved exact artifact for live execution."
        : "Denied.",
  );
  return response(200, { status: "decision_recorded" });
}

async function pairTelegramRecipient(request, env) {
  if (!(await authorized(request, env))) return response(401, { error: "unauthorized" });
  if (deliveryProvider(env) !== "telegram" || !configurationReady(env)) return response(503, { error: "not_ready" });
  const nonce = request.headers.get("x-iou-relay-nonce") || "";
  const proof = request.headers.get("x-iou-relay-proof") || "";
  if (!/^[0-9a-f]{64}$/.test(nonce) || !/^[0-9a-f]{64}$/.test(proof)) return response(400, { error: "invalid_setup_proof" });
  const expected = await hmacHex(env.DECISION_HMAC_KEY, `telegram-pair.v1:${nonce}`);
  if (!(await timingSafeText(proof, expected))) return response(401, { error: "unauthorized" });

  const existing = await telegramRecipient(env);
  if (existing) return response(200, { schema_version: "telegram-pair.v1", status: "paired" });

  let result;
  try {
    result = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/getUpdates`, {
      method: "POST",
      redirect: "error",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ allowed_updates: ["message"], limit: 10, timeout: 0 }),
    });
  } catch {
    return response(503, { error: "telegram_pairing_connection_failed" });
  }
  const body = await result.text();
  if (!result.ok) {
    return response(503, { error: `telegram_pairing_upstream_http_${safeTelegramStatus(result.status)}` });
  }
  if (enc.encode(body).byteLength > 65536) return response(503, { error: "telegram_pairing_response_too_large" });
  let updates;
  try {
    const value = JSON.parse(body);
    if (value?.ok !== true || !Array.isArray(value.result)) throw new Error("unexpected pairing result");
    updates = value.result;
  } catch {
    return response(503, { error: "telegram_pairing_invalid_response" });
  }

  const candidates = new Set();
  for (const update of updates) {
    const message = update?.message;
    const chatId = message?.chat?.id;
    if (!Number.isSafeInteger(update?.update_id) || update.update_id < 0
        || message?.chat?.type !== "private"
        || !Number.isSafeInteger(chatId) || !TELEGRAM_CHAT_ID.test(String(chatId))
        || !Number.isSafeInteger(message?.from?.id) || message.from.id !== chatId
        || message.from.is_bot === true
        || !/^\/start(?:@[A-Za-z0-9_]{5,32})?$/.test(message?.text || "")) continue;
    candidates.add(String(chatId));
  }
  if (candidates.size !== 1) return response(409, { error: candidates.size ? "telegram_pairing_ambiguous" : "telegram_pairing_pending" });
  const chatId = [...candidates][0];
  try {
    const stored = await env.DB.prepare("INSERT INTO telegram_recipient(singleton,chat_id,paired_at) VALUES(1,?,?)")
      .bind(chatId, new Date().toISOString()).run();
    if (stored.meta.changes !== 1) throw new Error("recipient was not stored exactly once");
  } catch {
    const concurrent = await telegramRecipient(env);
    if (concurrent) return response(200, { schema_version: "telegram-pair.v1", status: "paired" });
    return response(503, { error: "temporary_storage_failure" });
  }
  return response(200, { schema_version: "telegram-pair.v1", status: "paired" });
}

async function configureTelegramWebhook(request, env) {
  if (!(await authorized(request, env))) return response(401, { error: "unauthorized" });
  if (deliveryProvider(env) !== "telegram" || !(await deliveryReady(env))) return response(503, { error: "not_ready" });
  const nonce = request.headers.get("x-iou-relay-nonce") || "";
  const proof = request.headers.get("x-iou-relay-proof") || "";
  if (!/^[0-9a-f]{64}$/.test(nonce) || !/^[0-9a-f]{64}$/.test(proof)) return response(400, { error: "invalid_setup_proof" });
  const expected = await hmacHex(env.DECISION_HMAC_KEY, `telegram-webhook.v1:${nonce}`);
  if (!(await timingSafeText(proof, expected))) return response(401, { error: "unauthorized" });
  let result;
  try {
    result = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/setWebhook`, {
      method: "POST",
      redirect: "error",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        allowed_updates: ["callback_query"],
        secret_token: env.TELEGRAM_WEBHOOK_SECRET,
        url: `${new URL(request.url).origin}/webhooks/telegram`,
      }),
    });
  } catch {
    return response(503, { error: "telegram_setup_connection_failed" });
  }
  const body = await result.text();
  if (!result.ok) {
    return response(503, { error: `telegram_setup_upstream_http_${safeTelegramStatus(result.status)}` });
  }
  if (enc.encode(body).byteLength > 65536) return response(503, { error: "telegram_setup_response_too_large" });
  try {
    const value = JSON.parse(body);
    if (value?.ok !== true || value?.result !== true) throw new Error("unexpected setup result");
  } catch {
    return response(503, { error: "telegram_setup_invalid_response" });
  }
  return response(200, { schema_version: "telegram-webhook.v1", status: "configured" });
}

async function recordIgnoredWebhook(env, webhookId, status) {
  try {
    const inserted = await env.DB.prepare("INSERT OR IGNORE INTO webhook_events(webhook_id,processed_at) VALUES(?,?)")
      .bind(webhookId, new Date().toISOString()).run();
    return response(200, { status: inserted.meta.changes ? status : "duplicate" });
  } catch {
    return response(503, { error: "temporary_storage_failure" });
  }
}

async function recordFinalizedWebhook(env, webhookId, payload) {
  const messageId = payload?.id;
  const finalStatus = payload?.to?.[0]?.status;
  const allowed = ["delivered", "sending_failed", "delivery_failed", "delivery_unconfirmed"];
  if (typeof messageId !== "string" || !allowed.includes(finalStatus)) return recordIgnoredWebhook(env, webhookId, "ignored");
  const deliveryState = finalStatus === "delivered" ? "delivered" : "failed";
  try {
    await env.DB.batch([
      env.DB.prepare("INSERT INTO webhook_events(webhook_id,processed_at) VALUES(?,?)").bind(webhookId, new Date().toISOString()),
      env.DB.prepare("UPDATE events SET delivery_state = ?, telnyx_final_status = ? WHERE telnyx_message_id = ?")
        .bind(deliveryState, finalStatus, messageId),
    ]);
    return response(200, { status: "delivery_recorded" });
  } catch {
    try {
      const replay = await env.DB.prepare("SELECT webhook_id FROM webhook_events WHERE webhook_id = ?").bind(webhookId).first();
      if (replay) return response(200, { status: "duplicate" });
    } catch {
      // Fall through to a retryable response.
    }
    return response(503, { error: "temporary_delivery_status_failure" });
  }
}

async function listDecisions(request, env) {
  if (!(await authorized(request, env))) return response(401, { error: "unauthorized" });
  if (!(await deliveryReady(env))) return response(503, { error: "not_ready" });
  const afterRaw = new URL(request.url).searchParams.get("after") || "0";
  if (!/^[0-9]{1,18}$/.test(afterRaw)) return response(400, { error: "invalid_cursor" });
  const after = Number(afterRaw);
  if (!Number.isSafeInteger(after)) return response(400, { error: "invalid_cursor" });
  const result = await env.DB.prepare("SELECT sequence,signed_json FROM decisions WHERE sequence > ? ORDER BY sequence ASC LIMIT 100").bind(after).all();
  const data = result.results.map((row) => JSON.parse(row.signed_json));
  const next = result.results.length ? result.results[result.results.length - 1].sequence : after;
  return response(200, { schema_version: "relay-decisions.v1", data, next_cursor: String(next) });
}

async function relayReady(request, env) {
  // This endpoint is deliberately authenticated even though it exposes only a
  // fixed status.  It provides the Michigan host a way to verify the exact
  // bearer token, configuration, and D1 binding without submitting an event
  // (which could send an SMS) or receiving an inbound command (which could
  // create a signed decision).
  if (!(await authorized(request, env))) return response(401, { error: "unauthorized" });
  if (!(await deliveryReady(env))) return response(503, { error: "not_ready" });
  const nonce = request.headers.get("x-iou-relay-nonce") || "";
  const proof = request.headers.get("x-iou-relay-proof") || "";
  if (!/^[0-9a-f]{64}$/.test(nonce) || !/^[0-9a-f]{64}$/.test(proof)) {
    return response(400, { error: "invalid_readiness_proof" });
  }
  try {
    const expected = await hmacHex(env.DECISION_HMAC_KEY, `relay-ready.v1:${nonce}`);
    if (!(await timingSafeText(proof, expected))) return response(401, { error: "unauthorized" });
  } catch {
    return response(503, { error: "not_ready" });
  }
  try {
    const result = await env.DB.prepare("SELECT 1 AS ready").first();
    if (Number(result?.ready) !== 1) throw new Error("readiness query failed");
  } catch {
    return response(503, { error: "not_ready" });
  }
  return response(200, { schema_version: "relay-ready.v1", status: "ready" });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/healthz") {
      const ready = await deliveryReady(env);
      return response(ready ? 200 : 503, { status: ready ? "ready" : "not_ready" });
    }
    if (request.method === "GET" && url.pathname === "/v1/ready") return relayReady(request, env);
    if (request.method === "POST" && url.pathname === "/v1/events") return acceptEvent(request, env);
    if (request.method === "POST" && url.pathname === "/webhooks/telnyx") return receiveTelnyx(request, env);
    if (request.method === "POST" && url.pathname === "/webhooks/telegram") return receiveTelegram(request, env);
    if (request.method === "POST" && url.pathname === "/v1/telegram/pair") return pairTelegramRecipient(request, env);
    if (request.method === "POST" && url.pathname === "/v1/telegram/configure-webhook") return configureTelegramWebhook(request, env);
    if (request.method === "GET" && url.pathname === "/v1/decisions") return listDecisions(request, env);
    return response(404, { error: "not_found" });
  },
};

export { canonical, configurationReady, formatUsd, renderEvent, validateEvent };
