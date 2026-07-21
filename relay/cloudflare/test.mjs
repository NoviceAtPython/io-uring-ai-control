import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { canonical, formatUsd, renderEvent, validateEvent } from "./src/index.js";

const vector = JSON.parse(await readFile(new URL("./test-vectors.json", import.meta.url), "utf8"));
validateEvent(vector.event);
assert.equal(renderEvent(vector.event), vector.fixed_message);
assert.equal(formatUsd(125000), "0.13");
assert.equal(formatUsd(625000), "0.63");
assert.equal(formatUsd(1125000), "1.13");
assert.equal(canonical({ b: 2, a: 1 }), '{"a":1,"b":2}');

const inconsistentBudget = structuredClone(vector.event);
inconsistentBudget.remaining_microdollars = 1000000;
assert.throws(() => validateEvent(inconsistentBudget), /inconsistent budget/);

const invalidTriage = {
  bug_class: "attacker controlled text",
  campaign_id: "campaign",
  created_at: "2026-07-16T20:00:00Z",
  event_kind: "crash_triage",
  kernel_context_confirmed: false,
  potential_high_value: false,
  reproductions: 1,
  schema_version: "redacted-event.v1",
  severity: "attention",
  stack_signature: `sha256:${"a".repeat(64)}`,
  target_hashes: {
    compiler_hash: `sha256:${"b".repeat(64)}`,
    fleet_config_hash: `sha256:${"c".repeat(64)}`,
    harness_hash: `sha256:${"d".repeat(64)}`,
    op_table_hash: `sha256:${"e".repeat(64)}`,
  },
  telemetry_packet_digest: `sha256:${"f".repeat(64)}`,
};
assert.throws(() => validateEvent(invalidTriage), /triage classification/);

const now = Date.now();
const executionEvent = {
  approval: {
    allowed_actions: ["approve_for_live_execution", "deny"],
    binding_digest: `sha256:${"1".repeat(64)}`,
    expires_at: new Date(now + 30 * 60 * 1000).toISOString().replace(/\.\d{3}Z$/, "Z"),
    human_code: "EXECUTE2",
    nonce: "2".repeat(64),
  },
  artifact_digest: `sha256:${"3".repeat(64)}`,
  artifact_manifest_digest: `sha256:${"4".repeat(64)}`,
  artifact_size_bytes: 19,
  candidate_digest: `sha256:${"5".repeat(64)}`,
  canary_report_digest: `sha256:${"6".repeat(64)}`,
  created_at: new Date(now).toISOString().replace(/\.\d{3}Z$/, "Z"),
  envelope_digest: `sha256:${"7".repeat(64)}`,
  event_kind: "execution_ready",
  promotion_scope: {
    campaign_id: "campaign:io-uring-native",
    destination_id: "native_ai_sync",
    max_artifacts: 1,
    mode: "afl_foreign_sync_seed",
    schema_version: "promotion-scope.v1",
    worker_set: "native_stable",
  },
  schema_version: "redacted-event.v2",
  severity: "action_required",
  target_hashes: {
    compiler_hash: `sha256:${"8".repeat(64)}`,
    fleet_config_hash: `sha256:${"9".repeat(64)}`,
    harness_hash: `sha256:${"a".repeat(64)}`,
    op_table_hash: `sha256:${"b".repeat(64)}`,
  },
  validation_report_digest: `sha256:${"c".repeat(64)}`,
};
validateEvent(executionEvent);
assert.match(renderEvent(executionEvent), /LIVE EXECUTION APPROVAL/);
const crossProtocol = structuredClone(executionEvent);
crossProtocol.approval.allowed_actions = ["approve_for_offline_validation", "deny"];
assert.throws(() => validateEvent(crossProtocol), /execution approval actions/);
const pathLikeScope = structuredClone(executionEvent);
pathLikeScope.promotion_scope.destination_id = "/root/fuzzer_workspace/nat_out";
assert.throws(() => validateEvent(pathLikeScope), /promotion destination/);

console.log("cloudflare relay vectors: ok");
