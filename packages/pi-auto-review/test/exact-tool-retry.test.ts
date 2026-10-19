import assert from "node:assert/strict";
import test from "node:test";
import { BoundaryApprovalBroker } from "../src/broker/broker.ts";
import { boundaryRequestHash, OneShotGrantStore } from "../src/broker/grants.ts";
import { RecentDenialStore } from "../src/broker/overrides.ts";
import type { BoundaryRequest } from "../src/broker/types.ts";
import { buildClassifierTranscript } from "../src/policy.ts";
import { DEFAULT_CONFIG } from "../src/review/config.ts";
import { sharedReviewContext } from "../src/review/input.ts";

const input = { reason: "progress_update", message: `${"same-prefix ".repeat(30)}TARGET-A` };
const request: BoundaryRequest = {
  id: "original-denial", source: "permission-system", surface: "contact_supervisor", operation: "tool_call", cwd: ".",
  toolName: "contact_supervisor", toolCallId: "first-call", toolInputPreview: JSON.stringify(input).slice(0, 200),
  agentName: "sol", requesterSessionId: "child-session", toolActionStatus: "complete",
  toolAction: { version: 1, toolName: "contact_supervisor", toolCallId: "first-call", input,
    inputState: "complete", source: { kind: "sdk-tool-call", sessionId: "child-session" } },
};
const context = { sessionId: "parent-session", scopeKey: "turn-1" };
const denial = { outcome: "deny" as const, riskLevel: "high" as const, userAuthorization: "unknown" as const, rationale: "Synthetic denial." };
const changedInput = { ...input, message: `${"same-prefix ".repeat(30)}TARGET-B` };
const retry = { ...request, id: "fresh-request", toolCallId: "fresh-call",
  toolInputPreview: "a differently formatted display preview",
  toolAction: { ...request.toolAction!, toolCallId: "fresh-call", input: { message: input.message, reason: input.reason } },
};

test("an exact retry binds complete canonical input while allowing fresh correlation IDs", () => {
  assert.equal(boundaryRequestHash(request), boundaryRequestHash(retry));
  for (const changed of [
    { ...retry, toolAction: { ...retry.toolAction, input: changedInput } },
    { ...retry, toolAction: { ...retry.toolAction, source: { kind: "sdk-tool-call" as const, sessionId: "other-child" } } },
    { ...retry, toolAction: { ...retry.toolAction, toolName: "other_tool" } },
    { ...retry, toolActionStatus: "redacted" as const },
    { ...retry, toolAction: undefined },
  ]) assert.notEqual(boundaryRequestHash(request), boundaryRequestHash(changed));
});

test("same-preview input changes cannot consume a grant or approval; exact retry consumes once", () => {
  const changed = { ...request, toolAction: { ...request.toolAction!, input: changedInput } };
  assert.equal(request.toolInputPreview, changed.toolInputPreview);
  const grants = new OneShotGrantStore();
  const grant = grants.issue(request, context.sessionId);
  assert.equal(grants.consume(changed, context.sessionId, grant.token), false);
  assert.equal(grants.consume(retry, context.sessionId, grant.token), true);
  assert.equal(grants.consume(retry, context.sessionId, grant.token), false);
  const denials = new RecentDenialStore();
  denials.record(request, context, denial);
  denials.authorize(request.id, context.sessionId);
  assert.equal(denials.consume(changed, context), undefined);
  assert.equal(denials.consume(retry, { ...context, sessionId: "another-parent" }), undefined);
  assert.equal(denials.consume(retry, context)?.originalRequestId, request.id);
  assert.equal(denials.consume(retry, context), undefined);
});

test("broker supplies a trusted current-request binding only for the exact one-shot retry", async () => {
  const seen: Array<ReturnType<typeof JSON.parse>> = [];
  const broker = new BoundaryApprovalBroker({ reviewer: async (action, reviewerContext) => {
    const transcript = buildClassifierTranscript([
      { message: { role: "user", content: "Only report progress to the assigned supervisor." } },
    ], DEFAULT_CONFIG, action);
    const envelope = JSON.parse(sharedReviewContext(action, transcript, reviewerContext));
    seen.push(envelope);
    if (!envelope.override) return denial;
    assert.deepEqual(envelope.override, {
      approvedAt: envelope.override.approvedAt,
      originalRequestId: "original-denial", retryRequestId: "fresh-request",
      binding: "host-validated-session-and-exact-action", consumedForCurrentReview: true,
      kind: "trusted-exact-retry", trust: "host-generated",
    });
    assert.notEqual(envelope.override.originalRequestId, envelope.request.id);
    return { outcome: "allow", riskLevel: "medium", userAuthorization: "high", rationale: "Synthetic matched retry." };
  } });
  assert.equal((await broker.review(request, context)).kind, "deny");
  assert.ok(broker.authorizeRecentDenial(request.id, context.sessionId));
  assert.equal((await broker.review(retry, { ...context, scopeKey: "turn-2" })).kind, "allow");
  assert.equal((await broker.review({ ...retry, id: "third-request" }, { ...context, scopeKey: "turn-3" })).kind, "deny");
  assert.equal(seen.filter((item) => item.override).length, 1);
});
