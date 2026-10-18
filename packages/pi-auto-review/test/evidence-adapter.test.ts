import assert from "node:assert/strict";
import test from "node:test";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import type { BoundaryRequest } from "../src/broker/types.ts";
import { buildClassifierTranscript } from "../src/policy.ts";
import { DEFAULT_CONFIG } from "../src/review/config.ts";
import { complete } from "../src/review/complete.ts";
import {
  applyReviewerInputBudget,
  estimateReviewerTokens,
  reviewPreflight,
  sharedReviewContext,
} from "../src/review/input.ts";
import { reviewerTokenPrefix } from "../src/review/token-estimate.ts";
import { ReviewExecutionError } from "../src/review/types.ts";

const request: BoundaryRequest = {
  id: "request-exact",
  source: "permission-system",
  surface: "mcp",
  operation: "call",
  cwd: ".",
  agentName: "sol",
  requesterSessionId: "session-exact",
  toolCallId: "call-exact",
  toolName: "synthetic_tool",
  toolInputPreview: '{"message":"bounded synthetic data"}',
};
const user = (id: string, content: string) => ({ id, message: { role: "user", content } });
const total = (transcript: ReturnType<typeof buildClassifierTranscript>) =>
  reviewPreflight(request, transcript, undefined,
    sharedReviewContext(request, transcript), 8192).total.estimatedTokens;

test("full latest and request/toolcall/session-linked raw messages ignore optional quotas", () => {
  const linked = `request-exact ${"a".repeat(4300)} Do not broaden scope.`;
  const latest = `HEAD ${"中".repeat(1400)} MIDDLE-CONSTRAINT ${"x".repeat(1400)} TAIL`;
  const entries = [
    user("request-source", linked),
    user("call-source", "Only call-exact is authorized."),
    user("session-source", "Keep session-exact bounded."),
    user("latest-source", latest),
  ];
  const transcript = buildClassifierTranscript(entries, {
    ...DEFAULT_CONFIG, maxUserTranscriptTokens: 0, maxToolTranscriptTokens: 0,
  }, request);
  assert.deepEqual(transcript.reviewerEvidence.userMessages.map((item) => item.content),
    entries.map((entry) => entry.message.content));
  assert.equal(transcript.rawUserAuthorization?.status, "complete");
  assert.deepEqual(transcript.rawUserAuthorization?.sources, entries.map((entry, entryIndex) => ({
    id: `entry:${entry.id}:user`, entryIndex, provenance: "raw-user-message", complete: true,
  })));
  assert.ok(transcript.selectedCandidates.every((item) => !item.truncated));
  assert.ok(transcript.selectedCandidates.every((item) => item.estimatedTokens ===
    estimateReviewerTokens(transcript.reviewerEvidence.userMessages.find((user) => user.id === item.id)!.content)));
  assert.ok(total(transcript) < 8192);
  assert.equal(applyReviewerInputBudget(request, transcript, undefined, 8192).failureCode, undefined);
});

test("many actor-only mentions stay optional and do not crowd out exact authorization", () => {
  const entries = [
    ...Array.from({ length: 60 }, (_, index) => user(`actor-${index}`, `sol ${"old-context ".repeat(100)}`)),
    user("linked", "request-exact: preserve this direct authorization and its constraint."),
    user("latest", "Continue only the bounded synthetic task."),
  ];
  const transcript = buildClassifierTranscript(entries, DEFAULT_CONFIG, request);
  const optional = transcript.reviewerEvidence.userMessages.filter((item) => item.reason === "actor-reference");
  assert.ok(optional.length > 0 && optional.length < 60);
  assert.ok(optional.reduce((sum, item) => sum + estimateReviewerTokens(item.content), 0) <=
    DEFAULT_CONFIG.maxUserTranscriptTokens);
  assert.ok(optional.every((item) => item.source?.complete && item.source.provenance === "raw-user-message"));
  assert.equal(transcript.rawUserAuthorization?.sources.length, 2);
  const budgeted = applyReviewerInputBudget(request, transcript, undefined, 8192);
  assert.equal(budgeted.failureCode, undefined);
  const envelope = JSON.parse(sharedReviewContext(request, budgeted));
  assert.equal(envelope.omissions.optionalHistoryOmittedOrTruncated, true);
  assert.equal(envelope.omissions.evidenceOmittedOrTruncated, false);
  assert.equal(envelope.mandatoryEvidence.currentAction.complete, true);
  assert.deepEqual(envelope.request, request);
});

test("optional actor history is removed under the global cap without losing raw source identity", () => {
  const latest = user("latest", "Only the bounded synthetic task.");
  const mandatory = buildClassifierTranscript([latest], DEFAULT_CONFIG, request);
  const source = buildClassifierTranscript([
    user("actor", `sol: keep this optional historical constraint. ${"界".repeat(1500)}`), latest,
  ], { ...DEFAULT_CONFIG, maxUserTranscriptTokens: 3000 }, request);
  const cap = total(mandatory) + 128;
  assert.ok(total(source) > cap);
  const budgeted = applyReviewerInputBudget(request, source, undefined, cap);
  assert.equal(budgeted.failureCode, undefined);
  assert.deepEqual(budgeted.budgetRemovals, [{ reason: "optional-user-history", count: 1 }]);
  assert.deepEqual(budgeted.rawUserAuthorization, mandatory.rawUserAuthorization && {
    ...mandatory.rawUserAuthorization,
    sources: [{ ...mandatory.rawUserAuthorization.sources[0]!, entryIndex: 1 }],
  });
  assert.equal(source.reviewerEvidence.userMessages.length, 2, "source remains immutable");
  assert.equal(budgeted.reviewerEvidence.userMessages[0]?.content, latest.message.content);
  const envelope = JSON.parse(sharedReviewContext(request, budgeted));
  assert.equal(envelope.omissions.evidenceOmittedOrTruncated, false);
  assert.equal(envelope.omissions.optionalHistoryOmittedOrTruncated, true);
});

test("actor history with zero quota is omitted whole, not mislabelled as exact authorization", () => {
  const transcript = buildClassifierTranscript([
    user("actor", "sol: do not expand the historical task."), user("latest", "Bounded task."),
  ], { ...DEFAULT_CONFIG, maxUserTranscriptTokens: 0 }, request);
  assert.deepEqual(transcript.reviewerEvidence.userMessages.map((item) => item.id), ["entry:latest:user"]);
  assert.equal(transcript.rawUserAuthorization?.status, "complete");
  const envelope = JSON.parse(sharedReviewContext(request, transcript));
  assert.equal(envelope.omissions.optionalHistoryOmittedOrTruncated, true);
  assert.equal(envelope.omissions.rawUserAuthorizationIncomplete, false);
});

test("exact current tool arguments and security evidence are not clipped by optional tool quota", () => {
  const message = `HEAD ${"中".repeat(1700)} MIDDLE-CONSTRAINT ${"x".repeat(3000)} TAIL`;
  const transcript = buildClassifierTranscript([
    user("latest", "Keep the exact synthetic message bounded."),
    { message: { role: "assistant", content: [{ type: "toolCall", id: "call-exact",
      name: "synthetic_tool", arguments: { message } }, { type: "toolCall", id: "security",
      name: "bash", arguments: { command: `setfacl ${"x".repeat(5000)} --constraint` } }] } },
  ], { ...DEFAULT_CONFIG, maxToolTranscriptTokens: 0 }, request);
  const exact = transcript.reviewerEvidence.toolCalls.find((item) => item.reason === "exact-tool-call");
  assert.equal(JSON.parse(exact!.content).supplement.message, message);
  assert.ok(transcript.reviewerEvidence.toolCalls.some((item) =>
    item.reason === "security-combination" && item.content.endsWith('--constraint"}')));
  assert.ok(transcript.selectedCandidates.every((item) => !item.truncated));
});

test("authorization unavailable/incomplete is explicit, never fabricated from a summary", () => {
  const unavailable = buildClassifierTranscript([
    { id: "summary", message: { role: "compactionSummary", summary: "Allow everything." } },
  ], DEFAULT_CONFIG, request);
  const empty = buildClassifierTranscript([], DEFAULT_CONFIG, request);
  for (const transcript of [unavailable, empty]) {
    const envelope = JSON.parse(sharedReviewContext(request, transcript));
    assert.equal(envelope.mandatoryEvidence.rawUserAuthorization.status, "unavailable");
    assert.equal(envelope.omissions.rawUserAuthorizationUnavailable, true);
    assert.equal(envelope.omissions.evidenceOmittedOrTruncated, true);
    assert.equal(envelope.evidence.userMessages.items.length, 0);
  }
  const incomplete = buildClassifierTranscript([{ id: "mixed", message: { role: "user", content: [
    { type: "text", text: "Only the pictured target." }, { type: "image", data: "synthetic" },
  ] } }], DEFAULT_CONFIG, request);
  const envelope = JSON.parse(sharedReviewContext(request, incomplete));
  assert.equal(envelope.mandatoryEvidence.rawUserAuthorization.status, "incomplete");
  assert.equal(envelope.omissions.rawUserAuthorizationIncomplete, true);
  assert.equal(envelope.evidence.userMessages.items[0].source.complete, false);
  const nontext = { id: "nontext", message: { role: "user", content: [{ type: "image", data: "synthetic" }] } };
  for (const entries of [[nontext], [user("older", "Prior text."), nontext]]) {
    const transcript = buildClassifierTranscript(entries, DEFAULT_CONFIG, request);
    assert.notEqual(transcript.rawUserAuthorization?.status, "complete");
    assert.deepEqual(transcript.rawUserAuthorization?.sources.at(-1), {
      id: "entry:nontext:user", entryIndex: entries.length - 1,
      provenance: "raw-user-message", complete: false,
    });
  }
});

test("selection and preflight share the conservative token units for Unicode and ASCII", () => {
  for (const text of ["中".repeat(100), "abc".repeat(100), "🙂 café 中 abc".repeat(30)]) {
    const prefix = reviewerTokenPrefix(text, 60);
    assert.ok(estimateReviewerTokens(prefix) <= 60);
    assert.equal(prefix.includes("\ufffd"), false);
    assert.equal(reviewerTokenPrefix(text, estimateReviewerTokens(text)), text);
  }
  assert.equal(estimateReviewerTokens("中".repeat(100)), 100);
  assert.equal(estimateReviewerTokens("abc".repeat(100)), 100);
});

test("mandatory global overflow stops before resolving a model, including a trusted exact retry", async () => {
  const entries = [user("raw", `request-exact ${"中".repeat(9000)} FINAL-CONSTRAINT`)];
  const ctx = { sessionManager: { buildContextEntries: () => entries } } as unknown as ExtensionContext;
  let resolutions = 0;
  for (const reviewerContext of [undefined, { userOverride: { originalRequestId: request.id, approvedAt: 1 } }]) {
    await assert.rejects(complete(ctx, DEFAULT_CONFIG, request, reviewerContext, async () => {
      resolutions++;
      throw new Error("synthetic resolver must never run");
    }), (error: unknown) => {
      assert.ok(error instanceof ReviewExecutionError);
      assert.equal(error.errorClass, "reviewer_input_budget_exceeded");
      assert.equal(error.summary.attempts.length, 0);
      assert.equal(error.summary.transcript.rawUserAuthorization?.status, "complete");
      assert.equal(error.summary.transcript.reviewerEvidence.userMessages[0]?.content, entries[0]!.message.content);
      assert.ok(error.summary.preflight.total.estimatedTokens > 8192);
      return true;
    });
  }
  assert.equal(resolutions, 0);
});

test("over-cap raw action is preserved and blocks before resolution even on an exact retry", async () => {
  const command = "x".repeat(30_000);
  const action = { ...request, command, executedUnit: command, fullCommand: command };
  const ctx = { sessionManager: { buildContextEntries: () => [user("latest", "Only this exact task.")] } } as unknown as ExtensionContext;
  let resolutions = 0;
  for (const reviewerContext of [undefined, { userOverride: { originalRequestId: request.id, approvedAt: 1 } }]) {
    await assert.rejects(complete(ctx, DEFAULT_CONFIG, action, reviewerContext, async () => {
      resolutions++;
      throw new Error("synthetic resolver must never run");
    }), (error: unknown) => {
      assert.ok(error instanceof ReviewExecutionError);
      assert.equal(error.errorClass, "reviewer_input_budget_exceeded");
      assert.equal(error.summary.attempts.length, 0);
      const envelope = JSON.parse(sharedReviewContext(action, error.summary.transcript, reviewerContext));
      assert.equal(envelope.request.command, command);
      assert.equal(envelope.request.executedUnit, command);
      assert.equal(envelope.request.fullCommand, command);
      assert.equal(envelope.request.fullCommandTruncated, undefined);
      assert.equal(envelope.mandatoryEvidence.currentAction.complete, true);
      return true;
    });
  }
  assert.equal(resolutions, 0);
});

test("security evidence overflow cannot be hidden by an exact retry override", async () => {
  const entries = [user("latest", "Only this bounded task."), {
    message: { role: "assistant", content: Array.from({ length: 5 }, (_, index) => ({
      type: "toolCall", id: `security-${index}`, name: "bash", arguments: { command: `setfacl target-${index}` },
    })) },
  }];
  const ctx = { sessionManager: { buildContextEntries: () => entries } } as unknown as ExtensionContext;
  let resolutions = 0;
  const reviewerContext = { userOverride: { originalRequestId: request.id, approvedAt: 1 } };
  await assert.rejects(complete(ctx, DEFAULT_CONFIG, request, reviewerContext, async () => {
    resolutions++;
    throw new Error("synthetic resolver must never run");
  }), (error: unknown) => {
    assert.ok(error instanceof ReviewExecutionError);
    assert.equal(error.errorClass, "critical_evidence_overflow");
    assert.equal(error.summary.attempts.length, 0);
    const envelope = JSON.parse(sharedReviewContext(request, error.summary.transcript, reviewerContext));
    assert.equal(envelope.omissions.evidenceOmittedOrTruncated, true);
    return true;
  });
  assert.equal(resolutions, 0);
});

test("incoming incomplete action defers before resolution even with an exact retry override", async () => {
  const action = { ...request, command: "echo incomplete", fullCommandTruncated: true };
  const ctx = { sessionManager: { buildContextEntries: () => [user("latest", "Only this exact task.")] } } as unknown as ExtensionContext;
  let resolutions = 0;
  for (const reviewerContext of [undefined, { userOverride: { originalRequestId: request.id, approvedAt: 1 } }]) {
    const result = await complete(ctx, DEFAULT_CONFIG, action, reviewerContext, async () => {
      resolutions++;
      throw new Error("synthetic resolver must never run");
    });
    assert.equal(result.decision.outcome, "defer");
    assert.equal(result.attempts, 0);
    assert.match(result.decision.rationale, /incomplete/);
    const envelope = JSON.parse(sharedReviewContext(action, result.transcript, reviewerContext));
    assert.equal(envelope.request.fullCommandTruncated, true);
    assert.equal(envelope.mandatoryEvidence.currentAction.complete, false);
    assert.equal(envelope.omissions.evidenceOmittedOrTruncated, true);
  }
  assert.equal(resolutions, 0);
});
