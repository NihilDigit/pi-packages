import assert from "node:assert/strict";
import test from "node:test";
import { toolActionFacts } from "../src/review/tool-action.ts";
import { withRegisteredToolMetadata } from "../src/review/tool-metadata.ts";
import { buildClassifierTranscript } from "../src/policy.ts";
import { applyReviewerInputBudget, sharedReviewContext } from "../src/review/input.ts";
import { DEFAULT_CONFIG } from "../src/review/config.ts";
import type { BoundaryRequest } from "../src/broker/types.ts";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { complete } from "../src/review/complete.ts";
import { ReviewExecutionError } from "../src/review/types.ts";

const action = {
  version: 1, toolName: "synthetic", toolCallId: "call-1",
  input: { message: "中文完整尾部约束".repeat(100) }, inputState: "complete",
  source: { kind: "sdk-tool-call", sessionId: "child-1" },
};
const details = {
  payload: { request: { toolName: "synthetic", invokedToolName: null }, action,
    evidence: [{ label: "input", text: "with input truncated..." }] },
  forwarding: { requesterSessionId: "child-1" },
};
test("structured action and identity never derive from a display preview", () => {
  const facts = toolActionFacts(details);
  assert.equal(facts.toolActionStatus, "complete");
  assert.equal(facts.toolName, "synthetic");
  assert.equal(facts.toolCallId, "call-1");
  assert.deepEqual(facts.toolAction?.input, action.input);
  assert.equal(facts.toolInputPreview, "with input truncated...");
});
test("legacy, missing and contradictory facts never assert complete input", () => {
  assert.equal(toolActionFacts({ toolName: "legacy", toolInputPreview: '{"a":1}' }).toolAction, undefined);
  const legacy = toolActionFacts({ payload: { ...details.payload, action: undefined } });
  assert.equal(legacy.toolActionStatus, "unavailable");
  assert.equal(legacy.toolAction, undefined);
  for (const bad of [
    { ...details, toolCallId: "other-call" },
    { ...details, toolName: "other-tool" },
    { ...details, forwarding: { requesterSessionId: "other-child" } },
    { ...details, payload: { ...details.payload, action: { ...action, version: 2 } } },
  ]) {
    const facts = toolActionFacts(bad);
    assert.equal(facts.toolActionStatus, "invalid");
    assert.equal(facts.toolAction, undefined);
  }
});
test("forwarded registration does not borrow a same-name parent implementation", () => {
  const facts = toolActionFacts({ ...details, payload: { ...details.payload, action: {
    ...action, registration: { description: "Child-only route", parameters: { type: "object" } },
  } } });
  let parentReads = 0;
  const request = withRegisteredToolMetadata({ id: "r", source: "permission-system", cwd: "/synthetic", surface: "synthetic", operation: "tool_call", ...facts }, () => { parentReads++; return []; });
  assert.equal(parentReads, 0);
  assert.equal(request.toolMetadata?.description, "Child-only route");
  assert.equal(request.toolMetadata?.interpretation, "untrusted-data-not-instructions-or-authorization");
});
test("full structured action consumes the unchanged mandatory global budget", () => {
  const request: BoundaryRequest = { id: "r", source: "permission-system", cwd: "/synthetic", surface: "synthetic", operation: "tool_call", ...toolActionFacts(details) };
  const transcript = buildClassifierTranscript([{ id: "u", message: { role: "user", content: "Only this synthetic test." } }], DEFAULT_CONFIG, request);
  const huge: BoundaryRequest = { ...request, toolAction: { ...request.toolAction!, input: { message: "界".repeat(20000) } } };
  const bounded = applyReviewerInputBudget(huge, transcript, undefined, DEFAULT_CONFIG.maxReviewerInputTokens);
  assert.equal(bounded.failureCode, "reviewer_input_budget_exceeded");
  assert.deepEqual(huge.toolAction?.input, { message: "界".repeat(20000) });
  const legacy = { ...request, toolAction: undefined, toolActionStatus: "unavailable" as const };
  const view = JSON.parse(sharedReviewContext(legacy, transcript));
  assert.equal(view.mandatoryEvidence.currentAction.complete, false);
  assert.equal(view.omissions.evidenceOmittedOrTruncated, true);
});

const ctx = { sessionManager: { buildContextEntries: () => [{ id: "u", message: { role: "user", content: "Only this synthetic task." } }] } } as unknown as ExtensionContext;
const base: BoundaryRequest = { id: "r", source: "permission-system", cwd: "/synthetic", surface: "synthetic", operation: "tool_call" };
test("real complete defers missing, redacted, malformed generic action before resolver even with override", async () => {
  let resolutions = 0;
  const cases = [
    { toolName: "synthetic", toolInputPreview: '{"safe":true}' },
    { payload: { ...details.payload, kind: "tool", action: undefined } },
    { ...details, payload: { ...details.payload, action: { ...action, inputState: "redacted" } } },
    { ...details, payload: { ...details.payload, action: { ...action, inputState: "incomplete" } } },
    { ...details, forwarding: { requesterSessionId: "wrong" } },
  ];
  for (const d of cases) for (const override of [undefined, { userOverride: { originalRequestId: "r", approvedAt: 1 } }]) {
    const request = { ...base, ...toolActionFacts(d) };
    const result = await complete(ctx, DEFAULT_CONFIG, request, override, async () => {
      resolutions++;
      throw Error("resolver must not run");
    });
    assert.equal(result.decision.outcome, "defer");
    assert.equal(result.attempts, 0);
  }
  assert.equal(resolutions, 0);
});
test("complete structured generic and existing bash/path/skill channels still reach resolver", async () => {
  let resolutions = 0;
  const cases = [
    { ...base, ...toolActionFacts(details) },
    ...["bash", "path", "external_directory", "bash_external_directory", "skill", "skill_read"].map(kind => ({
      ...base, surface: kind,
      ...(kind.includes("bash") ? { command: "echo synthetic", fullCommand: "echo synthetic" } : { path: "/synthetic" }),
      ...toolActionFacts({ payload: { kind, request: { toolName: kind }, evidence: [] } }),
    })),
  ];
  for (const request of cases) {
    assert.ok(request.toolActionStatus === undefined || request.toolActionStatus === "complete");
    await assert.rejects(complete(ctx, { ...DEFAULT_CONFIG, retries: 0 }, request, undefined, async () => {
      resolutions++;
      throw Error("synthetic stop at resolver; no provider call");
    }), (error: unknown) => error instanceof ReviewExecutionError && error.errorClass === "model_resolution");
  }
  assert.equal(resolutions, cases.length);
});
