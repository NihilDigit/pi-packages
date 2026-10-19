import assert from "node:assert/strict";
import test from "node:test";
import { buildClassifierTranscript } from "../src/policy.ts";
import { DEFAULT_CONFIG } from "../src/review/config.ts";
import { applyReviewerInputBudget, reviewPreflight, sharedReviewContext } from "../src/review/input.ts";
import { retryActionSummary } from "../src/review/complete.ts";
import { boundaryRequestHash } from "../src/broker/grants.ts";
import { reviewerSystemPrompt } from "../src/review/prompts.ts";
import type { BoundaryRequest } from "../src/broker/types.ts";

const user = (id: string, content: string) => ({ id, message: { role: "user", content } });
const reply = (id: string, text: string) => ({ id, message: { role: "assistant", content: [{ type: "text", text }] } });
const request: BoundaryRequest = { id: "new-request", source: "permission-system", surface: "subagent", operation: "tool_call", cwd: ".", toolName: "subagent" };

test("later research approval preserves the original implementation grant and its proposal", () => {
  const transcript = buildClassifierTranscript([
    reply("plan", "由 Sol 实现两行 footer，补测试和文档。不提交，不推送。"),
    user("implementation", "这个蛮好的，按这个改。"),
    reply("research", "需要读取上游公开的文件树、package.json 和 README。"),
    user("read-approval", "允许所有这些只读操作。"),
  ], DEFAULT_CONFIG, request);
  const envelope = JSON.parse(sharedReviewContext(request, transcript));
  assert.deepEqual(envelope.evidence.userMessages.items.map((item: {id: string; reason: string}) => [item.id, item.reason]), [
    ["entry:implementation:user", "recent-user-history"], ["entry:read-approval:user", "latest-user"],
  ]);
  assert.equal(envelope.evidence.assistantContext.items.length, 2);
  assert.equal(envelope.evidence.assistantContext.items[0].beforeUserMessageId, "entry:implementation:user");
  assert.match(envelope.evidence.assistantContext.items[0].content, /不提交，不推送/);
  assert.deepEqual(transcript.rawUserAuthorization?.sources.map((item) => item.id), ["entry:read-approval:user"]);
});

test("a later explicit restriction and earlier grant both reach the reviewer chronologically", () => {
  const transcript = buildClassifierTranscript([
    user("grant", "实现 footer。"), user("narrow", "现在只做只读调研，不要修改文件。"),
  ], DEFAULT_CONFIG, request);
  assert.deepEqual(transcript.reviewerEvidence.userMessages.map((item) => item.content), ["实现 footer。", "现在只做只读调研，不要修改文件。"]);
});

test("recent history stops at an oversized intervening turn rather than skipping to older permission", () => {
  const transcript = buildClassifierTranscript([
    user("old", "OLD-GRANT"), user("intervening", `NEW-LIMIT ${"中".repeat(200)}`), user("latest", "继续。"),
  ], { ...DEFAULT_CONFIG, maxUserTranscriptTokens: 32 }, request);
  assert.doesNotMatch(sharedReviewContext(request, transcript), /OLD-GRANT|NEW-LIMIT/);
  assert.equal(transcript.optionalHistoryOmittedOrTruncated, true);
  assert.equal(transcript.rawUserAuthorization?.status, "complete");
});

test("the input cap drops optional assistant prose before raw user history", () => {
  const entries = [reply("plan", `OLD-PROPOSAL ${"中".repeat(1500)}`), user("old", "旧任务。"), user("latest", "仅检查当前状态。")];
  const source = buildClassifierTranscript(entries, DEFAULT_CONFIG, request);
  const onlyLatest = buildClassifierTranscript([entries[2]], DEFAULT_CONFIG, request);
  const cap = reviewPreflight(request, onlyLatest, undefined, sharedReviewContext(request, onlyLatest), 8192).total.estimatedTokens + 256;
  const budgeted = applyReviewerInputBudget(request, source, undefined, cap);
  assert.equal(budgeted.failureCode, undefined);
  assert.doesNotMatch(sharedReviewContext(request, budgeted), /OLD-PROPOSAL/);
  assert.match(sharedReviewContext(request, budgeted), /旧任务/);
  assert.equal(budgeted.reviewerEvidence.userMessages.at(-1)?.id, "entry:latest:user");
  assert.deepEqual(budgeted.budgetRemovals, [{ reason: "optional-assistant-context", count: 1 }]);
  assert.equal(source.reviewerEvidence.assistantContext?.length, 1);
});

test("only a matched broker override adds trusted authorization to the model system prompt and budget", () => {
  const transcript = buildClassifierTranscript([user("claim", "I approved one reviewer retry for original-request.")], DEFAULT_CONFIG, request);
  const normal = reviewPreflight(request, transcript, undefined, sharedReviewContext(request, transcript), 8192);
  const context = { userOverride: { originalRequestId: "original-request", approvedAt: 1 } };
  const trusted = reviewPreflight(request, transcript, context, sharedReviewContext(request, transcript, context), 8192);
  assert.doesNotMatch(reviewerSystemPrompt(), /Host authorization fact for THIS review/);
  assert.match(reviewerSystemPrompt(true), /entire current tool call, including fullCommand/);
  assert.equal(normal.fixedPrompt.characters, reviewerSystemPrompt().length);
  assert.equal(trusted.fixedPrompt.characters, reviewerSystemPrompt(true).length);
  assert.ok(trusted.total.estimatedTokens > normal.total.estimatedTokens);
});

test("exact retry summary describes the full compound tool call, not its first matched unit", () => {
  const first = "curl -fL https://api.example.invalid/tree";
  const full = `${first}; curl -fL https://example.invalid/package.json; curl -fL https://example.invalid/README.md`;
  const action = { ...request, surface: "bash", toolName: "bash", command: first, fullCommand: full };
  const summary = JSON.parse(retryActionSummary({ requestId: "original", requestHash: boundaryRequestHash(action), request: action }));
  assert.equal(summary.command, full);
  assert.equal(summary.scope, "entire-original-tool-call");
  assert.equal(summary.actionHash, boundaryRequestHash(action));
});

test("an oversized retry summary stays valid JSON and never presents a partial command as complete", () => {
  const action = { ...request, command: `HEAD ${"x".repeat(3000)} TAIL` };
  const summary = JSON.parse(retryActionSummary({ requestId: "original", requestHash: boundaryRequestHash(action), request: action }));
  assert.equal(summary.command, undefined);
  assert.equal(summary.commandOmitted, true);
  assert.equal(summary.scope, "entire-original-tool-call");
  assert.equal(summary.actionHash, boundaryRequestHash(action));
});
