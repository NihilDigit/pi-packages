import assert from "node:assert/strict";
import test from "node:test";
import { buildClassifierTranscript } from "../src/policy.ts";

// Synthetic evidence only; exercise the public reviewer-evidence path.
const args = {
  options: { z: true, a: { count: 2, enabled: false } },
  items: [{ z: 1, a: "first" }, "second", null],
  note: "synthetic <tag> é",
};
const reordered = {
  note: args.note,
  items: [{ a: "first", z: 1 }, "second", null],
  options: { a: { enabled: false, count: 2 }, z: true },
};
const raw = JSON.stringify(args);
const reorderedRaw = JSON.stringify(reordered);

function representation(preview, input = args, request = {}) {
  const result = buildClassifierTranscript(
    [
      { id: "synthetic-user", message: { role: "user", content: "Review synthetic input." } },
      {
        id: "synthetic-assistant",
        message: {
          role: "assistant",
          content: [{ type: "toolCall", id: "synthetic-call", name: "synthetic", arguments: input }],
        },
      },
    ],
    { maxUserTranscriptTokens: 1200, maxToolTranscriptTokens: 1200 },
    { toolCallId: "synthetic-call", toolName: "synthetic", toolInputPreview: preview, ...request },
  );
  assert.equal(result.failureCode, undefined);
  assert.equal(result.truncated, false);
  assert.equal(result.reviewerEvidence.toolCalls.length, 1);
  const evidence = result.reviewerEvidence.toolCalls[0];
  assert.equal(evidence.reason, "exact-tool-call");
  const value = JSON.parse(evidence.content);
  assert.equal(value.id, "synthetic-call");
  assert.equal(value.name, "synthetic");
  assert.equal(value.reason, "exact-tool-call");
  return value;
}

for (const [label, preview] of [
  ["raw JSON", raw],
  ["input-prefixed JSON", `input ${raw}`],
  ["recursive object key reordering", reorderedRaw],
  ["input-prefixed recursive reordering", `input ${reorderedRaw}`],
  ["pretty JSON", JSON.stringify(reordered, null, 2)],
  ["input-prefixed pretty JSON", `input ${JSON.stringify(reordered, null, 2)}`],
  ["JSON outer whitespace", ` \n\t${reorderedRaw}\r\n `],
  ["input-prefixed JSON whitespace", `input \n ${reorderedRaw}\n`],
  ["equivalent Unicode escape", reorderedRaw.replace("é", "\\u00e9")],
  ["equivalent JSON number spelling", reorderedRaw.replace('"count":2', '"count":2e0')],
]) {
  test(`complete equivalent preview omits supplement: ${label}`, () => {
    assert.equal(Object.hasOwn(representation(preview), "supplement"), false);
  });
}

const missing = structuredClone(args);
delete missing.note;
const nestedMissing = structuredClone(args);
delete nestedMissing.options.a.enabled;
const nestedExtra = structuredClone(args);
nestedExtra.options.a.extra = "synthetic";
const reversed = { ...args, items: [...args.items].reverse() };
const stringNumber = structuredClone(args);
stringNumber.options.a.count = "2";
const numberBoolean = structuredClone(args);
numberBoolean.options.a.enabled = 0;
const stringNull = { ...args, items: [args.items[0], "second", "null"] };
const objectArray = { ...args, items: { 0: args.items[0], 1: "second", 2: null } };

for (const [label, preview] of [
  ["missing field", JSON.stringify(missing)],
  ["extra field", JSON.stringify({ ...args, extra: true })],
  ["missing nested field", JSON.stringify(nestedMissing)],
  ["extra nested field", JSON.stringify(nestedExtra)],
  ["array order changed", JSON.stringify(reversed)],
  ["number changed to string", JSON.stringify(stringNumber)],
  ["boolean changed to number", JSON.stringify(numberBoolean)],
  ["null changed to string", JSON.stringify(stringNull)],
  ["array changed to object", JSON.stringify(objectArray)],
  ["missing preview", undefined],
  ["empty preview", ""],
  ["truncated JSON", raw.slice(0, -1)],
  ["truncated input-prefixed JSON", `input ${raw.slice(0, -1)}`],
  ["raw trailing text", `${raw} trailing`],
  ["input-prefixed trailing text", `input ${raw} trailing`],
  ["leading text", `summary ${raw}`],
  ["concatenated JSON", `${raw}{}`],
  ["markdown fenced JSON", `\`\`\`json\n${raw}\n\`\`\``],
  ["JSON comment", `${raw} // comment`],
  ["input prefix without separator", `input${raw}`],
  ["nested input prefix", `input input ${raw}`],
  ["JSON string containing object", JSON.stringify(raw)],
  ["JSON null", "null"],
  ["JSON array", `[${raw}]`],
]) {
  for (const prefix of ["", "input "]) {
    // Undefined is a genuinely absent preview, not a stringified value.
    if (preview === undefined && prefix) continue;
    test(`non-equivalent preview retains supplement: ${prefix ? "prefixed " : ""}${label}`, () => {
      const value = representation(preview === undefined ? undefined : `${prefix}${preview}`);
      assert.deepEqual(value.supplement, args);
    });
  }
}

test("failed preview comparison preserves existing request field coverage", () => {
  const input = { command: "echo synthetic", options: { extra: true } };
  assert.deepEqual(
    representation('{"command":"echo synthetic"}', input, { command: input.command }).supplement,
    { options: input.options },
  );
});

test("array order and value types survive retained supplement", () => {
  const value = representation(JSON.stringify(reversed));
  assert.deepEqual(value.supplement.items, args.items);
  assert.equal(typeof value.supplement.options.a.count, "number");
  assert.equal(typeof value.supplement.options.a.enabled, "boolean");
  assert.equal(value.supplement.items[2], null);
});
