import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { protectedWriteHardDeny } from "../src/review/guards.ts";
import { userConfigPath } from "../src/review/config.ts";
import { defaultPolicyAuditDirectory } from "../src/policy-audit/store.ts";

test("custom profile installation pointers cannot be rewritten through a tool", () => {
  const previous = process.env.PI_CODING_AGENT_DIR;
  const directory = mkdtempSync(join(tmpdir(), "reviewer-profile-"));
  process.env.PI_CODING_AGENT_DIR = directory;
  try {
    assert.equal(userConfigPath(), join(directory, "extensions/pi-auto-review/config.json"));
    assert.equal(defaultPolicyAuditDirectory(), join(directory, "extensions/pi-auto-review"));
    const result = protectedWriteHardDeny({ id: "write-pointer", source: "test", surface: "filesystem-write", operation: "write", cwd: directory, path: join(directory, "pi-thagoras.json") });
    assert.equal(result?.rule, "security-control-tampering");
  } finally {
    if (previous === undefined) delete process.env.PI_CODING_AGENT_DIR;
    else process.env.PI_CODING_AGENT_DIR = previous;
  }
});

test("reading non-secret installation metadata does not trigger write protection", () => {
  const directory = process.env.PI_CODING_AGENT_DIR ?? join(tmpdir(), "read-only-profile");
  assert.equal(protectedWriteHardDeny({ id: "read-pointer", source: "test", surface: "path", operation: "read", cwd: directory, path: join(directory, "pi-thagoras.json") }), undefined);
});
