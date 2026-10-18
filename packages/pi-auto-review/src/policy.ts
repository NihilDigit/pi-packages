import { isPathSurface } from "./path-surfaces.ts";
import { estimateReviewerTokens, reviewerTokenPrefix } from "./review/token-estimate.ts";
import {
  shellExpansionLimitExceeded,
  structuralScanText,
} from "./review/shell-text.ts";

export type RiskLevel = "low" | "medium" | "high" | "critical";

export type ModelDecision = {
  outcome: "allow" | "deny" | "defer";
  risk_level: RiskLevel;
  user_authorization: "unknown" | "low" | "medium" | "high";
  rationale: string;
};

export type PermissionDetailsLike = {
  surface?: string | null;
  value?: unknown;
  toolName?: string;
  skillName?: string;
  command?: unknown;
  path?: unknown;
  target?: unknown;
  agentName?: unknown;
  toolInputPreview?: unknown;
  accessIntent?: unknown;
  forwarding?: unknown;
  /** Structured permission-system ask; the only source of the execution facts. */
  payload?: unknown;
  /** Pre-projected execution facts (broker hard-deny entry). */
  executedUnit?: unknown;
  fullCommand?: unknown;
  matchedPattern?: unknown;
  matchedSpelling?: unknown;
};

export type NormalizedPermissionEvidence = {
  surface: string;
  value?: string;
  command?: string;
  executedUnit?: string;
  fullCommand?: string;
  matchedPattern?: string;
  /**
   * The spelling of the bash unit the matched rule hit when it did not match
   * the command as typed — the absolute spelling of a relative path argument,
   * say (permission-system #910). Display-only: absent whenever the typed text
   * decided.
   */
  matchedSpelling?: string;
  path?: string;
  resolvedPath?: string;
  destination?: string;
  accessIntent?: {
    surface: string;
    matchValues: readonly string[];
    boundaryValue?: string;
  };
  requester?: {
    agentName?: string;
    sessionId?: string;
  };
};

export type TranscriptConfig = {
  maxUserTranscriptTokens: number;
  maxToolTranscriptTokens: number;
  maxRelevantResultTokens?: number;
};

export type TranscriptResult = {
  text: string;
  surfaceProfile: EvidenceSurfaceProfile;
  reviewerEvidence: {
    userMessages: ReviewerEvidenceItem[];
    toolCalls: ReviewerEvidenceItem[];
    relevantResults: ReviewerEvidenceItem[];
  };
  budgetRemovals: ReviewerBudgetRemoval[];
  userCharacters: number;
  toolCharacters: number;
  relevantResultCharacters: number;
  truncated: boolean;
  optionalHistoryOmittedOrTruncated?: boolean;
  selectedCandidates: EvidenceCandidateMetadata[];
  failureCode?:
    | "critical_evidence_overflow"
    | "required_profile_overflow"
    | "reviewer_input_budget_exceeded";
  userAuthorizationCeiling: "unknown" | "low" | "medium" | "high";
  userConstraint: "none" | "narrowed" | "revoked";
  compactionState: "none" | "summary-present" | "authorization-unavailable";
  rawUserAuthorization?: {
    status: "complete" | "incomplete" | "unavailable";
    sources: Array<{
      id: string;
      entryIndex: number;
      provenance: "raw-user-message";
      complete: boolean;
    }>;
  };
};

export type ReviewerBudgetRemoval = {
  reason:
    | "secondary-reasons"
    | "older-structured-tool"
    | "optional-result"
    | "optional-user-history";
  count: number;
};

export type ReviewerEvidenceItem = {
  id: string;
  reason: EvidenceSelectionReason;
  secondaryReasons: EvidenceSelectionReason[];
  toolCallId?: string;
  content: string;
  source?: {
    entryIndex: number;
    provenance: "raw-user-message";
    complete: boolean;
  };
};

type Evidence = {
  id: string;
  index: number;
  entryIndex: number;
  kind: "user" | "tool";
  text: string;
  toolCallId?: string;
  reason: EvidenceSelectionReason;
  secondaryReasons: EvidenceSelectionReason[];
  sensitivity: EvidenceSensitivity;
  originalCharacters: number;
  preTruncated: boolean;
  representationCharacters?: number;
};

export type EvidenceSensitivity =
  | "user-intent"
  | "tool-input"
  | "tool-output"
  | "boundary"
  | "credential"
  | "permission-control"
  | "authorization-persistence"
  | "transport-weakening"
  | "audit-control"
  | "security-control";

export type EvidenceSelectionReason =
  | "latest-user"
  | "exact-request-reference"
  | "actor-reference"
  | "trusted-retry-user-message"
  | "exact-tool-call"
  | "structured-request-match"
  | "security-combination"
  | "same-tool"
  | "delete-precheck"
  | "git-push-context"
  | "provider-branch-protection"
  | "sandbox-trap";

export type EvidenceSurfaceProfile =
  | "network"
  | "delete"
  | "git-push"
  | "forwarded"
  | "generic";

export type EvidenceCandidateMetadata = {
  id: string;
  entryIndex: number;
  kind: "user" | "tool-call" | "tool-result" | "sandbox-trap";
  toolCallId?: string;
  reason: EvidenceSelectionReason;
  secondaryReasons: EvidenceSelectionReason[];
  surfaceProfile: EvidenceSurfaceProfile;
  originalCharacters: number;
  selectedCharacters: number;
  estimatedTokens: number;
  truncated: boolean;
  sensitivity: EvidenceSensitivity;
};

export type RelevantBoundaryRequest = {
  id?: string;
  source?: string;
  surface?: string;
  operation?: string;
  cwd?: string;
  command?: string;
  executedUnit?: string;
  fullCommand?: string;
  matchedPattern?: string;
  matchedSpelling?: string;
  path?: string;
  resolvedPath?: string;
  destination?: string;
  destinationHost?: string;
  destinationPort?: number;
  destinationProtocol?: string;
  toolCallId?: string;
  toolName?: string;
  toolInputPreview?: string;
  agentName?: string;
  requesterSessionId?: string;
  accessIntent?: {
    surface: string;
    matchValues: readonly string[];
    boundaryValue?: string;
  };
  trustedRetryOriginalRequestId?: string;
};

const MAX_EVIDENCE_ITEM_CHARACTERS = 4_000;

/** Stable compact JSON for reviewer-only representations. */
export function canonicalReviewerJson(value: unknown): string {
  return JSON.stringify(value, (_key, current: unknown) => {
    if (!current || typeof current !== "object" || Array.isArray(current)) {
      return current;
    }
    return Object.fromEntries(
      Object.keys(current as Record<string, unknown>)
        .sort()
        .map((key) => [key, (current as Record<string, unknown>)[key]]),
    );
  }) ?? "null";
}

function exactKeys(
  record: Record<string, unknown>,
  expected: readonly string[],
): boolean {
  const actual = Object.keys(record).sort();
  const wanted = [...expected].sort();
  return (
    actual.length === wanted.length &&
    actual.every((key, index) => key === wanted[index])
  );
}

// Some reviewer models (notably any routed through Claude Code, which always
// markdown-fences JSON) wrap the decision object in a ```json ... ``` block
// despite the prompt forbidding markdown. Strip a single enclosing fence before
// parsing; the strict shape validation below is unchanged.
function stripReviewerFence(text: string): string {
  const t = text.trim();
  const fenced = t.match(/^```(?:json)?\s*\n?([\s\S]*?)\n?```$/i);
  return (fenced?.[1] ?? t).trim();
}

export function parseDecision(text: string): ModelDecision {
  let value: unknown;
  try {
    value = JSON.parse(stripReviewerFence(text));
  } catch {
    throw new Error("reviewer returned non-JSON output");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("reviewer returned a non-object");
  }
  const record = value as Record<string, unknown>;
  const fields = ["outcome", "risk_level", "user_authorization", "rationale"];
  if (!Object.hasOwn(record, "outcome") || Object.keys(record).some(key => !fields.includes(key))) {
    throw new Error("reviewer returned unexpected fields");
  }
  // Public Codex CLI 0.162.0, c1382380, guardian-reviewer/assessment.rs:
  // model wire outcomes are allow/deny; optional fields use these defaults.
  // Runtime defer remains separate and cannot be supplied by the model.
  if (record.outcome !== "allow" && record.outcome !== "deny") {
    throw new Error("reviewer returned an invalid outcome");
  }
  const riskLevel = record.risk_level ?? (record.outcome === "allow" ? "low" : "high");
  const userAuthorization = record.user_authorization ?? "unknown";
  if (typeof riskLevel !== "string" || !["low", "medium", "high", "critical"].includes(riskLevel)) {
    throw new Error("reviewer returned an invalid risk level");
  }
  if (typeof userAuthorization !== "string" || !["unknown", "low", "medium", "high"].includes(userAuthorization)) {
    throw new Error("reviewer returned invalid user authorization");
  }
  if (record.rationale != null && typeof record.rationale !== "string") {
    throw new Error("reviewer returned an invalid rationale");
  }
  const rationale = typeof record.rationale === "string" && record.rationale.trim()
    ? record.rationale
    : record.outcome === "allow"
      ? "Auto-review returned a low-risk allow decision."
      : "Auto-review returned a deny decision without a rationale.";
  const decision = {
    outcome: record.outcome,
    risk_level: riskLevel,
    user_authorization: userAuthorization,
    rationale,
  } as ModelDecision;
  if (
    decision.outcome === "allow" &&
    decision.risk_level === "critical"
  ) {
    throw new Error("reviewer attempted a critical-risk allow");
  }
  if (
    decision.outcome === "allow" &&
    decision.risk_level === "high" &&
    !["medium", "high"].includes(decision.user_authorization)
  ) {
    throw new Error(
      "reviewer attempted an unauthorized high-risk allow",
    );
  }
  return decision;
}

function nonEmptyString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value : undefined;
}

function record(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function parsedPreviewCommand(value: unknown): string | undefined {
  const preview = nonEmptyString(value);
  if (!preview) return undefined;
  try {
    const parsed = JSON.parse(preview.trim().replace(/^input\s+/, ""));
    return nonEmptyString(record(parsed)?.command);
  } catch {
    // A bounded/truncated preview is deliberately not guessed.
    return undefined;
  }
}

function payloadFullCommand(
  payload: Record<string, unknown> | undefined,
): string | undefined {
  const evidence = payload?.evidence;
  if (!Array.isArray(evidence)) return undefined;
  for (const entry of evidence) {
    const candidate = record(entry);
    if (candidate?.label !== "full command") continue;
    const text = nonEmptyString(candidate.text);
    if (text) return text;
  }
  return undefined;
}

/** Normalize direct and forwarded permission-system evidence without trusting it. */
export function normalizePermissionEvidence(
  details: PermissionDetailsLike,
): NormalizedPermissionEvidence {
  const rawIntent = record(details.accessIntent);
  const intentSurface = nonEmptyString(rawIntent?.surface);
  const rawMatchValues = rawIntent?.matchValues;
  const matchValues =
    Array.isArray(rawMatchValues) &&
    rawMatchValues.every((item) => Boolean(nonEmptyString(item)))
      ? rawMatchValues as string[]
      : undefined;
  const accessIntent = intentSurface && matchValues
    ? {
        surface: intentSurface,
        matchValues: Object.freeze([...matchValues]),
        boundaryValue: nonEmptyString(rawIntent?.boundaryValue),
      }
    : undefined;
  const surface =
    accessIntent?.surface ??
    nonEmptyString(details.surface) ??
    (nonEmptyString(details.path) ? "path" : undefined) ??
    nonEmptyString(details.skillName) ??
    (nonEmptyString(details.command) ? "bash" : undefined) ??
    nonEmptyString(details.toolName) ??
    "unknown";
  const value = nonEmptyString(details.value);
  const isBash = surface === "bash" || surface === "bash_escalated";
  const isPath = isPathSurface(surface);
  const command =
    nonEmptyString(details.command) ??
    parsedPreviewCommand(details.toolInputPreview) ??
    (isBash ? value : undefined) ??
    (isBash && accessIntent?.matchValues.length === 1
      ? accessIntent.matchValues[0]
      : undefined);
  const path = nonEmptyString(details.path) ?? (isPath ? value : undefined);
  const destination =
    nonEmptyString(details.target) ?? (!isBash && !isPath ? value : undefined);
  const forwarding = record(details.forwarding);
  const agentName =
    nonEmptyString(details.agentName) ??
    nonEmptyString(forwarding?.requesterAgentName);
  const sessionId = nonEmptyString(forwarding?.requesterSessionId);
  const payload = record(details.payload);
  const payloadRequest = record(payload?.request);
  const matchedPattern =
    nonEmptyString(payloadRequest?.matchedPattern) ??
    nonEmptyString(details.matchedPattern);
  const matchedSpelling =
    nonEmptyString(payloadRequest?.matchedSpelling) ??
    nonEmptyString(details.matchedSpelling);
  const executedUnitCandidate =
    nonEmptyString(payloadRequest?.executedUnit) ??
    nonEmptyString(details.executedUnit);
  const fullCommandCandidate =
    payloadFullCommand(payload) ?? nonEmptyString(details.fullCommand);
  // Suppress facts that add nothing over the gated unit: duplicating the same
  // text would only widen the reviewer view and add hash noise.
  const executedUnit =
    executedUnitCandidate && executedUnitCandidate !== value
      ? executedUnitCandidate
      : undefined;
  const fullCommand =
    fullCommandCandidate && fullCommandCandidate !== command
      ? fullCommandCandidate
      : undefined;
  return {
    surface,
    value,
    command,
    ...(executedUnit ? { executedUnit } : {}),
    ...(fullCommand ? { fullCommand } : {}),
    ...(matchedPattern ? { matchedPattern } : {}),
    ...(matchedSpelling ? { matchedSpelling } : {}),
    path,
    resolvedPath: accessIntent?.boundaryValue,
    destination,
    accessIntent,
    requester:
      agentName || sessionId ? { agentName, sessionId } : undefined,
  };
}

/**
 * The text that will actually execute, most complete fact first.
 *
 * Used for transcript matching, denial labels, and surface inference. Keep
 * the outer command ahead of its extracted payload: wrapper options and
 * environment assignments are part of execution too. Hard denies scan all
 * three facts independently, and grant hashes bind all three.
 */
export function executionText(source: {
  command?: string;
  executedUnit?: string;
  fullCommand?: string;
}): string | undefined {
  return source.fullCommand ?? source.command ?? source.executedUnit;
}

export function effectiveCommand(details: PermissionDetailsLike): string | undefined {
  return normalizePermissionEvidence(details).command;
}

export type HardDeny = {
  rule: string;
  reason: string;
};

function executionCommands(details: PermissionDetailsLike): string[] {
  const evidence = normalizePermissionEvidence(details);
  return [...new Set([
    evidence.fullCommand,
    evidence.command,
    evidence.executedUnit,
  ].flatMap((command) => command?.trim() ? [command.trim()] : []))];
}

/** Hard denies run first; incomplete expansion then requires a human decision. */
export function commandExpansionLimitExceeded(details: PermissionDetailsLike): boolean {
  return executionCommands(details).some(shellExpansionLimitExceeded);
}

/**
 * Keep this list narrow: these checks are terminal and cannot be overridden by
 * the model or the user prompt. Ambiguous or merely high-risk actions belong in
 * the detailed reviewer, which can defer to the human.
 */
export function deterministicHardDeny(
  details: PermissionDetailsLike,
): HardDeny | undefined {
  // These facts are complementary. Unwrapping can omit an env assignment,
  // while the full program can contain syntax our shell scanner cannot peel.
  // Scan independently so unrelated projections cannot form a synthetic pipe
  // or staged credential upload when concatenated.
  for (const command of executionCommands(details)) {
    const denial = hardDenyCommand(command);
    if (denial) return denial;
  }
  return undefined;
}

function hardDenyCommand(command: string): HardDeny | undefined {
  // Structural rules run on the literal-masked skeleton so a literal mention
  // inside a commit message or an `echo` argument is not a wipe, while nested
  // interpreter payloads are still scanned. Credential/data rules below stay
  // on the raw text: a quoted `"$HOME/.aws/credentials"` is still the operand
  // of a real upload.
  const structural = structuralScanText(command);

  for (const segment of structural.split(/&&|\|\||;|\n/)) {
    const isRm = /(?:^|\s)(?:\/[^\s/]+)*\/?rm(?:\s|$)/i.test(segment);
    const recursive =
      /(?:^|\s)--recursive(?:\s|$)/i.test(segment) ||
      /(?:^|\s)-[A-Za-z]*r[A-Za-z]*(?:\s|$)/i.test(segment);
    const forced =
      /(?:^|\s)--force(?:\s|$)/i.test(segment) ||
      /(?:^|\s)-[A-Za-z]*f[A-Za-z]*(?:\s|$)/i.test(segment);
    const rootOrHomeTarget =
      /(?:^|\s)["']?(?:\/(?:\*)?|~(?:\/(?:\*)?)?|\$HOME(?:\/(?:\*)?)?|\$\{HOME\}(?:\/(?:\*)?)?)["']?(?=\s|$)/i.test(
        segment,
      );
    if (isRm && recursive && forced && rootOrHomeTarget) {
      return {
        rule: "destructive-root-or-home-delete",
        reason:
          "recursive forced deletion of root or the home directory is forbidden",
      };
    }
  }

  if (
    /\bcurl\b[^;\n]*(?:--insecure\b|-[A-Za-z]*k[A-Za-z]*(?:\s|$))/i.test(
      structural,
    ) ||
    /\bwget\b[^;\n]*--no-check-certificate\b/i.test(structural) ||
    /\bgit\s+config\b[^;\n]*http\.sslverify\s+false\b/i.test(structural) ||
    /\bnpm\s+config\s+set\s+strict-ssl\s+false\b/i.test(structural) ||
    /\bNODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0\b/i.test(structural)
  ) {
    return {
      rule: "transport-security-weakening",
      reason: "disabling TLS or certificate verification is forbidden",
    };
  }

  // Secret path text is only evidence when it occurs as the operand of an
  // operation that reads a file. In particular, a slash-delimited `.env` in
  // a URL or literal request payload is not itself a credential source.
  const envFileName =
    String.raw`\.env(?:\.(?!example\b|sample\b)[A-Za-z0-9_-]*)*`;
  const envFile =
    envFileName + String.raw`(?=[\s"'/@<>=|;&)\`]|$)`;
  const envPath =
    String.raw`(?:[^\s"'@<>=|;&()]+\/)*` + envFile;
  const credentialDirectoryPath =
    String.raw`(?:~\/|\$HOME\/|\$\{HOME\}\/|\/|\.\.?\/)?` +
    String.raw`(?:[^\s"'@<>=|;&()\/]+\/)*` +
    String.raw`(?:\.ssh\/(?:id_[A-Za-z0-9_-]+|authorized_keys)|\.aws\/credentials|\.kube\/config|\.docker\/config\.json|\.npmrc|\.netrc|\.pi\/agent\/auth\.json)`;
  const credentialPath =
    String.raw`(?:` +
    credentialDirectoryPath +
    String.raw`|` + envPath + String.raw`)`;
  const directCredentialUpload = new RegExp(
    String.raw`\b(?:curl|wget)\b[^;\n]*(?:` +
      String.raw`(?:--data(?:-binary|-urlencode)?|-d|--form|-F)(?:=|\s+)[^;\n\s]*@\s*["']?` + credentialPath +
      String.raw`|(?:--upload-file|--post-file)(?:=|\s+)["']?` + credentialPath +
      String.raw`|-T(?:\s*|=)["']?` + credentialPath +
      String.raw`)["']?`,
    "i",
  );
  const redirectedCredentialUpload = new RegExp(
    String.raw`\b(?:` +
      String.raw`(?:curl|wget)\b[^;\n]*(?:--data(?:-binary|-raw|-urlencode)?|-d|--form|-F|--upload-file|-T|--post-file|--post-data)[^;\n]*` +
      String.raw`|(?:nc|ncat|socat)\b[^;\n]*` +
      String.raw`)<\s*["']?` +
      credentialPath,
    "i",
  );
  // The pipe matcher covers any content-emitting reader that names a secret
  // file (a bare filename such as `head .env`, `dd if=.env`, or a path like
  // ~/.aws/credentials) and feeds a network sink. The producer set is
  // enumerated rather than derived from directCredentialUpload because a bare
  // filename argument carries no path/@/redirect evidence; keeping the list
  // broad is fail-closed and cheap, since a match also requires a secret-file
  // token before the pipe and a network sink after it. This is best-effort
  // hardening, not a completeness guarantee: readers not on the list still
  // fall through to the contextual matchers below or the dynamic reviewer.
  // The leading lookbehind keeps the producers from
  // matching mid-word (star, code) so the terms stay real tool tokens.
  const credentialPipe = new RegExp(
    String.raw`(?<![A-Za-z0-9_])(?:cat|sed|awk|base64|openssl|head|tail|grep|dd|sort|cut|strings|rev|uniq|fold|od|xxd|hexdump|base32|uuencode|gzip|bzip2|xz|zstd|tar|zip)\b[^|;\n]*(?:\.ssh|\.aws|\.kube|\.docker|\.npmrc|\.netrc|` +
      String.raw`(?:^|[\s"'=/@])` +
      envFile +
      String.raw`|auth\.json)[^|;\n]*\|[^;\n]*\b(?:curl|wget|nc|ncat|socat)\b`,
    "i",
  );
  const credentialReader =
    String.raw`(?<![A-Za-z0-9_])(?:cat|sed|awk|base64|openssl|head|tail|grep|dd|sort|cut|strings|rev|uniq|fold|od|xxd|hexdump|base32|uuencode|gzip|bzip2|xz|zstd|tar|zip)\b[^|;\n]*` +
    credentialPath;
  const credentialShellExpansion =
    String.raw`(?:\$\([^)]*` +
    credentialReader +
    String.raw`[^)]*\)|<\([^)]*` +
    credentialReader +
    String.raw`[^)]*\)|\`[^\`\n]*` +
    credentialReader +
    String.raw`[^\`\n]*\`)`;
  const credentialExpansionUpload = new RegExp(
    String.raw`\b(?:curl|wget)\b[^;\n]*(?:--data(?:-binary|-raw|-urlencode)?|-d|--form|-F|--upload-file|-T|--post-file|--post-data)[^;\n]*` +
      credentialShellExpansion,
    "i",
  );
  const redirectedCredentialExpansion = new RegExp(
    String.raw`\b(?:nc|ncat|socat)\b[^;\n]*(?:<<<|<)\s*` +
      credentialShellExpansion,
    "i",
  );
  const stagedCredentialVariableRead = new RegExp(
    String.raw`\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*` +
      credentialShellExpansion,
    "gi",
  );
  let stagedCredentialVariableUpload = false;
  for (const match of command.matchAll(stagedCredentialVariableRead)) {
    const variable = match[1];
    if (!variable) continue;
    const suffix = command.slice((match.index ?? 0) + match[0].length);
    const escapedVariable = variable.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const variableUpload = new RegExp(
      String.raw`(?:\b(?:curl|wget)\b[^;\n]*(?:--data(?:-binary|-raw|-urlencode)?|-d|--form|-F|--upload-file|-T|--post-file|--post-data)[^;\n]*|\b(?:nc|ncat|socat)\b[^;\n]*<<<\s*["']?)` +
        String.raw`(?:\$\{` +
        escapedVariable +
        String.raw`\}|\$` +
        escapedVariable +
        String.raw`(?![A-Za-z0-9_]))`,
      "i",
    );
    if (variableUpload.test(suffix)) {
      stagedCredentialVariableUpload = true;
      break;
    }
  }
  const credentialSubstitution = new RegExp(
    String.raw`\b(?:nc|ncat|socat)\b[^;\n]*\$\([^)]*` +
      credentialReader +
      String.raw`[^)]*\)`,
    "i",
  );
  const stagedCredentialRead = new RegExp(
    credentialReader + String.raw`[^|;\n]*>\s*["']?([^\s"';&|]+)["']?`,
    "gi",
  );
  let stagedCredentialUpload = false;
  for (const match of command.matchAll(stagedCredentialRead)) {
    const target = match[1];
    if (!target) continue;
    const suffix = command.slice((match.index ?? 0) + match[0].length);
    const escapedTarget = target.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const targetUpload = new RegExp(
      String.raw`\b(?:curl|wget)\b[^;\n]*(?:` +
        String.raw`(?:--data(?:-binary|-urlencode)?|-d|--form|-F)(?:=|\s+)[^;\n\s]*@\s*["']?` + escapedTarget +
        String.raw`|(?:--upload-file|--post-file)(?:=|\s+)["']?` + escapedTarget +
        String.raw`|-T(?:\s*|=)["']?` + escapedTarget +
        String.raw`)(?=[\s"']|$)`,
      "i",
    );
    if (targetUpload.test(suffix)) {
      stagedCredentialUpload = true;
      break;
    }
  }
  if (
    directCredentialUpload.test(command) ||
    redirectedCredentialUpload.test(command) ||
    credentialPipe.test(command) ||
    credentialExpansionUpload.test(command) ||
    redirectedCredentialExpansion.test(command) ||
    credentialSubstitution.test(command) ||
    stagedCredentialVariableUpload ||
    stagedCredentialUpload
  ) {
    return {
      rule: "credential-exfiltration",
      reason:
        "sending credentials or secret configuration to a network sink is forbidden",
    };
  }

  const authorizationPath =
    String.raw`(?:authorized_keys|/etc/sudoers|/etc/sudoers\.d/)`;
  const redirectedAuthorizationWrite = new RegExp(
    String.raw`\b(?:printf|echo|cat)\b[^;\n]*(?:>>?|\|\s*tee\b)[^;\n]*${authorizationPath}`,
    "i",
  );
  const directAuthorizationWrite = new RegExp(
    String.raw`\b(?:tee|cp|mv|install)\b[^;\n]*${authorizationPath}`,
    "i",
  );
  if (
    redirectedAuthorizationWrite.test(command) ||
    directAuthorizationWrite.test(command)
  ) {
    return {
      rule: "access-persistence",
      reason: "adding SSH or sudo authorization persistence is forbidden",
    };
  }

  return undefined;
}

function boundedString(value: unknown): string {
  let rendered: string;
  if (typeof value === "string") rendered = value;
  else {
    try {
      rendered = JSON.stringify(value);
    } catch {
      rendered = "[unserializable]";
    }
  }
  if (rendered.length <= MAX_EVIDENCE_ITEM_CHARACTERS) return rendered;
  const half = Math.floor((MAX_EVIDENCE_ITEM_CHARACTERS - 32) / 2);
  return `${rendered.slice(0, half)}\n…[middle truncated]…\n${rendered.slice(-half)}`;
}

function userText(message: Record<string, unknown>): string {
  if (message.role !== "user") return "";
  if (typeof message.content === "string") return message.content;
  if (!Array.isArray(message.content)) return "";
  return message.content
    .filter(
      (part): part is Record<string, unknown> =>
        Boolean(part) && typeof part === "object" && !Array.isArray(part),
    )
    .filter((part) => part.type === "text" && typeof part.text === "string")
    .map((part) => String(part.text))
    .join("\n");
}

function toolTexts(
  message: Record<string, unknown>,
): Array<{ id?: string; name: string; text: string }> {
  if (message.role !== "assistant" || !Array.isArray(message.content)) {
    return [];
  }
  return message.content.flatMap((part) => {
    if (!part || typeof part !== "object" || Array.isArray(part)) return [];
    const record = part as Record<string, unknown>;
    if (record.type !== "toolCall" || typeof record.name !== "string") {
      return [];
    }
    const id =
      typeof record.id === "string"
        ? record.id
        : typeof record.toolCallId === "string"
          ? record.toolCallId
          : undefined;
    return [{
      id,
      name: record.name,
      text: `${record.name} ${JSON.stringify(record.arguments ?? {})}`,
    }];
  });
}

function extractEvidence(entries: readonly unknown[]): Evidence[] {
  const evidence: Evidence[] = [];
  entries.forEach((entry, entryIndex) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) return;
    const message = (entry as Record<string, unknown>).message;
    if (!message || typeof message !== "object" || Array.isArray(message)) {
      return;
    }
    const record = message as Record<string, unknown>;
    const user = userText(record);
    if (user.trim()) {
      evidence.push({
        id: `${stableEntryId(entry, entryIndex)}:user`,
        index: evidence.length,
        entryIndex,
        kind: "user",
        text: user,
        reason: "latest-user",
        secondaryReasons: [],
        sensitivity: "user-intent",
        originalCharacters: user.length,
        preTruncated: Array.isArray(record.content) && record.content.some(
          (part: unknown) => !part || typeof part !== "object" ||
            !("type" in part) || part.type !== "text" ||
            !("text" in part) || typeof part.text !== "string",
        ),
      });
    }
    for (const tool of toolTexts(record)) {
      evidence.push({
        id: tool.id
          ? `tool-call:${tool.id}`
          : `${stableEntryId(entry, entryIndex)}:tool-${evidence.length}`,
        index: evidence.length,
        entryIndex,
        kind: "tool",
        text: tool.text,
        toolCallId: tool.id,
        reason: "structured-request-match",
        secondaryReasons: [],
        sensitivity: "tool-input",
        originalCharacters: tool.text.length,
        preTruncated: false,
      });
    }
  });
  return evidence;
}

type ToolCallRecord = {
  id?: string;
  name: string;
  arguments: unknown;
  rendered: string;
  entryIndex: number;
  candidateId: string;
};

function messageRecord(entry: unknown): Record<string, unknown> | undefined {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) return;
  const message = (entry as Record<string, unknown>).message;
  if (!message || typeof message !== "object" || Array.isArray(message)) return;
  return message as Record<string, unknown>;
}

function stableEntryId(entry: unknown, index: number): string {
  if (entry && typeof entry === "object" && !Array.isArray(entry)) {
    const id = (entry as Record<string, unknown>).id;
    if (typeof id === "string" && id.trim()) return `entry:${id}`;
  }
  return `entry-index:${index}`;
}

function redactSensitiveResult(value: string): string {
  return value
    .replace(
      /-----BEGIN [^-]*(?:PRIVATE KEY|OPENSSH PRIVATE KEY)-----[\s\S]*?-----END [^-]*(?:PRIVATE KEY|OPENSSH PRIVATE KEY)-----/gi,
      "[REDACTED PRIVATE KEY]",
    )
    .replace(
      /\b(authorization\s*:\s*(?:bearer|basic)|bearer)\s+[A-Za-z0-9._~+/=-]+/gi,
      "$1 [REDACTED]",
    )
    .replace(
      /(["'])([A-Z][A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|ACCESS_KEY))\1\s*:\s*(["'])[^"'\r\n]*\3/g,
      '$1$2$1:$3[REDACTED]$3',
    )
    .replace(
      /\b([A-Z][A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|ACCESS_KEY))\s*[:=]\s*([^\s]+)/g,
      "$1=[REDACTED]",
    )
    .replace(/\b(?:ghp|github_pat|sk)-[A-Za-z0-9_-]{12,}\b/g, "[REDACTED TOKEN]");
}

function escapeEvidenceMarkup(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function resultText(message: Record<string, unknown>): string {
  if (!Array.isArray(message.content)) return "";
  const text = message.content
    .flatMap((part) => {
      if (!part || typeof part !== "object" || Array.isArray(part)) return [];
      const record = part as Record<string, unknown>;
      return record.type === "text" && typeof record.text === "string"
        ? [record.text]
        : [];
    })
    .join("\n")
    .trim();
  return boundedString(redactSensitiveResult(text));
}

function commandArgument(call: ToolCallRecord): string {
  if (
    call.arguments &&
    typeof call.arguments === "object" &&
    !Array.isArray(call.arguments) &&
    typeof (call.arguments as Record<string, unknown>).command === "string"
  ) {
    return String((call.arguments as Record<string, unknown>).command);
  }
  return "";
}

type ProviderBranchQuery = {
  provider: "github" | "gitlab";
  branch: string;
};

function normalizedBranch(value: string): string | undefined {
  let branch = value.replace(/^refs\/heads\//, "");
  try {
    branch = decodeURIComponent(branch);
  } catch {
    return undefined;
  }
  return branch && !/[\s;&|`$<>]/.test(branch) ? branch : undefined;
}

function explicitPushBranch(command: string): string | undefined {
  if (/[\n;&|`<>]|\$\(/.test(command)) return;
  const words = command
    .trim()
    .split(/\s+/)
    .map((word) => word.replace(/^(["'])(.*)\1$/, "$2"));
  const git = words.findIndex((word) => /(?:^|\/)git$/.test(word));
  if (git < 0 || words[git + 1] !== "push") return;
  const positional = words
    .slice(git + 2)
    .filter((word) => word && !word.startsWith("-"));
  // A single explicit refspec keeps the provider evidence bound to the whole
  // push. Multi-ref pushes deliberately receive only the generic Git context.
  if (positional.length !== 2) return;
  const refspec = positional[positional.length - 1];
  if (!refspec) return;
  const destination = refspec.includes(":")
    ? refspec.slice(refspec.lastIndexOf(":") + 1)
    : refspec;
  return normalizedBranch(destination);
}

function providerBranchQuery(command: string): ProviderBranchQuery | undefined {
  if (/[\n;&|`<>]|\$\(/.test(command)) return;
  const github = command
    .trim()
    .match(
      /^gh\s+api\s+["']?\/?repos\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/branches\/([^\/\s"']+)(?:\/protection)?["']?$/,
    );
  if (github) {
    const branch = normalizedBranch(github[1] ?? "");
    return branch ? { provider: "github", branch } : undefined;
  }
  const gitlab = command
    .trim()
    .match(
      /^glab\s+api\s+["']?\/?projects\/[A-Za-z0-9_.%/-]+\/protected_branches\/([^\/\s"']+)["']?$/,
    );
  if (gitlab) {
    const branch = normalizedBranch(gitlab[1] ?? "");
    return branch ? { provider: "gitlab", branch } : undefined;
  }
  return undefined;
}

function relevanceReason(
  call: ToolCallRecord,
  request: RelevantBoundaryRequest,
):
  | "same-tool"
  | "delete-precheck"
  | "git-push-context"
  | "provider-branch-protection"
  | undefined {
  if (request.toolCallId && call.id === request.toolCallId) return "same-tool";
  const currentCommand = executionText(request) || "";
  const priorCommand = commandArgument(call);
  const pushedBranch = explicitPushBranch(currentCommand);
  const providerQuery = providerBranchQuery(priorCommand);
  const destructive =
    /\b(?:rm|rmdir|unlink|trash|delete)\b/i.test(currentCommand);
  const readOnlyCheck =
    /^\s*(?:stat|ls|find|test|readlink|realpath)\b/i.test(priorCommand);
  const priorWords = /[\n;&|`<>]|\$\(/.test(priorCommand)
    ? []
    : priorCommand
        .trim()
        .split(/\s+/)
        .map((word) => word.replace(/^(["'])(.*)\1$/, "$2"));
  const targets = [request.path, request.resolvedPath].filter(
    (value): value is string => Boolean(value),
  );
  if (
    destructive &&
    readOnlyCheck &&
    targets.some((target) => priorWords.includes(target))
  ) {
    return "delete-precheck";
  }
  if (
    /\bgit\b[\s\S]*\bpush\b/i.test(currentCommand) &&
    /^\s*git\s+(?:remote|branch|status|rev-parse|config\s+--get\s+remote)/i.test(
      priorCommand,
    )
  ) {
    return "git-push-context";
  }
  if (
    pushedBranch &&
    providerQuery &&
    providerQuery.branch === pushedBranch
  ) {
    return "provider-branch-protection";
  }
  return undefined;
}

function relevantResultEvidence(
  entries: readonly unknown[],
  request: RelevantBoundaryRequest,
  currentTurnStart: number,
): Array<{
  index: number;
  reason: Exclude<
    EvidenceSelectionReason,
    | "latest-user"
    | "exact-request-reference"
    | "actor-reference"
    | "trusted-retry-user-message"
    | "exact-tool-call"
    | "structured-request-match"
    | "security-combination"
    | "sandbox-trap"
  >;
  call: ToolCallRecord;
  resultId: string;
  resultText: string;
  renderedResult: string;
}> {
  const calls = new Map<string, ToolCallRecord>();
  const results: Array<{
    index: number;
    reason: "same-tool" | "delete-precheck" | "git-push-context" | "provider-branch-protection";
    call: ToolCallRecord;
    resultId: string;
    resultText: string;
    renderedResult: string;
  }> = [];
  entries.forEach((entry, index) => {
    const message = messageRecord(entry);
    if (!message) return;
    if (message.role === "assistant" && Array.isArray(message.content)) {
      for (const part of message.content) {
        if (!part || typeof part !== "object" || Array.isArray(part)) continue;
        const record = part as Record<string, unknown>;
        if (record.type !== "toolCall" || typeof record.name !== "string") continue;
        const id =
          typeof record.id === "string"
            ? record.id
            : typeof record.toolCallId === "string"
              ? record.toolCallId
              : undefined;
        if (!id) continue;
        calls.set(id, {
          id,
          name: record.name,
          arguments: record.arguments,
          rendered: `${record.name} ${boundedString(record.arguments ?? {})}`,
          entryIndex: index,
          candidateId: `tool-call:${id}`,
        });
      }
      return;
    }
    if (
      message.role !== "toolResult" ||
      typeof message.toolCallId !== "string"
    ) {
      return;
    }
    const call = calls.get(message.toolCallId);
    if (!call) return;
    const reason = relevanceReason(call, request);
    const text = resultText(message);
    const crossTurnAllowed = reason === "same-tool";
    if (reason && text && (crossTurnAllowed || call.entryIndex >= currentTurnStart)) {
      results.push({
        index,
        reason,
        call,
        resultId: `${stableEntryId(entry, index)}:tool-result:${message.toolCallId}`,
        resultText: text,
        renderedResult: `<tool-result id="${escapeEvidenceMarkup(message.toolCallId)}" reason="${reason}" tool="${escapeEvidenceMarkup(call.name)}">\n${escapeEvidenceMarkup(text)}\n</tool-result>`,
      });
    }
  });
  return results;
}

function sandboxTrapSupplement(
  request: RelevantBoundaryRequest,
): string | undefined {
  if (request.source !== "sandbox-runtime") return;
  const supplement = {
    ...(request.toolName ? { process: request.toolName } : {}),
  };
  if (Object.keys(supplement).length === 0) return;
  return canonicalReviewerJson(supplement);
}

function sandboxTrapEvidence(
  request: RelevantBoundaryRequest,
): string | undefined {
  const supplement = sandboxTrapSupplement(request);
  if (!supplement) return;
  return `<sandbox-trap>
${supplement}
</sandbox-trap>`;
}

function currentTurnStart(entries: readonly unknown[]): number {
  let start = 0;
  entries.forEach((entry, index) => {
    if (messageRecord(entry)?.role === "user") start = index;
  });
  return start;
}

function surfaceProfile(
  request: RelevantBoundaryRequest,
): EvidenceSurfaceProfile {
  if (request.agentName || request.requesterSessionId) return "forwarded";
  if (request.surface === "network" || request.destination) return "network";
  const command = executionText(request) ?? "";
  if (/\bgit\b[\s\S]*\bpush\b/i.test(command)) return "git-push";
  if (/\b(?:rm|rmdir|unlink|trash|delete)\b/i.test(command)) {
    return "delete";
  }
  return "generic";
}

function collectToolCalls(entries: readonly unknown[]): ToolCallRecord[] {
  const calls: ToolCallRecord[] = [];
  entries.forEach((entry, entryIndex) => {
    const message = messageRecord(entry);
    if (message?.role !== "assistant" || !Array.isArray(message.content)) return;
    for (const part of message.content) {
      if (!part || typeof part !== "object" || Array.isArray(part)) continue;
      const value = part as Record<string, unknown>;
      if (value.type !== "toolCall" || typeof value.name !== "string") continue;
      const id =
        typeof value.id === "string"
          ? value.id
          : typeof value.toolCallId === "string"
            ? value.toolCallId
            : undefined;
      calls.push({
        id,
        name: value.name,
        arguments: value.arguments,
        rendered: `${value.name} ${boundedString(value.arguments ?? {})}`,
        entryIndex,
        candidateId: id
          ? `tool-call:${id}`
          : `${stableEntryId(entry, entryIndex)}:tool-${calls.length}`,
      });
    }
  });
  return calls;
}

function exactStructuredMatch(
  call: ToolCallRecord,
  request: RelevantBoundaryRequest,
): boolean {
  if (!call.arguments || typeof call.arguments !== "object" || Array.isArray(call.arguments)) {
    return false;
  }
  const args = call.arguments as Record<string, unknown>;
  const pairs: Array<[unknown, unknown]> = [
    [args.command, executionText(request)],
    [args.path, request.path],
    [args.resolvedPath, request.resolvedPath],
    [args.destination, request.destination],
    [args.agentName, request.agentName],
    [args.requesterSessionId, request.requesterSessionId],
    [args.target, request.destination ?? request.path],
    [args.value, request.destination ?? request.path ?? request.command],
  ];
  if (pairs.some(
    ([actual, expected]) =>
      typeof actual === "string" &&
      typeof expected === "string" &&
      actual === expected,
  )) return true;
  const forwarding =
    args.forwarding && typeof args.forwarding === "object" && !Array.isArray(args.forwarding)
      ? args.forwarding as Record<string, unknown>
      : undefined;
  if (
    forwarding &&
    ((typeof forwarding.requesterAgentName === "string" &&
      forwarding.requesterAgentName === request.agentName) ||
      (typeof forwarding.requesterSessionId === "string" &&
        forwarding.requesterSessionId === request.requesterSessionId))
  ) return true;
  const intent =
    args.accessIntent && typeof args.accessIntent === "object" && !Array.isArray(args.accessIntent)
      ? args.accessIntent as Record<string, unknown>
      : undefined;
  return Boolean(
    intent &&
    request.accessIntent &&
    intent.surface === request.accessIntent.surface &&
    Array.isArray(intent.matchValues) &&
    intent.matchValues.length === request.accessIntent.matchValues.length &&
    intent.matchValues.every(
      (value, index) => value === request.accessIntent!.matchValues[index],
    ) &&
    intent.boundaryValue === request.accessIntent.boundaryValue,
  );
}

function sameReviewerField(actual: unknown, expected: unknown): boolean {
  return expected !== undefined &&
    canonicalReviewerJson(actual) === canonicalReviewerJson(expected);
}

function toolArgumentCoveredByRequest(
  key: string,
  actual: unknown,
  request: RelevantBoundaryRequest,
): boolean {
  if (key === "target") {
    return sameReviewerField(actual, request.destination ?? request.path);
  }
  if (key === "value") {
    return [executionText(request), request.path, request.destination].some(
      (expected) => sameReviewerField(actual, expected),
    );
  }
  if (key === "forwarding") {
    if (!request.agentName && !request.requesterSessionId) return false;
    return sameReviewerField(actual, {
      requesterAgentName: request.agentName,
      requesterSessionId: request.requesterSessionId,
    });
  }
  const expected = ({
    command: executionText(request),
    path: request.path,
    resolvedPath: request.resolvedPath,
    destination: request.destination,
    destinationHost: request.destinationHost,
    destinationPort: request.destinationPort,
    destinationProtocol: request.destinationProtocol,
    cwd: request.cwd,
    agentName: request.agentName,
    requesterSessionId: request.requesterSessionId,
    accessIntent: request.accessIntent,
  } as Record<string, unknown>)[key];
  return sameReviewerField(actual, expected);
}

function exactToolCallReviewerRepresentation(
  call: ToolCallRecord,
  request: RelevantBoundaryRequest,
  reason: EvidenceSelectionReason,
): string | undefined {
  if (
    !call.id ||
    call.id !== request.toolCallId ||
    !call.arguments ||
    typeof call.arguments !== "object" ||
    Array.isArray(call.arguments)
  ) {
    return;
  }
  const args = call.arguments as Record<string, unknown>;
  let previewCoversAll = false;
  const preview = request.toolInputPreview;
  if (typeof preview === "string") {
    try {
      const parsed: unknown = JSON.parse(
        preview.startsWith("input ") ? preview.slice(6) : preview,
      );
      previewCoversAll =
        canonicalReviewerJson(parsed) === canonicalReviewerJson(args);
    } catch {
      // Incomplete or decorated previews cannot replace tool-call supplements.
    }
  }
  const supplement = previewCoversAll
    ? {}
    : Object.fromEntries(
        Object.entries(args).filter(
          ([key, actual]) =>
            !toolArgumentCoveredByRequest(key, actual, request),
        ),
      );
  return canonicalReviewerJson({
    id: call.id,
    name: call.name,
    reason,
    ...(Object.keys(supplement).length > 0 ? { supplement } : {}),
  });
}

function securityEvidenceCategory(
  call: ToolCallRecord,
):
  | "credential"
  | "permission"
  | "authorization"
  | "transport"
  | "audit"
  | "security-control"
  | undefined {
  const command = commandArgument(call);
  if (!command) return;
  if (
    /\b(?:cat|sed|awk|base64|openssl|head|tail|grep|dd|xxd|tar|zip)\b[\s\S]*(?:\.env|\.ssh|\.aws\/credentials|\.kube\/config|\.npmrc|auth\.json)/i.test(
      command,
    )
  ) return "credential";
  if (/\b(?:chmod|chown|chgrp|setfacl)\b/i.test(command)) return "permission";
  if (/(?:authorized_keys|\/etc\/sudoers|access[_-]?grant)/i.test(command)) {
    return "authorization";
  }
  if (
    /(?:--insecure|--no-check-certificate|sslverify\s+false|strict-ssl\s+false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0|https?_proxy)/i.test(
      command,
    )
  ) return "transport";
  if (/\b(?:disable|truncate|delete|rm)\b[\s\S]*\b(?:audit|log)/i.test(command)) {
    return "audit";
  }
  if (/(?:pi-auto-review|pi-sandbox|permission-system|permissions\.json|sandbox\.json)/i.test(command)) {
    return "security-control";
  }
  return undefined;
}

function selectRequestAwareTools(
  entries: readonly unknown[],
  evidence: Evidence[],
  request: RelevantBoundaryRequest,
  relevant: ReturnType<typeof relevantResultEvidence>,
  turnStart: number,
): { selected: Evidence[]; criticalEvidenceOverflow: boolean } {
  const calls = collectToolCalls(entries);
  const reasons = new Map<string, EvidenceSelectionReason[]>();
  const addReason = (call: ToolCallRecord, reason: EvidenceSelectionReason) => {
    const current = reasons.get(call.candidateId) ?? [];
    if (!current.includes(reason)) current.push(reason);
    reasons.set(call.candidateId, current);
  };

  const exact = request.toolCallId
    ? calls.find((call) => call.id === request.toolCallId)
    : undefined;
  if (exact) addReason(exact, "exact-tool-call");
  for (const unit of relevant) addReason(unit.call, unit.reason);
  for (const call of calls) {
    if (call.entryIndex < turnStart || call === exact) continue;
    if (exactStructuredMatch(call, request)) {
      addReason(call, "structured-request-match");
    }
  }
  const profile = surfaceProfile(request);
  const securityCalls = calls.filter(
    (call) =>
      call.entryIndex >= turnStart &&
      securityEvidenceCategory(call) !== undefined &&
      ["network", "git-push", "forwarded"].includes(profile),
  );
  for (const call of securityCalls.slice(-4)) {
    addReason(call, "security-combination");
  }

  const priority: EvidenceSelectionReason[] = [
    "exact-tool-call",
    "security-combination",
    "same-tool",
    "delete-precheck",
    "git-push-context",
    "provider-branch-protection",
    "structured-request-match",
  ];
  const selected = evidence
    .filter((item) => item.kind === "tool" && reasons.has(item.id))
    .map((item) => {
      const matched = reasons.get(item.id)!;
      const ordered = [...matched].sort(
        (left, right) => priority.indexOf(left) - priority.indexOf(right),
      );
      const call = calls.find((candidate) => candidate.candidateId === item.id)!;
      // Invariant: reasons entries are only created via addReason, which
      // always pushes at least one reason, and this item passed the
      // reasons.has(item.id) filter above — so ordered[0] is defined.
      const primaryReason = ordered[0]!;
      const linkage = exactToolCallReviewerRepresentation(
        call,
        request,
        primaryReason,
      );
      return {
        ...item,
        ...(linkage
          ? { text: linkage, representationCharacters: linkage.length }
          : {}),
        reason: primaryReason,
        secondaryReasons: ordered.slice(1),
        sensitivity:
          ordered.includes("security-combination")
            ? ({
                credential: "credential",
                permission: "permission-control",
                authorization: "authorization-persistence",
                transport: "transport-weakening",
                audit: "audit-control",
                "security-control": "security-control",
              } as const)[
                securityEvidenceCategory(
                  calls.find((call) => call.candidateId === item.id)!,
                )!
              ]
            : item.sensitivity,
      };
    });
  return {
    selected,
    criticalEvidenceOverflow: securityCalls.length > 4,
  };
}

function capRelevantUnits(
  units: ReturnType<typeof relevantResultEvidence>,
  profile: EvidenceSurfaceProfile,
): ReturnType<typeof relevantResultEvidence> {
  const newest = [...units].sort((left, right) => right.index - left.index);
  const selected: typeof units = [];
  const take = (
    reason: (typeof units)[number]["reason"],
    limit: number,
    predicate: (unit: (typeof units)[number]) => boolean = () => true,
  ) => {
    for (const unit of newest) {
      if (
        selected.length >= units.length ||
        selected.includes(unit) ||
        unit.reason !== reason ||
        !predicate(unit) ||
        selected.filter(
          (candidate) => candidate.reason === reason && predicate(candidate),
        ).length >= limit
      ) {
        continue;
      }
      selected.push(unit);
    }
  };
  take("same-tool", 1);
  if (profile === "delete") take("delete-precheck", 2);
  if (profile === "git-push") {
    take("git-push-context", 1, (unit) =>
      /^\s*git\s+(?:remote|config\s+--get\s+remote)/i.test(
        commandArgument(unit.call),
      ),
    );
    take("git-push-context", 1, (unit) =>
      /^\s*git\s+(?:branch|status|rev-parse)/i.test(
        commandArgument(unit.call),
      ),
    );
    take("provider-branch-protection", 1);
  }
  if (profile === "generic") {
    for (const unit of newest) {
      if (!selected.includes(unit) && selected.length < 4) selected.push(unit);
    }
  }
  return selected.sort((left, right) => left.index - right.index);
}

function selectedMetadata(
  item: Evidence,
  original: Evidence,
  profile: EvidenceSurfaceProfile,
): EvidenceCandidateMetadata {
  return {
    id: item.id,
    entryIndex: item.entryIndex,
    kind: item.kind === "user" ? "user" : "tool-call",
    ...(item.toolCallId ? { toolCallId: item.toolCallId } : {}),
    reason: item.reason,
    secondaryReasons: [...item.secondaryReasons],
    surfaceProfile: profile,
    originalCharacters: original.originalCharacters,
    selectedCharacters: item.text.length,
    estimatedTokens: estimateReviewerTokens(item.text),
    truncated:
      original.preTruncated ||
      item.text.length <
        (item.representationCharacters ?? original.originalCharacters),
    sensitivity: item.sensitivity,
  };
}

type UserSelection = {
  selected: Evidence[];
  truncated: boolean;
  authorizationCeiling: TranscriptResult["userAuthorizationCeiling"];
  constraint: TranscriptResult["userConstraint"];
  compactionState: TranscriptResult["compactionState"];
  rawUserAuthorization: NonNullable<TranscriptResult["rawUserAuthorization"]>;
  optionalHistoryOmittedOrTruncated: boolean;
};

function summaryEntryIndices(entries: readonly unknown[]): number[] {
  const indices: number[] = [];
  entries.forEach((entry, index) => {
    const role = messageRecord(entry)?.role;
    if (role === "compactionSummary" || role === "branchSummary") {
      indices.push(index);
    }
  });
  return indices;
}

function containsExactIdentifier(text: string, value: string): boolean {
  const escaped = value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`(^|[^A-Za-z0-9_-])${escaped}(?=$|[^A-Za-z0-9_-])`).test(
    text,
  );
}

function exactUserReference(
  text: string,
  request: RelevantBoundaryRequest,
): boolean {
  return [
    request.id,
    request.toolCallId,
    request.requesterSessionId,
  ].some((value) => {
    if (typeof value !== "string" || value.length === 0) return false;
    return containsExactIdentifier(text, value);
  });
}

function selectUserEvidence(
  entries: readonly unknown[],
  evidence: Evidence[],
  request: RelevantBoundaryRequest,
  optionalBudgetTokens: number,
): UserSelection {
  const users = evidence.filter((item) => item.kind === "user");
  const summaries = summaryEntryIndices(entries);
  const lastSummary = summaries.at(-1) ?? -1;
  let latestRawEntry = -1;
  entries.forEach((entry, index) => {
    if (index > lastSummary && messageRecord(entry)?.role === "user") latestRawEntry = index;
  });
  const unavailableSource = latestRawEntry >= 0 ? [{
    id: `${stableEntryId(entries[latestRawEntry], latestRawEntry)}:user`,
    entryIndex: latestRawEntry,
    provenance: "raw-user-message" as const,
    complete: false,
  }] : [];
  const rawAfterSummary = users.filter((item) => item.entryIndex > lastSummary);
  const eligibleUsers = lastSummary >= 0 ? rawAfterSummary : users;
  const latest = eligibleUsers.at(-1);
  const compactionState: TranscriptResult["compactionState"] =
    summaries.length === 0
      ? "none"
      : latest
        ? "summary-present"
        : "authorization-unavailable";
  if (!latest) {
    return {
      selected: [],
      truncated: users.length > 0,
      authorizationCeiling: request.trustedRetryOriginalRequestId
        ? "high"
        : "unknown",
      constraint: "none",
      compactionState,
      rawUserAuthorization: { status: "unavailable", sources: unavailableSource },
      optionalHistoryOmittedOrTruncated: false,
    };
  }

  // Latest intent and exact-reference raw authorization are mandatory. The
  // optional-history quotas must not clip them; the complete prompt cap wins.
  const latestTrustedRetry = Boolean(
    request.trustedRetryOriginalRequestId &&
      latest.text.includes("I approved one reviewer retry") &&
      containsExactIdentifier(
        latest.text,
        request.trustedRetryOriginalRequestId,
      ),
  );
  const latestExactReference = exactUserReference(latest.text, request);
  const selected: Evidence[] = [{
    ...latest,
    reason: "latest-user",
    secondaryReasons: [
      ...(latestTrustedRetry ? ["trusted-retry-user-message" as const] : []),
      ...(latestExactReference ? ["exact-request-reference" as const] : []),
    ],
  }];
  let optionalRemaining = optionalBudgetTokens;
  let optionalOmitted = false;
  const older = eligibleUsers.slice(0, -1).reverse();
  for (const candidate of older) {
    const trustedRetry = Boolean(
      request.trustedRetryOriginalRequestId &&
        candidate.text.includes("I approved one reviewer retry") &&
        containsExactIdentifier(
          candidate.text,
          request.trustedRetryOriginalRequestId,
        ),
    );
    const exactReference = exactUserReference(candidate.text, request);
    const actorReference = Boolean(request.agentName &&
      containsExactIdentifier(candidate.text, request.agentName));
    if (!trustedRetry && !exactReference && !actorReference) continue;
    const reason: EvidenceSelectionReason = trustedRetry
      ? "trusted-retry-user-message"
      : exactReference ? "exact-request-reference" : "actor-reference";
    if (reason === "actor-reference") {
      const tokens = estimateReviewerTokens(candidate.text);
      // Keep optional raw messages whole: clipping can hide a later constraint.
      if (tokens > optionalRemaining) {
        optionalOmitted = true;
        continue;
      }
      optionalRemaining -= tokens;
    }
    selected.push({
      ...candidate,
      reason,
      secondaryReasons: [
        ...(trustedRetry && exactReference
          ? ["exact-request-reference" as const]
          : []),
      ],
    });
  }
  selected.sort((left, right) => left.entryIndex - right.entryIndex);
  const mandatory = selected.filter((item) => item.reason !== "actor-reference");
  const incomplete = latestRawEntry > latest.entryIndex ||
    mandatory.some((item) => item.preTruncated);
  return {
    selected,
    truncated: incomplete || optionalOmitted || selected.some((item) => item.preTruncated),
    optionalHistoryOmittedOrTruncated: optionalOmitted ||
      selected.some((item) => item.reason === "actor-reference" && item.preTruncated),
    authorizationCeiling: "high",
    constraint: "none",
    compactionState,
    rawUserAuthorization: {
      status: incomplete ? "incomplete" : "complete",
      sources: [
        ...mandatory.map((item) => ({
          id: item.id,
          entryIndex: item.entryIndex,
          provenance: "raw-user-message" as const,
          complete: !item.preTruncated,
        })),
        ...(latestRawEntry > latest.entryIndex ? unavailableSource : []),
      ],
    },
  };
}

function selectEvidence(
  evidence: Evidence[],
  budgetTokens: number,
): { selected: Evidence[]; truncated: boolean } {
  const candidates = evidence;
  const mandatory = candidates.filter((item) =>
    item.reason === "exact-tool-call" || item.reason === "security-combination");
  const selected = new Map<number, Evidence>(
    mandatory.map((item) => [item.index, item]),
  );
  let remaining = budgetTokens;
  const add = (item: Evidence, limit = remaining): void => {
    if (selected.has(item.index) || remaining <= 0) return;
    const text = reviewerTokenPrefix(boundedString(item.text), Math.min(remaining, limit));
    if (!text) return;
    selected.set(item.index, { ...item, text });
    remaining -= estimateReviewerTokens(text);
  };

  // Only optional history spends this quota; mandatory evidence is untouched.
  for (let index = candidates.length - 1; index >= 0; index--) {
    const candidate = candidates[index];
    if (candidate) add(candidate);
  }
  return {
    selected: [...selected.values()],
    truncated:
      selected.size < candidates.length ||
      [...selected.values()].some(
        (item) =>
          item.text.length <
          (candidates.find((candidate) => candidate.index === item.index)?.text
            .length || 0),
      ),
  };
}

export function buildClassifierTranscript(
  entries: readonly unknown[],
  config: TranscriptConfig,
  request: RelevantBoundaryRequest = {},
): TranscriptResult {
  const evidence = extractEvidence(entries);
  const profile = surfaceProfile(request);
  const turnStart = currentTurnStart(entries);
  const relevantUnits = capRelevantUnits(
    relevantResultEvidence(entries, request, turnStart),
    profile,
  );
  const users = selectUserEvidence(
    entries,
    evidence,
    request,
    config.maxUserTranscriptTokens,
  );
  const requestAwareTools = selectRequestAwareTools(
    entries,
    evidence,
    request,
    relevantUnits,
    turnStart,
  );
  const tools = selectEvidence(
    requestAwareTools.selected,
    config.maxToolTranscriptTokens,
  );
  const relevantBudget =
    config.maxRelevantResultTokens ?? config.maxToolTranscriptTokens;
  const sandboxSupplement = sandboxTrapSupplement(request);
  const sandboxEvidence = sandboxTrapEvidence(request);
  const relevantCandidates = [
    ...(sandboxEvidence && sandboxSupplement
      ? [{
          index: Number.MAX_SAFE_INTEGER - 1,
          id: `sandbox-trap:${request.id ?? "request"}`,
          reason: "sandbox-trap" as const,
          toolCallId: undefined,
          text: sandboxEvidence,
          content: sandboxSupplement,
          rawCharacters: sandboxEvidence.length,
          sensitivity: "boundary" as const,
        }]
      : []),
    ...relevantUnits
      .filter((unit) =>
        tools.selected.some((tool) => tool.id === unit.call.candidateId),
      )
      .map((unit) => ({
        index: unit.index,
        id: unit.resultId,
        reason: unit.reason,
        toolCallId: unit.call.id,
        text: unit.renderedResult,
        content: unit.resultText,
        rawCharacters: unit.renderedResult.length,
        sensitivity: "tool-output" as const,
      })),
  ];
  let relevantRemaining = relevantBudget;
  const relevantSelected: Array<
    (typeof relevantCandidates)[number] & { selectedText: string }
  > = [];
  const relevantSelectionOrder = [
    ...relevantCandidates.filter((candidate) => candidate.reason === "sandbox-trap"),
    ...relevantCandidates
      .filter((candidate) => candidate.reason !== "sandbox-trap")
      .sort((left, right) => right.index - left.index),
  ];
  for (const candidate of relevantSelectionOrder) {
    const mandatory = candidate.reason === "sandbox-trap";
    const text = mandatory
      ? candidate.text
      : reviewerTokenPrefix(candidate.text, relevantRemaining);
    if (text) {
      relevantSelected.push({ ...candidate, selectedText: text });
      if (!mandatory) relevantRemaining -= estimateReviewerTokens(text);
    }
  }
  relevantSelected.sort((left, right) => left.index - right.index);
  const pairedToolCallIds = new Set(
    relevantSelected
      .map((candidate) => candidate.toolCallId)
      .filter((id): id is string => Boolean(id)),
  );
  const resultReasons = new Set<EvidenceSelectionReason>([
    "same-tool",
    "delete-precheck",
    "git-push-context",
    "provider-branch-protection",
  ]);
  const finalTools = tools.selected.filter((tool) => {
    if (!resultReasons.has(tool.reason)) return true;
    if (tool.toolCallId && pairedToolCallIds.has(tool.toolCallId)) return true;
    return tool.secondaryReasons.some((reason) => !resultReasons.has(reason));
  });
  const selected = [...users.selected, ...finalTools].sort(
    (left, right) => left.index - right.index,
  );
  const baseRendered = selected
    .map((item) => {
      const attributes = item.kind === "tool"
        ? ` id="${escapeEvidenceMarkup(item.toolCallId ?? item.id)}" reason="${item.reason}"`
        : ` reason="${item.reason}"`;
      return `<${item.kind}${attributes}>\n${escapeEvidenceMarkup(item.text)}\n</${item.kind}>`;
    })
    .join("\n\n");
  const authorizationNotice =
    users.compactionState === "authorization-unavailable"
      ? "[Original user authorization is unavailable after compaction. Agent-generated summaries are not authorization.]"
      : users.compactionState === "summary-present"
        ? "[A compaction/branch summary exists but is not user authorization.]"
        : "";
  const rendered = [
    authorizationNotice,
    baseRendered,
    ...relevantSelected.map((candidate) => candidate.selectedText),
  ]
    .filter(Boolean)
    .join("\n\n");
  const relevantTruncated =
    relevantSelected.length < relevantCandidates.length ||
    relevantSelected.reduce(
      (total, value) => total + value.selectedText.length,
      0,
    ) <
      relevantCandidates.reduce((total, value) => total + value.text.length, 0);
  const truncated =
    users.truncated ||
    tools.truncated ||
    finalTools.length < tools.selected.length ||
    relevantTruncated;
  const text = truncated
    ? `[Some transcript evidence was omitted or truncated.]\n\n${rendered}`
    : rendered;
  return {
    text: text || "(no eligible transcript evidence)",
    surfaceProfile: profile,
    reviewerEvidence: {
      userMessages: users.selected.map((item) => ({
        id: item.id,
        reason: item.reason,
        secondaryReasons: [...item.secondaryReasons],
        content: item.text,
        source: {
          entryIndex: item.entryIndex,
          provenance: "raw-user-message",
          complete: !item.preTruncated,
        },
      })),
      toolCalls: finalTools.map((item) => ({
        id: item.id,
        reason: item.reason,
        secondaryReasons: [...item.secondaryReasons],
        ...(item.toolCallId ? { toolCallId: item.toolCallId } : {}),
        content: item.text,
      })),
      relevantResults: relevantSelected.map((item) => ({
        id: item.id,
        reason: item.reason,
        secondaryReasons: [],
        ...(item.toolCallId ? { toolCallId: item.toolCallId } : {}),
        content: item.selectedText === item.text
          ? item.content
          : item.selectedText,
      })),
    },
    budgetRemovals: [],
    userCharacters: users.selected.reduce(
      (total, item) => total + item.text.length,
      0,
    ),
    toolCharacters: finalTools.reduce(
      (total, item) => total + item.text.length,
      0,
    ),
    relevantResultCharacters: relevantSelected.reduce(
      (total, item) =>
        total +
        (item.selectedText === item.text
          ? item.content.length
          : item.selectedText.length),
      0,
    ),
    truncated,
    optionalHistoryOmittedOrTruncated:
      users.optionalHistoryOmittedOrTruncated || tools.truncated ||
      finalTools.length < tools.selected.length || relevantTruncated,
    selectedCandidates: [
      ...users.selected.map((item) =>
        selectedMetadata(
          item,
          evidence.find((candidate) => candidate.id === item.id)!,
          profile,
        ),
      ),
      ...finalTools.map((item) =>
        selectedMetadata(
          item,
          evidence.find((candidate) => candidate.id === item.id)!,
          profile,
        ),
      ),
      ...relevantSelected.map((item) => ({
        id: item.id,
        entryIndex: item.index,
        kind: item.sensitivity === "boundary" ? "sandbox-trap" as const : "tool-result" as const,
        ...(item.toolCallId ? { toolCallId: item.toolCallId } : {}),
        reason: item.reason,
        secondaryReasons: [],
        surfaceProfile: profile,
        originalCharacters: item.rawCharacters,
        selectedCharacters: item.selectedText.length,
        estimatedTokens: estimateReviewerTokens(item.selectedText),
        truncated: item.selectedText.length < item.rawCharacters,
        sensitivity: item.sensitivity,
      })),
    ].sort((left, right) => left.entryIndex - right.entryIndex),
    ...(requestAwareTools.criticalEvidenceOverflow
      ? { failureCode: "critical_evidence_overflow" as const }
      : {}),
    userAuthorizationCeiling: users.authorizationCeiling,
    userConstraint: users.constraint,
    compactionState: users.compactionState,
    rawUserAuthorization: users.rawUserAuthorization,
  };
}
