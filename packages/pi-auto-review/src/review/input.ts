import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import type {
  AuthorizerLog,
  AuthorizerVerdict,
  PermissionQuery,
  PromptPermissionDetails,
} from "@gotgenes/pi-permission-system";
import {
  canonicalReviewerJson,
  normalizePermissionEvidence,
  type TranscriptResult,
} from "../policy.ts";
import { parseHostPort } from "../integrations/sandbox.ts";
import { isPathSurface } from "../path-surfaces.ts";
import type { BoundaryRequest, BoundaryReviewerContext } from "../broker/index.ts";
import type {
  CompletionMessage,
  Config,
  PreflightPart,
  ReviewPreflight,
} from "./types.ts";
import {
  EXTENSION_NAME,
  PROJECT_CONFIG_PATH,
  REVIEWER_FRAMING_RESERVE_TOKENS,
} from "./consts.ts";
import { reviewerSystemPrompt } from "./prompts.ts";
import { applyProjectConfig } from "./config.ts";
import { assertTrustedInstallation } from "./guards.ts";
import { estimateReviewerTokens } from "./token-estimate.ts";
import { toolActionFacts } from "./tool-action.ts";
export { estimateReviewerTokens } from "./token-estimate.ts";

export function sessionConfig(
  cwd: string,
  trusted: Config,
  allowUntrustedWorkspace: boolean,
): Readonly<Config> {
  if (!allowUntrustedWorkspace) assertTrustedInstallation(cwd);
  const projectPath = join(cwd, PROJECT_CONFIG_PATH);
  let raw: unknown;
  try {
    const content = readFileSync(projectPath, "utf8");
    if (!content.trim()) {
      // Treat empty/whitespace-only file the same as missing — sandbox
      // runtime may leave 0-byte mount-point stubs for denyWrite paths.
      return Object.freeze({ ...trusted });
    }
    raw = JSON.parse(content);
  } catch (error) {
    if (
      error &&
      typeof error === "object" &&
      "code" in error &&
      error.code === "ENOENT"
    ) {
      return Object.freeze({ ...trusted });
    }
    throw new Error(
      `${EXTENSION_NAME}: cannot load ${projectPath}: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  return applyProjectConfig(trusted, raw);
}

export function boundedRequest(surface: string): boolean {
  return isPathSurface(surface);
}

export type PermissionsService = {
  registerAuthorizer(
    name: string,
    authorize: (
      details: PromptPermissionDetails,
      query: PermissionQuery,
      log: AuthorizerLog,
    ) => Promise<AuthorizerVerdict>,
  ): () => void;
};

export function boundaryRequest(
  ctx: ExtensionContext,
  details: PromptPermissionDetails,
  query: PermissionQuery,
): BoundaryRequest {
  const evidence = normalizePermissionEvidence(details);
  const surface = evidence.surface;
  const value =
    evidence.resolvedPath ??
    (isPathSurface(surface)
      ? evidence.path
      : evidence.command ?? evidence.value ?? evidence.destination) ??
    details.skillName ??
    details.toolName;
  const deterministicPolicy = query.checkPermission(
    surface,
    value,
    evidence.requester?.agentName,
  );
  const policyRule =
    typeof deterministicPolicy === "string"
      ? deterministicPolicy
      : JSON.stringify(deterministicPolicy);
  const destParsed = parseHostPort(evidence.destination);
  return {
    id: details.requestId,
    source: "permission-system",
    surface,
    operation: details.source || surface,
    cwd: ctx.cwd,
    command: evidence.command,
    ...(evidence.executedUnit ? { executedUnit: evidence.executedUnit } : {}),
    ...(evidence.fullCommand ? { fullCommand: evidence.fullCommand } : {}),
    ...(evidence.matchedPattern
      ? { matchedPattern: evidence.matchedPattern }
      : {}),
    ...(evidence.matchedSpelling
      ? { matchedSpelling: evidence.matchedSpelling }
      : {}),
    path: evidence.path,
    resolvedPath: evidence.resolvedPath,
    destination: evidence.destination,
    destinationHost: destParsed?.host,
    destinationPort: destParsed?.port,
    ...toolActionFacts(details),
    skillName: details.skillName,
    agentName: evidence.requester?.agentName,
    requesterSessionId: evidence.requester?.sessionId,
    accessIntent: evidence.accessIntent,
    matchedPolicy: {
      decision: "ask" as const,
      rule: policyRule,
    },
  } satisfies BoundaryRequest;
}

export function textFromAssistant(message: CompletionMessage): string {
  return (message.content || [])
    .filter((part) => part.type === "text" && typeof part.text === "string")
    .map((part) => part.text)
    .join("\n")
    .trim();
}

// Local budget state survives cloneTranscript's spread without changing policy types.
type BudgetedTranscript = TranscriptResult & { toolMetadataOmittedForBudget?: true };

export function sharedReviewContext(
  request: BoundaryRequest,
  transcript: TranscriptResult,
  reviewerContext?: BoundaryReviewerContext,
): string {
  const rawUserAuthorization = transcript.rawUserAuthorization ?? {
    status: "unavailable",
    sources: [],
  };
  return canonicalReviewerJson({
    evidence: {
      ...(transcript.reviewerEvidence.assistantContext?.length ? {
        assistantContext: {
          items: transcript.reviewerEvidence.assistantContext,
          trust: "untrusted",
          interpretation: "reference-context-not-authorization",
        },
      } : {}),
      relevantResults: {
        items: transcript.reviewerEvidence.relevantResults,
        trust: "untrusted",
      },
      toolCalls: {
        items: transcript.reviewerEvidence.toolCalls,
        trust: "untrusted",
      },
      userMessages: {
        items: transcript.reviewerEvidence.userMessages,
        trust: "untrusted",
      },
    },
    omissions: {
      ...(transcript.compactionState !== "none"
        ? { agentGeneratedSummaryExcludedFromAuthorization: true }
        : {}),
      evidenceOmittedOrTruncated:
        reviewerRequestView(request).fullCommandTruncated === true ||
        (request.toolActionStatus !== undefined && request.toolActionStatus !== "complete") ||
        rawUserAuthorization.status !== "complete" ||
        (transcript.reviewerEvidence.assistantContext?.some((item) => !item.source.complete) ?? false) ||
        transcript.failureCode === "critical_evidence_overflow" ||
        transcript.failureCode === "required_profile_overflow" ||
        transcript.selectedCandidates.some((item) => item.truncated &&
          (item.reason === "exact-tool-call" || item.reason === "security-combination" ||
            item.reason === "sandbox-trap")),
      optionalHistoryOmittedOrTruncated: transcript.optionalHistoryOmittedOrTruncated ?? false,
      rawUserAuthorizationUnavailable:
        rawUserAuthorization.status === "unavailable",
      rawUserAuthorizationIncomplete:
        rawUserAuthorization.status === "incomplete",
      ...((transcript as BudgetedTranscript).toolMetadataOmittedForBudget
        ? { registeredToolMetadataOmittedForBudget: true }
        : {}),
      ...(transcript.budgetRemovals.length > 0
        ? { budgetRemovals: transcript.budgetRemovals }
        : {}),
    },
    ...(reviewerContext?.userOverride
      ? {
          override: {
            ...reviewerContext.userOverride,
            retryRequestId: request.id,
            binding: "host-validated-session-and-exact-action",
            consumedForCurrentReview: true,
            kind: "trusted-exact-retry",
            trust: "host-generated",
          },
        }
      : {}),
    mandatoryEvidence: {
      currentAction: {
        id: request.id,
        provenance: "permission-boundary-request",
        complete: reviewerRequestView(request).fullCommandTruncated !== true &&
          (request.toolActionStatus === undefined || request.toolActionStatus === "complete"),
        ...(request.toolActionStatus ? { toolInputStatus: request.toolActionStatus } : {}),
      },
      rawUserAuthorization,
    },
    profile: transcript.surfaceProfile,
    request: reviewerRequestView(request, transcript),
  });
}

/**
 * Preserve all mandatory action facts. Only optional registration metadata may
 * be omitted; the complete prompt's token cap, not a byte cap, bounds review.
 * An incoming incompleteness marker is retained, never repaired by projection.
 */
export function reviewerRequestView(
  request: BoundaryRequest,
  transcript?: TranscriptResult,
): BoundaryRequest {
  const view: BoundaryRequest = { ...request };
  if ((transcript as BudgetedTranscript | undefined)?.toolMetadataOmittedForBudget) {
    delete view.toolMetadata;
  }
  return view;
}

export function preflightPart(text: string): PreflightPart {
  return {
    characters: text.length,
    estimatedTokens: estimateReviewerTokens(text),
  };
}

export function combinedPreflightPart(values: readonly string[]): PreflightPart {
  return values.reduce<PreflightPart>(
    (total, value) => ({
      characters: total.characters + value.length,
      estimatedTokens:
        total.estimatedTokens + estimateReviewerTokens(value),
    }),
    { characters: 0, estimatedTokens: 0 },
  );
}

export function reviewPreflight(
  request: BoundaryRequest,
  transcript: TranscriptResult,
  reviewerContext: BoundaryReviewerContext | undefined,
  sharedContext: string,
  maxReviewerInputTokens: number,
): ReviewPreflight {
  const fixedPrompt = preflightPart(reviewerSystemPrompt(Boolean(reviewerContext?.userOverride)));
  const canonicalRequest = preflightPart(
    canonicalReviewerJson(reviewerRequestView(request, transcript)),
  );
  const override = preflightPart(
    reviewerContext?.userOverride
      ? canonicalReviewerJson(reviewerContext.userOverride)
      : "",
  );
  const user = combinedPreflightPart(
    transcript.reviewerEvidence.userMessages.map((item) => item.content),
  );
  const assistantContext = combinedPreflightPart(
    transcript.reviewerEvidence.assistantContext?.map((item) => item.content) ?? [],
  );
  const tool = combinedPreflightPart(
    transcript.reviewerEvidence.toolCalls.map((item) => item.content),
  );
  const relevantResult = combinedPreflightPart(
    transcript.reviewerEvidence.relevantResults.map((item) => item.content),
  );
  const dynamic = preflightPart(sharedContext);
  const dynamicEvidenceCharacters =
    canonicalRequest.characters +
    override.characters +
    user.characters +
    assistantContext.characters +
    tool.characters +
    relevantResult.characters;
  const dynamicEvidenceTokens =
    canonicalRequest.estimatedTokens +
    override.estimatedTokens +
    user.estimatedTokens +
    assistantContext.estimatedTokens +
    tool.estimatedTokens +
    relevantResult.estimatedTokens;
  const framing: PreflightPart = {
    characters: Math.max(0, dynamic.characters - dynamicEvidenceCharacters),
    estimatedTokens:
      Math.max(0, dynamic.estimatedTokens - dynamicEvidenceTokens) +
      REVIEWER_FRAMING_RESERVE_TOKENS,
  };
  const total: PreflightPart = {
    characters: fixedPrompt.characters + dynamic.characters,
    estimatedTokens:
      fixedPrompt.estimatedTokens +
      dynamic.estimatedTokens +
      REVIEWER_FRAMING_RESERVE_TOKENS,
  };
  return {
    estimator: "conservative:cjk-aware",
    maxReviewerInputTokens,
    framingReserveTokens: REVIEWER_FRAMING_RESERVE_TOKENS,
    fixedPrompt,
    canonicalRequest,
    override,
    user,
    assistantContext,
    tool,
    relevantResult,
    framing,
    total,
  };
}

export function cloneTranscript(transcript: TranscriptResult): TranscriptResult {
  const cloneItems = (items: TranscriptResult["reviewerEvidence"]["userMessages"]) =>
    items.map((item) => ({
      ...item,
      secondaryReasons: [...item.secondaryReasons],
      ...(item.source ? { source: { ...item.source } } : {}),
    }));
  return {
    ...transcript,
    reviewerEvidence: {
      ...(transcript.reviewerEvidence.assistantContext ? {
        assistantContext: transcript.reviewerEvidence.assistantContext.map((item) => ({
          ...item, source: { ...item.source },
        })),
      } : {}),
      userMessages: cloneItems(transcript.reviewerEvidence.userMessages),
      toolCalls: cloneItems(transcript.reviewerEvidence.toolCalls),
      relevantResults: cloneItems(transcript.reviewerEvidence.relevantResults),
    },
    ...(transcript.rawUserAuthorization ? {
      rawUserAuthorization: {
        ...transcript.rawUserAuthorization,
        sources: transcript.rawUserAuthorization.sources.map((item) => ({ ...item })),
      },
    } : {}),
    budgetRemovals: transcript.budgetRemovals.map((item) => ({ ...item })),
    selectedCandidates: transcript.selectedCandidates.map((item) => ({
      ...item,
      secondaryReasons: [...item.secondaryReasons],
    })),
  };
}

export function recordBudgetRemoval(
  transcript: TranscriptResult,
  reason: TranscriptResult["budgetRemovals"][number]["reason"],
  count: number,
): void {
  if (count <= 0) return;
  const existing = transcript.budgetRemovals.find(
    (item) => item.reason === reason,
  );
  if (existing) existing.count += count;
  else transcript.budgetRemovals.push({ reason, count });
}

export function refreshBudgetedTranscript(transcript: TranscriptResult): void {
  const retainedIds = new Set([
    ...transcript.reviewerEvidence.assistantContext ?? [],
    ...transcript.reviewerEvidence.userMessages,
    ...transcript.reviewerEvidence.toolCalls,
    ...transcript.reviewerEvidence.relevantResults,
  ].map((item) => item.id));
  transcript.selectedCandidates = transcript.selectedCandidates.filter(
    (item) => retainedIds.has(item.id),
  );
  transcript.userCharacters = transcript.reviewerEvidence.userMessages.reduce(
    (total, item) => total + item.content.length,
    0,
  );
  transcript.toolCharacters = transcript.reviewerEvidence.toolCalls.reduce(
    (total, item) => total + item.content.length,
    0,
  );
  transcript.relevantResultCharacters =
    transcript.reviewerEvidence.relevantResults.reduce(
      (total, item) => total + item.content.length,
      0,
    );
  if (transcript.budgetRemovals.length > 0) {
    transcript.truncated = true;
    transcript.optionalHistoryOmittedOrTruncated = true;
  }
}

export function applyReviewerInputBudget(
  request: BoundaryRequest,
  source: TranscriptResult,
  reviewerContext: BoundaryReviewerContext | undefined,
  maxReviewerInputTokens: number,
): TranscriptResult {
  const transcript: BudgetedTranscript = cloneTranscript(source);
  if (transcript.failureCode) return transcript;
  const estimatedTokens = () => {
    const context = sharedReviewContext(request, transcript, reviewerContext);
    return reviewPreflight(
      request,
      transcript,
      reviewerContext,
      context,
      maxReviewerInputTokens,
    ).total.estimatedTokens;
  };
  if (estimatedTokens() <= maxReviewerInputTokens) return transcript;

  // Optional metadata must never displace existing authorization/evidence. Both
  // shared context and preflight read this flag; the stored request stays intact.
  if (request.toolMetadata) {
    transcript.toolMetadataOmittedForBudget = true;
    if (estimatedTokens() <= maxReviewerInputTokens) return transcript;
  }

  let secondaryReasonCount = 0;
  for (const item of [
    ...transcript.reviewerEvidence.userMessages,
    ...transcript.reviewerEvidence.toolCalls,
    ...transcript.reviewerEvidence.relevantResults,
  ]) {
    secondaryReasonCount += item.secondaryReasons.length;
    item.secondaryReasons = [];
  }
  for (const item of transcript.selectedCandidates) {
    item.secondaryReasons = [];
  }
  recordBudgetRemoval(transcript, "secondary-reasons", secondaryReasonCount);
  refreshBudgetedTranscript(transcript);
  if (estimatedTokens() <= maxReviewerInputTokens) return transcript;

  const contexts = transcript.reviewerEvidence.assistantContext ?? [];
  for (let index = contexts.length - 1; index >= 0; index--) {
    const context = contexts[index]!;
    const user = transcript.reviewerEvidence.userMessages.find((item) => item.id === context.beforeUserMessageId);
    if (user?.reason !== "recent-user-history") continue;
    contexts.splice(index, 1);
    recordBudgetRemoval(transcript, "optional-assistant-context", 1);
    refreshBudgetedTranscript(transcript);
    if (estimatedTokens() <= maxReviewerInputTokens) return transcript;
  }

  for (let index = 0; index < transcript.reviewerEvidence.userMessages.length;) {
    const item = transcript.reviewerEvidence.userMessages[index];
    if (!item || item.reason !== "recent-user-history") {
      index++;
      continue;
    }
    transcript.reviewerEvidence.userMessages.splice(index, 1);
    transcript.reviewerEvidence.assistantContext = transcript.reviewerEvidence.assistantContext
      ?.filter((context) => context.beforeUserMessageId !== item.id);
    recordBudgetRemoval(transcript, "optional-user-history", 1);
    refreshBudgetedTranscript(transcript);
    if (estimatedTokens() <= maxReviewerInputTokens) return transcript;
  }

  for (let index = 0; index < transcript.reviewerEvidence.toolCalls.length;) {
    const item = transcript.reviewerEvidence.toolCalls[index];
    if (!item || item.reason !== "structured-request-match") {
      index++;
      continue;
    }
    transcript.reviewerEvidence.toolCalls.splice(index, 1);
    recordBudgetRemoval(transcript, "older-structured-tool", 1);
    refreshBudgetedTranscript(transcript);
    if (estimatedTokens() <= maxReviewerInputTokens) return transcript;
  }

  for (let index = 0; index < transcript.reviewerEvidence.relevantResults.length;) {
    const item = transcript.reviewerEvidence.relevantResults[index];
    if (!item || item.reason === "sandbox-trap") {
      index++;
      continue;
    }
    transcript.reviewerEvidence.relevantResults.splice(index, 1);
    if (item.toolCallId) {
      transcript.reviewerEvidence.toolCalls =
        transcript.reviewerEvidence.toolCalls.filter(
          (tool) =>
            tool.toolCallId !== item.toolCallId ||
            tool.reason === "exact-tool-call" ||
            tool.reason === "security-combination",
        );
    }
    recordBudgetRemoval(transcript, "optional-result", 1);
    refreshBudgetedTranscript(transcript);
    if (estimatedTokens() <= maxReviewerInputTokens) return transcript;
  }

  transcript.failureCode = "reviewer_input_budget_exceeded";
  return transcript;
}

