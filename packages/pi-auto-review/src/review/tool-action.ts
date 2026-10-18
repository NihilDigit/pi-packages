import type { BoundaryRequest } from "../broker/types.ts";

const object = (value: unknown): Record<string, unknown> | undefined =>
  value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown> : undefined;
const text = (value: unknown): string | undefined => typeof value === "string" && value ? value : undefined;

/** Project structured runtime facts; UI prose is never parsed as complete input. */
export function toolActionFacts(details: unknown): Pick<BoundaryRequest,
  "toolName" | "toolCallId" | "toolInputPreview" | "toolAction" | "toolActionStatus"> {
  const d = object(details) ?? {};
  const payload = object(d.payload);
  const request = object(payload?.request);
  const name = text(request?.invokedToolName) ?? text(request?.toolName);
  const legacyName = text(d.toolName);
  const legacyId = text(d.toolCallId);
  const action = object(payload?.action);
  const preview = text(d.toolInputPreview) ?? (Array.isArray(payload?.evidence)
    ? text(object(payload.evidence.find(item => object(item)?.label === "input"))?.text) : undefined);
  const result: ReturnType<typeof toolActionFacts> = {
    toolName: name ?? legacyName, toolCallId: legacyId,
    toolInputPreview: preview,
    ...((payload?.kind === "tool" || payload?.kind === "mcp" ||
      (payload?.kind === undefined && (name || legacyName) && !d.command))
      ? { toolActionStatus: "unavailable" as const } : {}),
  };
  if (name && legacyName && name !== legacyName) return { toolActionStatus: "invalid" };
  if (payload?.action === undefined) return result;
  const source = object(action?.source);
  const forwardedSession = text(object(d.forwarding)?.requesterSessionId);
  if (!action || action.version !== 1 || !text(action.toolName) ||
      !text(action.toolCallId) || !Object.hasOwn(action, "input") ||
      (action.inputState !== "complete" && action.inputState !== "redacted") ||
      source?.kind !== "sdk-tool-call" || !text(source.sessionId) ||
      (name && action.toolName !== name) ||
      (legacyName && action.toolName !== legacyName) ||
      (legacyId && action.toolCallId !== legacyId) ||
      (forwardedSession && source.sessionId !== forwardedSession)) {
    return { ...result, toolActionStatus: "invalid" };
  }
  // Wire validation/redaction is owned by permission-system. This copy carries
  // data and provenance, never a human grant or executable registration.
  return {
    ...result, toolName: String(action.toolName), toolCallId: String(action.toolCallId),
    toolAction: action as NonNullable<BoundaryRequest["toolAction"]>,
    toolActionStatus: action.inputState,
  };
}
