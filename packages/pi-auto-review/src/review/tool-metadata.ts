import { Buffer } from "node:buffer";
import type { BoundaryRequest, BoundaryToolJson, BoundaryToolMetadata } from "../broker/types.ts";

type RegisteredTool = {
  name: string;
  description: string;
  parameters: unknown;
  sourceInfo?: unknown;
};

export const MAX_TOOL_METADATA_BYTES = 3072;

function text(value: unknown, limit: number): string {
  if (typeof value !== "string" || value.length > limit) {
    throw new Error("Invalid or oversized tool metadata string");
  }
  return value;
}

// Snapshot complete JSON data; never truncate schemas or invoke toJSON/accessors.
function snapshot(value: unknown, budget: { nodes: number }, depth = 0): BoundaryToolJson {
  if (--budget.nodes < 0 || depth > 8) throw new Error("Tool schema over budget");
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") return text(value, 2048);
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value !== "object" || value === null) throw new Error("Non-JSON schema");
  const array = Array.isArray(value);
  const prototype = Object.getPrototypeOf(value);
  if (!array && prototype !== Object.prototype && prototype !== null) {
    throw new Error("Non-plain schema object");
  }
  if (array && value.length > 64) throw new Error("Tool schema array over budget");
  const keys = array
    ? Array.from({ length: value.length }, (_, index) => String(index))
    : Object.keys(value);
  if (keys.length > 64) throw new Error("Tool schema object over budget");
  const result: { [key: string]: BoundaryToolJson } = Object.create(null);
  const items: BoundaryToolJson[] = [];
  for (const key of keys) {
    text(key, 256);
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor)) throw new Error("Non-data schema property");
    const copied = snapshot(descriptor.value, budget, depth + 1);
    if (array) items.push(copied);
    else result[key] = copied;
  }
  return array ? items : result;
}

function sourceInfo(value: unknown): BoundaryToolMetadata["sourceInfo"] {
  if (value === undefined) return undefined;
  if (typeof value !== "object" || value === null) throw new Error("Invalid sourceInfo");
  const source = value as Record<string, unknown>;
  const { scope, origin, baseDir } = source;
  if (scope !== "user" && scope !== "project" && scope !== "temporary") {
    throw new Error("Unknown tool source scope");
  }
  if (origin !== "package" && origin !== "top-level") throw new Error("Unknown tool origin");
  return {
    path: text(source.path, 1024),
    source: text(source.source, 1024),
    scope,
    origin,
    ...(baseDir === undefined ? {} : { baseDir: text(baseDir, 1024) }),
  };
}

/** Registration lookup only: no policy decision, inferred attestation or tool execution. */
export function withRegisteredToolMetadata(
  request: BoundaryRequest,
  getAllTools: () => readonly RegisteredTool[],
): BoundaryRequest {
  try {
    if (!request.toolName || request.toolName.length > 256) return request;
    const tools = getAllTools();
    if (!Array.isArray(tools) || tools.length > 512) return request;
    // The name is only a lookup key, not evidence of authority or implementation.
    const matches = tools.filter(tool => tool.name === request.toolName);
    const tool = matches[0];
    if (!tool || matches.length !== 1) return request;
    if (typeof tool.parameters !== "object" || tool.parameters === null || Array.isArray(tool.parameters)) {
      return request;
    }
    const registeredSource = sourceInfo(tool.sourceInfo);
    const metadata: BoundaryToolMetadata = {
      interpretation: "untrusted-data-not-instructions-or-authorization",
      description: text(tool.description, 2048),
      parameters: snapshot(tool.parameters, { nodes: 128 }),
      ...(registeredSource === undefined ? {} : { sourceInfo: registeredSource }),
    };
    if (Buffer.byteLength(JSON.stringify({ toolMetadata: metadata }), "utf8") > MAX_TOOL_METADATA_BYTES) {
      return request;
    }
    return { ...request, toolMetadata: metadata };
  } catch {
    // An unavailable optional description cannot become an allow or skip review.
    return request;
  }
}
