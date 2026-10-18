/**
 * Conservative reviewer estimate: CJK code points cost one token; remaining
 * code points cost their UTF-8 byte length / 3 (rounded up for the whole text).
 * Shared by evidence selection and the complete prompt preflight.
 */
const OTHER_BYTES_PER_TOKEN = 3;

function codePointUtf8Bytes(code: number): number {
  return code < 0x80 ? 1 : code < 0x800 ? 2 : code < 0x10000 ? 3 : 4;
}

function isCjkCodePoint(code: number): boolean {
  return (
    (code >= 0x3000 && code <= 0x9fff) ||
    (code >= 0x3400 && code <= 0x4dbf) ||
    (code >= 0xf900 && code <= 0xfaff) ||
    (code >= 0xac00 && code <= 0xd7af) ||
    (code >= 0x3040 && code <= 0x30ff) ||
    (code >= 0xff00 && code <= 0xffef)
  );
}

export function estimateReviewerTokens(text: string): number {
  let tokens = 0;
  for (const char of text) {
    const code = char.codePointAt(0) ?? 0;
    tokens += isCjkCodePoint(code)
      ? 1
      : codePointUtf8Bytes(code) / OTHER_BYTES_PER_TOKEN;
  }
  return Math.ceil(tokens);
}

/** Prefix within the same estimate, without splitting Unicode code points. */
export function reviewerTokenPrefix(text: string, maxTokens: number): string {
  if (maxTokens <= 0) return "";
  let tokens = 0;
  let end = 0;
  for (const char of text) {
    const code = char.codePointAt(0) ?? 0;
    const next = tokens + (isCjkCodePoint(code)
      ? 1
      : codePointUtf8Bytes(code) / OTHER_BYTES_PER_TOKEN);
    if (Math.ceil(next) > maxTokens) break;
    tokens = next;
    end += char.length;
  }
  return text.slice(0, end);
}
