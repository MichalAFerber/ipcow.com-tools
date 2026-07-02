// Portable (Node + Workers). The domains a short URL can be built on, plus shape helpers shared by
// the tool UI, the create endpoint, and the redirect handler. Public so the target-URL validation
// (which prevents javascript:/data: and host-less links) is reviewable.

// First entry is the default in the tool's domain picker.
export const SHORT_DOMAINS = ['73mp.net', 'shortcow.com', 'n9a.us', 'n48.us'] as const;
export type ShortDomain = (typeof SHORT_DOMAINS)[number];

export function isShortDomain(host: string): host is ShortDomain {
  return (SHORT_DOMAINS as readonly string[]).includes(host);
}

/** Short codes are 5–10 base62 chars. */
const CODE_RE = /^[0-9A-Za-z]{5,10}$/;
export function isShortCode(code: string): boolean {
  return CODE_RE.test(code);
}

/** Validate + normalize a target URL: http(s) only, has a host, length-capped. */
export function normalizeTargetUrl(input: unknown): string | null {
  if (typeof input !== 'string') return null;
  const raw = input.trim();
  if (!raw || raw.length > 2048) return null;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
  if (!url.hostname || !url.hostname.includes('.')) return null;
  return url.toString();
}
