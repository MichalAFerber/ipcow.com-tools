import { ToolError } from '../errors';

export interface RedirectHop {
  url: string;
  status: number;
  location: string;
}

export interface SecurityHeaders {
  hsts: string | null;
  csp: string | null;
  xContentTypeOptions: string | null;
  xFrameOptions: string | null;
  referrerPolicy: string | null;
  permissionsPolicy: string | null;
}

export interface HttpHeadersResult {
  url: string;
  finalUrl: string;
  status: number;
  redirects: RedirectHop[];
  headers: Record<string, string>;
  security: SecurityHeaders;
}

const MAX_REDIRECTS = 10;
const UA = 'ipcow-http-check/1.0 (+https://ipcow.com)';

function normalizeUrl(input: string): string {
  let raw = input.trim();
  if (raw === '') throw new ToolError('invalid_input', 'missing URL');
  if (!/^https?:\/\//i.test(raw)) raw = `https://${raw}`;
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new ToolError('invalid_input', `invalid URL: ${input}`);
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    throw new ToolError('invalid_input', `unsupported protocol: ${u.protocol}`);
  }
  return u.toString();
}

/** Pull the notable security headers out of a (lowercased) header map. */
export function extractSecurityHeaders(headers: Record<string, string>): SecurityHeaders {
  const g = (k: string) => headers[k] ?? null;
  return {
    hsts: g('strict-transport-security'),
    csp: g('content-security-policy'),
    xContentTypeOptions: g('x-content-type-options'),
    xFrameOptions: g('x-frame-options'),
    referrerPolicy: g('referrer-policy'),
    permissionsPolicy: g('permissions-policy'),
  };
}

function headersToObject(h: Headers): Record<string, string> {
  const obj: Record<string, string> = {};
  h.forEach((v, k) => {
    obj[k] = v; // Headers keys are already lowercased
  });
  return obj;
}

/**
 * Fetch a URL, follow the redirect chain by hand, and report the final response headers plus a
 * pulled-out set of security headers. Uses `redirect: 'manual'` so each hop is visible; runs the
 * same on the Node and Workers targets.
 */
export async function checkHttpHeaders(
  input: string,
  opts?: {
    timeoutMs?: number;
    /**
     * SSRF guard, injected by the caller (kept out of this portable package so it has no Node-only
     * DNS deps). Called for the initial URL AND every redirect hop before the request; it should
     * throw if the target host doesn't resolve to a public address.
     */
    assertAllowed?: (url: string) => void | Promise<void>;
  },
): Promise<HttpHeadersResult> {
  const start = normalizeUrl(input);
  const timeoutMs = opts?.timeoutMs ?? 8000;
  const redirects: RedirectHop[] = [];
  let current = start;

  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    if (opts?.assertAllowed) await opts.assertAllowed(current);
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    let res: Response;
    try {
      res = await fetch(current, {
        method: 'GET',
        redirect: 'manual',
        signal: ctrl.signal,
        headers: { 'user-agent': UA },
      });
    } catch (err) {
      const n = (err as Error)?.name;
      if (n === 'TimeoutError' || n === 'AbortError') {
        throw new ToolError('timeout', `request to ${current} timed out`);
      }
      throw new ToolError(
        'upstream_error',
        `request to ${current} failed: ${(err as Error)?.message}`,
      );
    } finally {
      clearTimeout(timer);
    }
    void res.body?.cancel().catch(() => {}); // headers only — don't download the body

    const status = res.status;
    const location = res.headers.get('location');
    if (status >= 300 && status < 400 && location && i < MAX_REDIRECTS) {
      const next = new URL(location, current).toString();
      redirects.push({ url: current, status, location: next });
      current = next;
      continue;
    }

    const headers = headersToObject(res.headers);
    return {
      url: start,
      finalUrl: current,
      status,
      redirects,
      headers,
      security: extractSecurityHeaders(headers),
    };
  }

  throw new ToolError('upstream_error', `too many redirects (>${MAX_REDIRECTS}) from ${start}`);
}
