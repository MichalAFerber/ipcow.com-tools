import { ToolError } from '../errors';
import { type DnsMessage, type RecordType, decodeMessage, encodeQuery } from './wire';

export interface DohOptions {
  /** RFC 8484 resolver endpoint. If set, only this resolver is used (no fallback). */
  resolver?: string;
  /** Explicit ordered list of resolvers to try. Overrides `resolver` and the default chain. */
  resolvers?: string[];
  timeoutMs?: number;
}

export const RESOLVERS = {
  /** Quad9 — privacy-first, non-profit, malware-blocking. Our default. */
  quad9: 'https://dns.quad9.net/dns-query',
  /** Cloudflare — fast fallback (we already host here; not Google/Apple/MS). */
  cloudflare: 'https://cloudflare-dns.com/dns-query',
} as const;

export const DEFAULT_RESOLVER = RESOLVERS.quad9;

/** Default chain: Quad9 first, then Cloudflare — so a single resolver/edge hiccup
 *  (e.g. one returning a 5xx for our egress) doesn't fail the whole lookup. */
const DEFAULT_RESOLVERS: string[] = [RESOLVERS.quad9, RESOLVERS.cloudflare];

/** base64url (no padding) — for the RFC 8484 GET form. btoa is available in Workers + Node 18+. */
function base64url(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Perform a DoH query and return the decoded message. Uses the RFC 8484 **GET** form
 * (query in the URL, no binary request body): it's the most broadly compatible shape across
 * runtimes/edges and is cacheable, which sidesteps environments that reject the wireformat
 * POST. Tries each resolver in turn so one bad upstream doesn't break the lookup.
 */
export async function dohQuery(
  name: string,
  type: RecordType,
  opts?: DohOptions,
): Promise<DnsMessage> {
  const dns = base64url(encodeQuery(name, type));
  const list = opts?.resolvers ?? (opts?.resolver ? [opts.resolver] : DEFAULT_RESOLVERS);
  const timeoutMs = opts?.timeoutMs ?? 5000;

  let lastErr: ToolError | undefined;
  for (const resolver of list) {
    const url = `${resolver}${resolver.includes('?') ? '&' : '?'}dns=${dns}`;
    let res: Response;
    try {
      res = await fetch(url, {
        method: 'GET',
        headers: { accept: 'application/dns-message' },
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (err) {
      const errName = (err as Error)?.name;
      lastErr =
        errName === 'TimeoutError' || errName === 'AbortError'
          ? new ToolError('timeout', 'DNS resolver timed out')
          : new ToolError(
              'upstream_error',
              `DNS resolver request failed: ${(err as Error)?.message}`,
            );
      continue;
    }
    if (res.ok) {
      return decodeMessage(new Uint8Array(await res.arrayBuffer()));
    }
    lastErr = new ToolError('upstream_error', `DNS resolver returned HTTP ${res.status}`);
  }
  throw lastErr ?? new ToolError('upstream_error', 'DNS resolver unavailable');
}
