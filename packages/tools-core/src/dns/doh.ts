import { ToolError } from '../errors';
import { type DnsMessage, type RecordType, decodeMessage, encodeQuery } from './wire';

export interface DohOptions {
  /** RFC 8484 resolver endpoint. Defaults to Quad9. */
  resolver?: string;
  timeoutMs?: number;
}

export const RESOLVERS = {
  /** Quad9 — privacy-first, non-profit, malware-blocking. Our default. */
  quad9: 'https://dns.quad9.net/dns-query',
  /** Cloudflare — fast fallback (we already host here; not Google/Apple/MS). */
  cloudflare: 'https://cloudflare-dns.com/dns-query',
} as const;

export const DEFAULT_RESOLVER = RESOLVERS.quad9;

/** Perform a single DoH query (wireformat POST) and return the decoded message. */
export async function dohQuery(
  name: string,
  type: RecordType,
  opts?: DohOptions,
): Promise<DnsMessage> {
  const body = encodeQuery(name, type);
  const resolver = opts?.resolver ?? DEFAULT_RESOLVER;

  let res: Response;
  try {
    res = await fetch(resolver, {
      method: 'POST',
      headers: {
        'content-type': 'application/dns-message',
        accept: 'application/dns-message',
      },
      body,
      signal: AbortSignal.timeout(opts?.timeoutMs ?? 5000),
    });
  } catch (err) {
    const name = (err as Error)?.name;
    if (name === 'TimeoutError' || name === 'AbortError') {
      throw new ToolError('timeout', 'DNS resolver timed out');
    }
    throw new ToolError('upstream_error', `DNS resolver request failed: ${(err as Error)?.message}`);
  }

  if (!res.ok) {
    throw new ToolError('upstream_error', `DNS resolver returned HTTP ${res.status}`);
  }
  return decodeMessage(new Uint8Array(await res.arrayBuffer()));
}
