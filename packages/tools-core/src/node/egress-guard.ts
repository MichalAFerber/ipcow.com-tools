// Node-only (kept out of the package index so it never enters a Workers bundle). SSRF egress guard:
// confirm a user-supplied target resolves only to public (global) addresses before connecting out,
// so it can't reach loopback, RFC1918, link-local, CGNAT, or cloud metadata (169.254.169.254).
// Returns a validated IP to connect to — pin it to defeat DNS rebinding.
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';

/** True only for globally-routable unicast addresses (rejects private/loopback/link-local/etc.). */
export function isPublicIp(ip: string): boolean {
  const a = ip.split('%')[0];
  const kind = isIP(a);
  if (kind === 4) {
    const p = a.split('.').map(Number);
    if (p[0] === 0 || p[0] === 10 || p[0] === 127) return false;
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return false;
    if (p[0] === 192 && p[1] === 168) return false;
    if (p[0] === 169 && p[1] === 254) return false; // link-local incl. 169.254.169.254 metadata
    if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return false; // CGNAT
    if (p[0] >= 224) return false; // multicast / reserved
    return true;
  }
  if (kind === 6) {
    const l = a.toLowerCase();
    if (l === '::1' || l === '::') return false;
    if (l.startsWith('fe80') || l.startsWith('fec0')) return false; // link/site-local
    if (l.startsWith('fc') || l.startsWith('fd')) return false; // unique-local
    if (l.startsWith('ff')) return false; // multicast
    const m = l.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/); // v4-mapped → validate the embedded v4
    if (m) return isPublicIp(m[1]);
    return true;
  }
  return false;
}

/**
 * Resolve `host` and return a public address to connect to (pinned), or null if the host is a
 * non-public target or won't resolve. If ANY resolved record is non-public, the whole host is
 * rejected (defeats a split-horizon / rebinding answer).
 */
export async function resolvePublicAddress(
  host: string,
): Promise<{ address: string; family: number } | null> {
  if (isIP(host)) return isPublicIp(host) ? { address: host, family: isIP(host) } : null;
  let addrs;
  try {
    addrs = await lookup(host, { all: true });
  } catch {
    return null;
  }
  if (!addrs.length || addrs.some((a) => !isPublicIp(a.address))) return null;
  return { address: addrs[0].address, family: addrs[0].family };
}

/**
 * Throw if `url`'s host doesn't resolve to a public address. Injected into outbound tools (e.g. the
 * http-headers checker) as an `assertAllowed` hook so a user can't point them at internal services /
 * cloud metadata.
 */
export async function assertUrlPublic(url: string): Promise<void> {
  let host: string;
  try {
    host = new URL(url).hostname.replace(/^\[|\]$/g, ''); // strip IPv6 brackets
  } catch {
    throw new Error('invalid URL');
  }
  if (!(await resolvePublicAddress(host))) {
    throw new Error('This URL points to a non-public address and can’t be fetched.');
  }
}
