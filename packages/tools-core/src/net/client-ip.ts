// Portable (Node + Workers). Resolve the caller's real public IP from proxy headers. Kept public
// so the IP-trust logic (which drives rate limiting) is reviewable. IMPORTANT: cf-connecting-ip is
// only authoritative when the request genuinely came through Cloudflare — on a direct-to-origin
// (grey-cloud) deployment the edge/proxy MUST strip it, or it is client-forgeable.

/** First hop of a comma-separated X-Forwarded-For header, or null. */
export function firstForwarded(xff: string | null | undefined): string | null {
  return xff?.split(',')[0]?.trim() || null;
}

function present(v: string | null | undefined): string | null {
  return (v && v.trim()) || null;
}

/**
 * Resolve the caller's public IP across the deployment shapes IP Cow runs in:
 *
 *  1. `cf-connecting-ip` — behind Cloudflare (orange). Authoritative only when CF actually fronts
 *     the request; the origin must strip it otherwise (see the module note).
 *  2. `x-forwarded-for`  — behind Caddy / any reverse proxy (the Hetzner origin, staging), where
 *     the Node socket peer is loopback. Take the first (client) hop.
 *  3. `clientAddress`    — last resort for a direct, unproxied connection.
 */
export function resolveClientIp(
  header: (name: string) => string | null,
  clientAddress?: string | null,
): string {
  return (
    present(header('cf-connecting-ip')) ??
    firstForwarded(header('x-forwarded-for')) ??
    present(clientAddress) ??
    ''
  );
}
