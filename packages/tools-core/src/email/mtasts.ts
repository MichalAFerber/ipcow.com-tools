import { type DohOptions, dohQuery } from '../dns/doh';
import { normalizeHostname } from '../dns/records';
import { RECORD_TYPES } from '../dns/wire';

export interface MtaStsPolicy {
  version: string;
  mode: string; // enforce | testing | none
  mx: string[];
  maxAge: number | null;
}

export interface MtaStsResult {
  domain: string;
  /** A published _mta-sts id AND a fetchable, valid policy. */
  configured: boolean;
  stsId: string | null;
  policy: MtaStsPolicy | null;
  /** Raw TLS-RPT (_smtp._tls) record, if any. */
  tlsRpt: string | null;
}

/** Pull the `id=` out of a `v=STSv1; id=…` TXT record. */
export function parseStsId(txts: string[]): string | null {
  for (const t of txts) {
    if (!/v=STSv1/i.test(t)) continue;
    const id = t.match(/id=([^;]+)/i)?.[1];
    if (id) return id.trim();
  }
  return null;
}

/** Parse an mta-sts.txt policy file (key: value lines; `mx` may repeat). */
export function parseMtaStsPolicy(body: string): MtaStsPolicy | null {
  const lines = body
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);
  const valuesOf = (k: string) =>
    lines
      .filter((l) => l.toLowerCase().startsWith(`${k}:`))
      .map((l) => l.slice(k.length + 1).trim());

  const version = valuesOf('version')[0] ?? '';
  if (!/STSv1/i.test(version)) return null;
  const maxAgeRaw = valuesOf('max_age')[0];
  return {
    version,
    mode: valuesOf('mode')[0] ?? '',
    mx: valuesOf('mx'),
    maxAge: maxAgeRaw && /^\d+$/.test(maxAgeRaw) ? Number(maxAgeRaw) : null,
  };
}

/** Return the TLS-RPT record string, if present. */
export function parseTlsRpt(txts: string[]): string | null {
  return txts.find((t) => /v=TLSRPTv1/i.test(t)) ?? null;
}

async function fetchPolicy(host: string, timeoutMs: number): Promise<string | null> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(`https://mta-sts.${host}/.well-known/mta-sts.txt`, {
      signal: ctrl.signal,
      headers: { 'user-agent': 'ipcow-mta-sts/1.0 (+https://ipcow.com)' },
    });
    if (!res.ok) return null;
    return (await res.text()).slice(0, 4096);
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

const txtStrings = (msg: Awaited<ReturnType<typeof dohQuery>> | null): string[] =>
  msg ? msg.answers.filter((a) => a.type === RECORD_TYPES.TXT).map((a) => a.data as string) : [];

/** Check a domain's SMTP TLS posture: the MTA-STS policy and the TLS-RPT reporting record. */
export async function checkMtaSts(
  domain: string,
  opts?: DohOptions & { timeoutMs?: number },
): Promise<MtaStsResult> {
  const host = normalizeHostname(domain);
  const [stsMsg, tlsRptMsg, policyBody] = await Promise.all([
    dohQuery(`_mta-sts.${host}`, 'TXT', opts).catch(() => null),
    dohQuery(`_smtp._tls.${host}`, 'TXT', opts).catch(() => null),
    fetchPolicy(host, opts?.timeoutMs ?? 6000),
  ]);

  const stsId = parseStsId(txtStrings(stsMsg));
  const policy = policyBody ? parseMtaStsPolicy(policyBody) : null;
  return {
    domain: host,
    configured: stsId !== null && policy !== null,
    stsId,
    policy,
    tlsRpt: parseTlsRpt(txtStrings(tlsRptMsg)),
  };
}
