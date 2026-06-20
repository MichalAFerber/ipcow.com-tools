import { type DohOptions } from '../dns/doh';
import { lookupTxt, normalizeHostname } from '../dns/records';

export interface DmarcResult {
  domain: string;
  found: boolean;
  record?: string;
  tags: Record<string, string>;
  policy?: string;
  subdomainPolicy?: string;
  pct?: number;
  rua: string[];
  ruf: string[];
  warnings: string[];
}

function parseTags(record: string): Record<string, string> {
  const tags: Record<string, string> = {};
  for (const part of record.split(';')) {
    const t = part.trim();
    if (!t) continue;
    const eq = t.indexOf('=');
    if (eq < 0) continue;
    tags[t.slice(0, eq).trim().toLowerCase()] = t.slice(eq + 1).trim();
  }
  return tags;
}

/** Pure DMARC analysis given an already-fetched record (or undefined if none). Testable offline. */
export function analyzeDmarc(domain: string, record: string | undefined): DmarcResult {
  const warnings: string[] = [];

  if (!record) {
    return {
      domain,
      found: false,
      tags: {},
      rua: [],
      ruf: [],
      warnings: [`No DMARC record found at _dmarc.${domain}.`],
    };
  }

  const tags = parseTags(record);
  const policy = tags['p'];
  const subdomainPolicy = tags['sp'];
  const pctRaw = tags['pct'];
  const pct = pctRaw !== undefined ? Number(pctRaw) : undefined;
  const split = (v: string | undefined) =>
    (v ?? '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
  const rua = split(tags['rua']);
  const ruf = split(tags['ruf']);

  if (!policy) warnings.push('Missing required "p=" policy tag.');
  if (policy === 'none') {
    warnings.push('Policy is "p=none" — monitoring only; spoofed mail is not rejected or quarantined.');
  }
  if (policy && !['none', 'quarantine', 'reject'].includes(policy)) {
    warnings.push(`Invalid policy value "p=${policy}".`);
  }
  if (rua.length === 0) {
    warnings.push('No "rua=" address — you are not receiving DMARC aggregate reports.');
  }
  if (pct !== undefined && (Number.isNaN(pct) || pct < 0 || pct > 100)) {
    warnings.push(`Invalid "pct=${pctRaw}".`);
  } else if (pct !== undefined && pct < 100) {
    warnings.push(`Only ${pct}% of mail is subject to the policy (pct=${pct}).`);
  }

  return { domain, found: true, record, tags, policy, subdomainPolicy, pct, rua, ruf, warnings };
}

/** Resolve and analyze the DMARC policy at _dmarc.<domain> using live DNS. */
export async function checkDmarc(domainInput: string, opts?: DohOptions): Promise<DmarcResult> {
  const domain = normalizeHostname(domainInput);
  const txts = await lookupTxt(`_dmarc.${domain}`, opts);
  const record = txts.find((t) => /^v=DMARC1(\s|;|$)/i.test(t.trim()));
  return analyzeDmarc(domain, record);
}
