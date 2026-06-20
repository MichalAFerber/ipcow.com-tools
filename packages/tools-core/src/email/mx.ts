import { type DohOptions } from '../dns/doh';
import { lookup, normalizeHostname } from '../dns/records';
import type { MxData } from '../dns/wire';

export interface MxRecord {
  preference: number;
  exchange: string;
}

export interface MxResult {
  domain: string;
  found: boolean;
  records: MxRecord[];
  warnings: string[];
}

/** Look up MX records, sorted by preference (lowest = most preferred). */
export async function lookupMx(domainInput: string, opts?: DohOptions): Promise<MxResult> {
  const domain = normalizeHostname(domainInput);
  const res = await lookup(domain, 'MX', opts);

  const records: MxRecord[] = res.records
    .map((r) => r.data as MxData)
    .map((d) => ({ preference: d.preference, exchange: d.exchange.replace(/\.$/, '') }))
    .sort((a, b) => a.preference - b.preference);

  const warnings: string[] = [];
  if (records.length === 0) {
    warnings.push('No MX records — mail falls back to the A/AAAA record (implicit MX), if present.');
  }
  if (records.length === 1 && (records[0]!.exchange === '' || records[0]!.preference === 0)) {
    // RFC 7505 "null MX" is a single MX with preference 0 and an empty exchange (".").
    if (records[0]!.exchange === '') {
      warnings.push('Null MX (RFC 7505) — this domain explicitly does not accept mail.');
    }
  }

  return { domain, found: records.length > 0, records, warnings };
}
