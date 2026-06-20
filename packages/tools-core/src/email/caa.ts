import { type DohOptions } from '../dns/doh';
import { lookup, normalizeHostname } from '../dns/records';
import type { CaaData } from '../dns/wire';

export interface CaaEntry {
  flags: number;
  tag: string;
  value: string;
  critical: boolean;
}

export interface CaaResult {
  domain: string;
  found: boolean;
  records: CaaEntry[];
  issuers: string[];
  wildcardIssuers: string[];
  iodef: string[];
  warnings: string[];
}

/** Look up CAA records and interpret which CAs are authorized to issue. */
export async function checkCaa(domainInput: string, opts?: DohOptions): Promise<CaaResult> {
  const domain = normalizeHostname(domainInput);
  const res = await lookup(domain, 'CAA', opts);

  const records: CaaEntry[] = res.records.map((r) => {
    const d = r.data as CaaData;
    return { flags: d.flags, tag: d.tag, value: d.value, critical: (d.flags & 0x80) !== 0 };
  });

  const valuesFor = (tag: string) => records.filter((e) => e.tag === tag).map((e) => e.value);
  const issuers = valuesFor('issue');
  const wildcardIssuers = valuesFor('issuewild');
  const iodef = valuesFor('iodef');

  const warnings: string[] = [];
  if (records.length === 0) {
    warnings.push('No CAA records — any certificate authority may issue for this domain.');
  }
  if (issuers.some((v) => v.trim() === ';')) {
    warnings.push('An "issue \\";\\"" record forbids all certificate issuance.');
  }

  return {
    domain,
    found: records.length > 0,
    records,
    issuers,
    wildcardIssuers,
    iodef,
    warnings,
  };
}
