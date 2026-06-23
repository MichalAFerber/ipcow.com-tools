import { type DnssecResult, checkDnssec } from './dnssec';
import { lookupAll, normalizeHostname } from './records';
import type { ResourceRecord } from './wire';

export interface DnsCheckResult {
  domain: string;
  warnings: string[];
  /** The common record set (A, AAAA, MX, NS, TXT, SOA, CAA), each as found. */
  records: Record<string, ResourceRecord[]>;
  dnssec: Pick<DnssecResult, 'status' | 'validated'>;
}

/** A one-shot DNS overview: the common record set plus DNSSEC status, with obvious gaps flagged. */
export async function checkDns(domainInput: string): Promise<DnsCheckResult> {
  const domain = normalizeHostname(domainInput);
  const [records, dnssec] = await Promise.all([lookupAll(domain), checkDnssec(domain)]);

  const warnings: string[] = [];
  const has = (t: string) => (records[t]?.length ?? 0) > 0;
  if (!has('A') && !has('AAAA')) warnings.push('No A or AAAA address records.');
  if (!has('NS')) warnings.push('No NS records — delegation looks broken.');
  if (!has('SOA')) warnings.push('No SOA record.');
  if (dnssec.status === 'unsigned') warnings.push('Zone is not DNSSEC-signed.');

  return {
    domain,
    warnings,
    records,
    dnssec: { status: dnssec.status, validated: dnssec.validated },
  };
}
