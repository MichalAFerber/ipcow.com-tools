import { type DohOptions, dohQuery } from './doh';
import { normalizeHostname } from './records';
import { type DnskeyData, type DsData, RECORD_TYPES } from './wire';

export type DnssecStatus = 'secure' | 'unsigned' | 'signed-unvalidated';

export interface DnssecResult {
  domain: string;
  status: DnssecStatus;
  /** The validating resolver set the Authenticated Data bit for this zone. */
  validated: boolean;
  dnskeys: DnskeyData[];
  ds: DsData[];
}

/**
 * Check whether a domain is DNSSEC-signed and validating. We read the zone's DNSKEY set and the
 * parent's DS set, and take the Authenticated Data flag from a validating resolver (Quad9 /
 * Cloudflare both validate) as the "did the chain verify" signal. A signed-but-broken (bogus)
 * zone is hidden by the validating resolver (SERVFAIL), so it surfaces here as `unsigned`.
 */
export async function checkDnssec(domain: string, opts?: DohOptions): Promise<DnssecResult> {
  const host = normalizeHostname(domain);
  const [soa, keyMsg, dsMsg] = await Promise.all([
    dohQuery(host, 'SOA', { ...opts, dnssecOk: true }), // DO bit -> AD (validated) flag for the zone
    dohQuery(host, 'DNSKEY', opts),
    dohQuery(host, 'DS', opts),
  ]);

  const dnskeys = keyMsg.answers
    .filter((a) => a.type === RECORD_TYPES.DNSKEY)
    .map((a) => a.data as DnskeyData);
  const ds = dsMsg.answers.filter((a) => a.type === RECORD_TYPES.DS).map((a) => a.data as DsData);
  const validated = soa.ad;

  const status: DnssecStatus =
    dnskeys.length === 0 ? 'unsigned' : validated ? 'secure' : 'signed-unvalidated';

  return { domain: host, status, validated, dnskeys, ds };
}
