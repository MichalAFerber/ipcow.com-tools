import { ToolError } from '../errors';
import { formatIPv6, parseIp } from '../ip/address';
import { type DohOptions, dohQuery } from './doh';
import { RECORD_TYPES } from './wire';

// IP-to-ASN over DNS, via Team Cymru's public service — no whois/HTTP API, so it rides the
// same privacy-first DoH path as the rest of ipcow. Two zones:
//   <reversed-ip>.origin.asn.cymru.com  TXT -> "ASN[ ASN…] | BGP prefix | CC | registry | date"
//   AS<n>.asn.cymru.com                 TXT -> "ASN | CC | registry | date | AS name"
// IPv6 uses nibble reversal under origin6.asn.cymru.com.

/** Build the Team Cymru origin query name for an IP. */
export function asnOriginQuery(ip: string): string {
  const parsed = parseIp(ip.trim());
  if (!parsed) throw new ToolError('invalid_input', `invalid IP address: ${ip}`);

  if (parsed.version === 4) {
    const v = parsed.value;
    const a = (v >> 24n) & 0xffn;
    const b = (v >> 16n) & 0xffn;
    const c = (v >> 8n) & 0xffn;
    const d = v & 0xffn;
    return `${d}.${c}.${b}.${a}.origin.asn.cymru.com`;
  }

  const nibbles = formatIPv6(parsed.value, { expand: true })
    .replace(/:/g, '')
    .split('')
    .reverse()
    .join('.');
  return `${nibbles}.origin6.asn.cymru.com`;
}

export interface AsnRecord {
  asn: number;
  name?: string;
  prefix: string;
  country: string;
  registry: string;
  allocated: string;
}

export interface AsnLookupResult {
  ip: string;
  records: AsnRecord[];
}

const unquote = (s: string): string =>
  s
    .trim()
    .replace(/^"(.*)"$/s, '$1')
    .trim();

/** Parse an `origin`/`origin6` TXT answer. The first field may list several origin ASNs. */
export function parseOriginTxt(txt: string): Omit<AsnRecord, 'name'>[] {
  const parts = unquote(txt)
    .split('|')
    .map((p) => p.trim());
  if (parts.length < 5) return [];
  const [asns, prefix, country, registry, allocated] = parts;
  return asns
    .split(/\s+/)
    .filter(Boolean)
    .map((a) => ({ asn: Number(a), prefix, country, registry, allocated }))
    .filter((r) => Number.isInteger(r.asn) && r.asn > 0);
}

/** Parse the AS-name field out of an `AS<n>.asn.cymru.com` TXT answer. */
export function parseAsnNameTxt(txt: string): string {
  const parts = unquote(txt)
    .split('|')
    .map((p) => p.trim());
  return parts.length >= 5 ? parts[4] : '';
}

/** Look up the AS number(s), name and BGP prefix announcing an IP, over Team Cymru DNS. */
export async function lookupAsn(ip: string, opts?: DohOptions): Promise<AsnLookupResult> {
  const trimmed = ip.trim();
  const msg = await dohQuery(asnOriginQuery(trimmed), 'TXT', opts);
  const txts = msg.answers.filter((a) => a.type === RECORD_TYPES.TXT).map((a) => a.data as string);

  // Dedupe by ASN across all origin answers (an IP can be multi-origin).
  const byAsn = new Map<number, Omit<AsnRecord, 'name'>>();
  for (const t of txts)
    for (const r of parseOriginTxt(t)) if (!byAsn.has(r.asn)) byAsn.set(r.asn, r);
  if (byAsn.size === 0) throw new ToolError('not_found', `no AS announces ${trimmed}`);

  // Resolve AS names (best-effort, bounded — origins are a small handful).
  const records = await Promise.all(
    [...byAsn.values()].slice(0, 8).map(async (r): Promise<AsnRecord> => {
      try {
        const nameMsg = await dohQuery(`AS${r.asn}.asn.cymru.com`, 'TXT', opts);
        const nt = nameMsg.answers.find((a) => a.type === RECORD_TYPES.TXT)?.data as
          | string
          | undefined;
        const name = nt ? parseAsnNameTxt(nt) : '';
        return { ...r, name: name || undefined };
      } catch {
        return { ...r };
      }
    }),
  );
  records.sort((a, b) => a.asn - b.asn);
  return { ip: trimmed, records };
}
