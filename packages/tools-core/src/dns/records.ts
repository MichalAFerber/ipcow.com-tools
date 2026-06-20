import { ToolError } from '../errors';
import { type DohOptions, dohQuery } from './doh';
import { RECORD_TYPES, type RecordType, type ResourceRecord } from './wire';

// Labels may contain underscores (e.g. _dmarc, _domainkey); the overall name must have a dot.
const HOSTNAME_RE =
  /^(?=.{1,253}$)(?!-)[a-z0-9_-]{1,63}(?<!-)(\.(?!-)[a-z0-9_-]{1,63}(?<!-))*$/;

const NON_ASCII_RE = /[^\x00-\x7f]/;

/** Normalize user input to a queryable hostname: trims URLs, lowercases, IDN -> A-label. */
export function normalizeHostname(input: string): string {
  let h = input.trim().toLowerCase().replace(/\.$/, '');
  if (!h) throw new ToolError('invalid_input', 'a hostname or domain is required');

  if (h.includes('/') || h.startsWith('http')) {
    try {
      h = new URL(h.includes('://') ? h : `http://${h}`).hostname;
    } catch {
      /* fall through with raw value */
    }
  }
  if (NON_ASCII_RE.test(h)) {
    try {
      h = new URL(`http://${h}`).hostname; // IDNA toASCII
    } catch {
      /* fall through */
    }
  }

  if (h !== 'localhost' && (!h.includes('.') || !HOSTNAME_RE.test(h))) {
    throw new ToolError('invalid_input', `not a valid hostname: ${input}`);
  }
  return h;
}

export interface LookupResult {
  name: string;
  type: RecordType;
  rcode: number;
  rcodeName: string;
  records: ResourceRecord[];
  /** CNAMEs encountered while resolving (the answer may be an aliased chain). */
  cnames: string[];
}

/** Look up a single record type for a hostname. */
export async function lookup(
  name: string,
  type: RecordType,
  opts?: DohOptions,
): Promise<LookupResult> {
  const host = normalizeHostname(name);
  const msg = await dohQuery(host, type, opts);
  const wanted = RECORD_TYPES[type];
  return {
    name: host,
    type,
    rcode: msg.rcode,
    rcodeName: msg.rcodeName,
    records: msg.answers.filter((a) => a.type === wanted),
    cnames: msg.answers
      .filter((a) => a.type === RECORD_TYPES.CNAME)
      .map((a) => a.data as string),
  };
}

/** Raw TXT strings for an already-constructed name (no normalization). */
export async function lookupTxt(name: string, opts?: DohOptions): Promise<string[]> {
  const msg = await dohQuery(name, 'TXT', opts);
  return msg.answers.filter((a) => a.type === RECORD_TYPES.TXT).map((a) => a.data as string);
}

const ALL_TYPES: RecordType[] = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CAA'];

/** Fetch the common record set for a domain in parallel. */
export async function lookupAll(
  name: string,
  opts?: DohOptions,
): Promise<Record<string, ResourceRecord[]>> {
  const host = normalizeHostname(name);
  const entries = await Promise.all(
    ALL_TYPES.map(async (t) => {
      const msg = await dohQuery(host, t, opts);
      return [t, msg.answers.filter((a) => a.type === RECORD_TYPES[t])] as const;
    }),
  );
  return Object.fromEntries(entries);
}
