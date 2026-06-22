import { ToolError } from '../errors';
import { type DohOptions, dohQuery } from './doh';
import { normalizeHostname } from './records';
import { RECORD_TYPES, type RecordData, type RecordType, type ResourceRecord } from './wire';

/** Public DoH resolvers we compare against — all privacy-leaning, none from Google/Apple/Microsoft. */
export const PROPAGATION_RESOLVERS = [
  { label: 'Quad9', url: 'https://dns.quad9.net/dns-query' },
  { label: 'Cloudflare', url: 'https://cloudflare-dns.com/dns-query' },
  { label: 'Mullvad', url: 'https://dns.mullvad.net/dns-query' },
  { label: 'AdGuard', url: 'https://dns.adguard-dns.com/dns-query' },
] as const;

export interface PropagationEntry {
  resolver: string;
  values: string[];
  error?: string;
}
export interface PropagationResult {
  query: string;
  type: RecordType;
  consistent: boolean;
  results: PropagationEntry[];
}

/** Render a record's data as a stable string for cross-resolver comparison and display. */
export function formatRecordValue(data: RecordData): string {
  if (typeof data === 'string') return data;
  if ('exchange' in data) return `${data.preference} ${data.exchange}`; // MX
  if ('target' in data) return `${data.priority} ${data.weight} ${data.port} ${data.target}`; // SRV
  if ('mname' in data) return `${data.mname} (serial ${data.serial})`; // SOA
  if ('tag' in data) return `${data.flags} ${data.tag} "${data.value}"`; // CAA
  if ('digestType' in data) return `${data.keyTag} ${data.algorithm} ${data.digestType}`; // DS
  if ('sep' in data) return `${data.keyTag} ${data.algorithm}${data.sep ? ' (KSK)' : ''}`; // DNSKEY
  return JSON.stringify(data);
}

function valuesFor(answers: ResourceRecord[], type: RecordType): string[] {
  return answers
    .filter((a) => a.type === RECORD_TYPES[type])
    .map((a) => formatRecordValue(a.data))
    .sort();
}

/** Query a record across several public resolvers and report whether they agree. */
export async function checkPropagation(
  name: string,
  type: RecordType,
  opts?: DohOptions,
): Promise<PropagationResult> {
  if (!(type in RECORD_TYPES)) {
    throw new ToolError('invalid_input', `unsupported record type: ${type}`);
  }
  const host = normalizeHostname(name);

  const results: PropagationEntry[] = await Promise.all(
    PROPAGATION_RESOLVERS.map(async (r) => {
      try {
        const msg = await dohQuery(host, type, {
          resolver: r.url,
          timeoutMs: opts?.timeoutMs ?? 4000,
        });
        return { resolver: r.label, values: valuesFor(msg.answers, type) };
      } catch (err) {
        return { resolver: r.label, values: [], error: (err as Error)?.message ?? 'lookup failed' };
      }
    }),
  );

  const answered = results.filter((r) => !r.error).map((r) => r.values.join('\n'));
  const consistent = answered.length > 0 && answered.every((v) => v === answered[0]);

  return { query: host, type, consistent, results };
}
