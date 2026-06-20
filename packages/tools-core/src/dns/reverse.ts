import { ToolError } from '../errors';
import { formatIPv6, parseIp } from '../ip/address';
import { type DohOptions, dohQuery } from './doh';
import { RECORD_TYPES } from './wire';

/** Build the reverse-DNS pointer name (in-addr.arpa / ip6.arpa) for an IP. */
export function reversePointer(ip: string): string {
  const parsed = parseIp(ip.trim());
  if (!parsed) throw new ToolError('invalid_input', `invalid IP address: ${ip}`);

  if (parsed.version === 4) {
    const v = parsed.value;
    const a = (v >> 24n) & 0xffn;
    const b = (v >> 16n) & 0xffn;
    const c = (v >> 8n) & 0xffn;
    const d = v & 0xffn;
    return `${d}.${c}.${b}.${a}.in-addr.arpa`;
  }

  const nibbles = formatIPv6(parsed.value, { expand: true })
    .replace(/:/g, '')
    .split('')
    .reverse()
    .join('.');
  return `${nibbles}.ip6.arpa`;
}

export interface ReverseDnsResult {
  ip: string;
  pointer: string;
  names: string[];
}

/** Reverse-resolve an IP to its PTR name(s). */
export async function reverseDns(ip: string, opts?: DohOptions): Promise<ReverseDnsResult> {
  const pointer = reversePointer(ip);
  const msg = await dohQuery(pointer, 'PTR', opts);
  return {
    ip: ip.trim(),
    pointer,
    names: msg.answers.filter((a) => a.type === RECORD_TYPES.PTR).map((a) => a.data as string),
  };
}
