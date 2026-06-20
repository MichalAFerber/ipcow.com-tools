import { ToolError } from '../errors';
import {
  type IpVersion,
  bitWidth,
  formatIPv4,
  formatIp,
  maxValue,
  parseIp,
} from './address';

export interface CidrInfo {
  version: IpVersion;
  cidr: string;
  prefix: number;
  networkAddress: string;
  firstAddress: string;
  lastAddress: string;
  totalAddresses: string;
  usableHosts: string;
  firstHost?: string;
  lastHost?: string;
  /** IPv4 only */
  broadcastAddress?: string;
  netmask?: string;
  wildcardMask?: string;
}

/** Contiguous network mask for a prefix length, as a bigint. */
export function maskFor(version: IpVersion, prefix: number): bigint {
  const bits = bitWidth(version);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > bits) {
    throw new ToolError('invalid_input', `prefix /${prefix} out of range for IPv${version}`);
  }
  if (prefix === 0) return 0n;
  const full = maxValue(version);
  return (full << BigInt(bits - prefix)) & full;
}

export function parseCidr(input: string): { version: IpVersion; value: bigint; prefix: number } {
  const s = input.trim();
  const slash = s.indexOf('/');
  if (slash < 0) {
    throw new ToolError('invalid_input', 'expected CIDR, e.g. 192.0.2.0/24 or 2001:db8::/32');
  }
  const ipPart = s.slice(0, slash);
  const prefixPart = s.slice(slash + 1);
  const ip = parseIp(ipPart);
  if (!ip) throw new ToolError('invalid_input', `invalid IP address: ${ipPart}`);
  if (!/^\d{1,3}$/.test(prefixPart)) {
    throw new ToolError('invalid_input', `invalid prefix length: ${prefixPart}`);
  }
  const prefix = Number(prefixPart);
  if (prefix > bitWidth(ip.version)) {
    throw new ToolError('invalid_input', `prefix /${prefix} out of range for IPv${ip.version}`);
  }
  return { version: ip.version, value: ip.value, prefix };
}

/** Full breakdown of a CIDR block for the subnet calculator. */
export function describeCidr(input: string): CidrInfo {
  const { version, value, prefix } = parseCidr(input);
  const bits = bitWidth(version);
  const mask = maskFor(version, prefix);
  const network = value & mask;
  const last = network | (maxValue(version) ^ mask);
  const total = 1n << BigInt(bits - prefix);

  const info: CidrInfo = {
    version,
    prefix,
    cidr: `${formatIp(version, network)}/${prefix}`,
    networkAddress: formatIp(version, network),
    firstAddress: formatIp(version, network),
    lastAddress: formatIp(version, last),
    totalAddresses: total.toString(),
    usableHosts: total.toString(),
  };

  if (version === 4) {
    info.netmask = formatIPv4(mask);
    info.wildcardMask = formatIPv4(maxValue(4) ^ mask);
    info.broadcastAddress = formatIp(4, last);
    if (prefix < 31) {
      info.firstHost = formatIp(4, network + 1n);
      info.lastHost = formatIp(4, last - 1n);
      info.usableHosts = (total - 2n).toString();
    } else if (prefix === 31) {
      // RFC 3021 point-to-point link: both addresses usable.
      info.firstHost = formatIp(4, network);
      info.lastHost = formatIp(4, last);
      info.usableHosts = '2';
    } else {
      info.firstHost = formatIp(4, network);
      info.lastHost = formatIp(4, network);
      info.usableHosts = '1';
    }
  } else {
    info.firstHost = formatIp(6, network);
    info.lastHost = formatIp(6, last);
  }

  return info;
}

export function cidrToRange(input: string): {
  version: IpVersion;
  start: bigint;
  end: bigint;
  startIp: string;
  endIp: string;
} {
  const { version, value, prefix } = parseCidr(input);
  const mask = maskFor(version, prefix);
  const start = value & mask;
  const end = start | (maxValue(version) ^ mask);
  return { version, start, end, startIp: formatIp(version, start), endIp: formatIp(version, end) };
}

function trailingZeros(v: bigint): number {
  let count = 0;
  let n = v;
  while ((n & 1n) === 0n) {
    count++;
    n >>= 1n;
  }
  return count;
}

/** Minimal set of CIDR blocks that exactly covers an inclusive IP range. */
export function rangeToCidrs(startInput: string, endInput: string): string[] {
  const a = parseIp(startInput.trim());
  const b = parseIp(endInput.trim());
  if (!a || !b) throw new ToolError('invalid_input', 'invalid start or end IP address');
  if (a.version !== b.version) {
    throw new ToolError('invalid_input', 'start and end must be the same IP version');
  }
  if (a.value > b.value) throw new ToolError('invalid_input', 'start address must be <= end address');

  const bits = bitWidth(a.version);
  const out: string[] = [];
  let start = a.value;
  const end = b.value;

  while (start <= end) {
    let maxBits = start === 0n ? bits : trailingZeros(start);
    if (maxBits > bits) maxBits = bits;
    while (maxBits > 0 && (1n << BigInt(maxBits)) > end - start + 1n) maxBits--;
    out.push(`${formatIp(a.version, start)}/${bits - maxBits}`);
    start += 1n << BigInt(maxBits);
    if (out.length > 100_000) throw new ToolError('invalid_input', 'range too large to enumerate');
  }
  return out;
}

export interface IpScope {
  scope: string;
  description: string;
  global: boolean;
}

const SPECIAL_V4: ReadonlyArray<readonly [string, string, string]> = [
  ['0.0.0.0/8', 'this-network', 'Current network (RFC 791)'],
  ['10.0.0.0/8', 'private', 'Private-use (RFC 1918)'],
  ['100.64.0.0/10', 'cgnat', 'Carrier-grade NAT (RFC 6598)'],
  ['127.0.0.0/8', 'loopback', 'Loopback (RFC 1122)'],
  ['169.254.0.0/16', 'link-local', 'Link-local (RFC 3927)'],
  ['172.16.0.0/12', 'private', 'Private-use (RFC 1918)'],
  ['192.0.2.0/24', 'documentation', 'Documentation TEST-NET-1 (RFC 5737)'],
  ['192.168.0.0/16', 'private', 'Private-use (RFC 1918)'],
  ['198.18.0.0/15', 'benchmarking', 'Benchmarking (RFC 2544)'],
  ['198.51.100.0/24', 'documentation', 'Documentation TEST-NET-2 (RFC 5737)'],
  ['203.0.113.0/24', 'documentation', 'Documentation TEST-NET-3 (RFC 5737)'],
  ['224.0.0.0/4', 'multicast', 'Multicast (RFC 5771)'],
  ['240.0.0.0/4', 'reserved', 'Reserved (RFC 1112)'],
  ['255.255.255.255/32', 'broadcast', 'Limited broadcast'],
];

const SPECIAL_V6: ReadonlyArray<readonly [string, string, string]> = [
  ['::1/128', 'loopback', 'Loopback (RFC 4291)'],
  ['::/128', 'unspecified', 'Unspecified address (RFC 4291)'],
  ['64:ff9b::/96', 'nat64', 'NAT64 well-known prefix (RFC 6052)'],
  ['100::/64', 'discard', 'Discard-only (RFC 6666)'],
  ['2001:db8::/32', 'documentation', 'Documentation (RFC 3849)'],
  ['fc00::/7', 'unique-local', 'Unique local address (RFC 4193)'],
  ['fe80::/10', 'link-local', 'Link-local unicast (RFC 4291)'],
  ['ff00::/8', 'multicast', 'Multicast (RFC 4291)'],
];

/** Classify an address as private/loopback/documentation/etc., or global unicast. */
export function classifyIp(input: string): IpScope | null {
  const ip = parseIp(input.trim());
  if (!ip) return null;
  const table = ip.version === 4 ? SPECIAL_V4 : SPECIAL_V6;
  for (const [cidr, scope, description] of table) {
    const { start, end } = cidrToRange(cidr);
    if (ip.value >= start && ip.value <= end) {
      return { scope, description, global: false };
    }
  }
  return { scope: 'global-unicast', description: 'Globally routable unicast address', global: true };
}
