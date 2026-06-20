/**
 * IPv4 / IPv6 parsing, formatting and normalization. Everything is done in `bigint`
 * so the same math works for both families.
 */

export type IpVersion = 4 | 6;

const V4_MAX = (1n << 32n) - 1n;
const V6_MAX = (1n << 128n) - 1n;

export function bitWidth(version: IpVersion): 32 | 128 {
  return version === 4 ? 32 : 128;
}

export function maxValue(version: IpVersion): bigint {
  return version === 4 ? V4_MAX : V6_MAX;
}

/** Parse a dotted-quad IPv4 address to its 32-bit value, or `null` if invalid. */
export function parseIPv4(input: string): bigint | null {
  const s = input.trim();
  if (!/^[0-9.]+$/.test(s)) return null;
  const parts = s.split('.');
  if (parts.length !== 4) return null;
  let value = 0n;
  for (const part of parts) {
    if (part.length === 0 || part.length > 3) return null;
    if (part.length > 1 && part.startsWith('0')) return null; // reject octal-ambiguous leading zeros
    const n = Number(part);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    value = (value << 8n) | BigInt(n);
  }
  return value;
}

/** Parse an IPv6 address (incl. `::` compression and embedded IPv4) to its 128-bit value. */
export function parseIPv6(input: string): bigint | null {
  let s = input.trim();
  const zone = s.indexOf('%');
  if (zone >= 0) s = s.slice(0, zone); // drop scope id
  if (s.length === 0) return null;

  const halves = s.split('::');
  if (halves.length > 2) return null;

  const parseGroups = (str: string): number[] | null => {
    if (str === '') return [];
    const parts = str.split(':');
    const groups: number[] = [];
    for (const [i, part] of parts.entries()) {
      if (part.includes('.')) {
        if (i !== parts.length - 1) return null; // embedded IPv4 only in the final position
        const v4 = parseIPv4(part);
        if (v4 === null) return null;
        groups.push(Number((v4 >> 16n) & 0xffffn));
        groups.push(Number(v4 & 0xffffn));
      } else {
        if (!/^[0-9a-fA-F]{1,4}$/.test(part)) return null;
        groups.push(parseInt(part, 16));
      }
    }
    return groups;
  };

  let groups: number[];
  if (halves.length === 2) {
    const left = parseGroups(halves[0] ?? '');
    const right = parseGroups(halves[1] ?? '');
    if (!left || !right) return null;
    const missing = 8 - (left.length + right.length);
    if (missing < 1) return null; // "::" must stand in for at least one zero group
    groups = [...left, ...new Array<number>(missing).fill(0), ...right];
  } else {
    const all = parseGroups(s);
    if (!all) return null;
    groups = all;
  }

  if (groups.length !== 8) return null;
  let value = 0n;
  for (const g of groups) {
    if (g < 0 || g > 0xffff) return null;
    value = (value << 16n) | BigInt(g);
  }
  return value;
}

export function ipVersion(input: string): IpVersion | null {
  if (parseIPv4(input) !== null) return 4;
  if (parseIPv6(input) !== null) return 6;
  return null;
}

export function parseIp(input: string): { version: IpVersion; value: bigint } | null {
  const v4 = parseIPv4(input);
  if (v4 !== null) return { version: 4, value: v4 };
  const v6 = parseIPv6(input);
  if (v6 !== null) return { version: 6, value: v6 };
  return null;
}

export function formatIPv4(value: bigint): string {
  return [(value >> 24n) & 0xffn, (value >> 16n) & 0xffn, (value >> 8n) & 0xffn, value & 0xffn]
    .map((n) => n.toString())
    .join('.');
}

export function formatIPv6(value: bigint, opts?: { expand?: boolean }): string {
  const hextets = Array.from({ length: 8 }, (_, i) =>
    Number((value >> BigInt((7 - i) * 16)) & 0xffffn),
  );
  if (opts?.expand) {
    return hextets.map((h) => h.toString(16).padStart(4, '0')).join(':');
  }
  // Compress the longest run (>= 2) of zero hextets to "::".
  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;
  for (const [i, h] of hextets.entries()) {
    if (h === 0) {
      if (curStart < 0) curStart = i;
      curLen++;
      if (curLen > bestLen) {
        bestLen = curLen;
        bestStart = curStart;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }
  const parts = hextets.map((h) => h.toString(16));
  if (bestLen >= 2) {
    const before = parts.slice(0, bestStart).join(':');
    const after = parts.slice(bestStart + bestLen).join(':');
    return `${before}::${after}`;
  }
  return parts.join(':');
}

export function formatIp(version: IpVersion, value: bigint): string {
  return version === 4 ? formatIPv4(value) : formatIPv6(value);
}

export interface NormalizedIp {
  version: IpVersion;
  value: bigint;
  normalized: string;
  expanded: string;
}

export function normalizeIp(input: string): NormalizedIp | null {
  const parsed = parseIp(input);
  if (!parsed) return null;
  const { version, value } = parsed;
  return {
    version,
    value,
    normalized: formatIp(version, value),
    expanded: version === 6 ? formatIPv6(value, { expand: true }) : formatIPv4(value),
  };
}
