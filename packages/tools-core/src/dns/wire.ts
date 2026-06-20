/**
 * Minimal RFC 1035 / RFC 8484 DNS message codec. We encode wireformat queries and decode
 * wireformat responses ourselves so DoH works against ANY RFC-8484 resolver (Quad9 by default)
 * rather than a vendor-specific `application/dns-json` endpoint.
 */

import { formatIPv6 } from '../ip/address';

export const RECORD_TYPES = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  SRV: 33,
  CAA: 257,
} as const;

export type RecordType = keyof typeof RECORD_TYPES;

export const RCODE_NAMES: Record<number, string> = {
  0: 'NOERROR',
  1: 'FORMERR',
  2: 'SERVFAIL',
  3: 'NXDOMAIN',
  4: 'NOTIMP',
  5: 'REFUSED',
};

export interface SoaData {
  mname: string;
  rname: string;
  serial: number;
  refresh: number;
  retry: number;
  expire: number;
  minimum: number;
}
export interface MxData {
  preference: number;
  exchange: string;
}
export interface SrvData {
  priority: number;
  weight: number;
  port: number;
  target: string;
}
export interface CaaData {
  flags: number;
  tag: string;
  value: string;
}

export type RecordData = string | SoaData | MxData | SrvData | CaaData;

export interface ResourceRecord {
  name: string;
  type: number;
  typeName: string;
  ttl: number;
  data: RecordData;
}

export interface DnsMessage {
  rcode: number;
  rcodeName: string;
  answers: ResourceRecord[];
}

const TYPE_BY_NUM: Record<number, string> = Object.fromEntries(
  Object.entries(RECORD_TYPES).map(([k, v]) => [v, k]),
);

function encodeName(name: string): number[] {
  const trimmed = name.replace(/\.$/, '');
  if (trimmed === '') return [0];
  const bytes: number[] = [];
  for (const label of trimmed.split('.')) {
    const enc = new TextEncoder().encode(label);
    if (enc.length === 0 || enc.length > 63) {
      throw new Error(`invalid DNS label: "${label}"`);
    }
    bytes.push(enc.length, ...enc);
  }
  bytes.push(0);
  return bytes;
}

/** Build a wireformat query for a single question with RD (recursion desired) set. */
export function encodeQuery(name: string, type: RecordType, id = 0): Uint8Array {
  const header = [(id >> 8) & 0xff, id & 0xff, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
  const qtype = RECORD_TYPES[type];
  const question = [...encodeName(name), (qtype >> 8) & 0xff, qtype & 0xff, 0x00, 0x01];
  return new Uint8Array([...header, ...question]);
}

/** Read a (possibly compressed) domain name; returns the name and the offset just past it. */
function readName(buf: Uint8Array, dv: DataView, offset: number): [string, number] {
  const labels: string[] = [];
  let pos = offset;
  let next = -1;
  let safety = 0;
  while (true) {
    if (safety++ > 255) throw new Error('DNS name decompression loop');
    const len = dv.getUint8(pos);
    if ((len & 0xc0) === 0xc0) {
      const pointer = ((len & 0x3f) << 8) | dv.getUint8(pos + 1);
      if (next < 0) next = pos + 2;
      pos = pointer;
      continue;
    }
    if (len === 0) {
      if (next < 0) next = pos + 1;
      break;
    }
    pos += 1;
    labels.push(new TextDecoder().decode(buf.subarray(pos, pos + len)));
    pos += len;
  }
  return [labels.join('.'), next];
}

function decodeTxt(buf: Uint8Array, dv: DataView, offset: number, rdlength: number): string {
  let pos = offset;
  const end = offset + rdlength;
  const chunks: string[] = [];
  while (pos < end) {
    const len = dv.getUint8(pos);
    pos += 1;
    chunks.push(new TextDecoder().decode(buf.subarray(pos, pos + len)));
    pos += len;
  }
  return chunks.join('');
}

function decodeRdata(
  buf: Uint8Array,
  dv: DataView,
  type: number,
  offset: number,
  rdlength: number,
): RecordData {
  switch (type) {
    case RECORD_TYPES.A:
      return `${dv.getUint8(offset)}.${dv.getUint8(offset + 1)}.${dv.getUint8(offset + 2)}.${dv.getUint8(offset + 3)}`;
    case RECORD_TYPES.AAAA: {
      let value = 0n;
      for (let i = 0; i < 16; i++) value = (value << 8n) | BigInt(dv.getUint8(offset + i));
      return formatIPv6(value);
    }
    case RECORD_TYPES.NS:
    case RECORD_TYPES.CNAME:
    case RECORD_TYPES.PTR:
      return readName(buf, dv, offset)[0];
    case RECORD_TYPES.TXT:
      return decodeTxt(buf, dv, offset, rdlength);
    case RECORD_TYPES.MX: {
      const preference = dv.getUint16(offset);
      const [exchange] = readName(buf, dv, offset + 2);
      return { preference, exchange };
    }
    case RECORD_TYPES.SOA: {
      const [mname, o1] = readName(buf, dv, offset);
      const [rname, o2] = readName(buf, dv, o1);
      return {
        mname,
        rname,
        serial: dv.getUint32(o2),
        refresh: dv.getUint32(o2 + 4),
        retry: dv.getUint32(o2 + 8),
        expire: dv.getUint32(o2 + 12),
        minimum: dv.getUint32(o2 + 16),
      };
    }
    case RECORD_TYPES.SRV: {
      const priority = dv.getUint16(offset);
      const weight = dv.getUint16(offset + 2);
      const port = dv.getUint16(offset + 4);
      const [target] = readName(buf, dv, offset + 6);
      return { priority, weight, port, target };
    }
    case RECORD_TYPES.CAA: {
      const flags = dv.getUint8(offset);
      const tagLen = dv.getUint8(offset + 1);
      const tag = new TextDecoder().decode(buf.subarray(offset + 2, offset + 2 + tagLen));
      const value = new TextDecoder().decode(buf.subarray(offset + 2 + tagLen, offset + rdlength));
      return { flags, tag, value };
    }
    default:
      // Unknown type: hex dump of the rdata.
      return Array.from(buf.subarray(offset, offset + rdlength))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
  }
}

/** Decode a wireformat DNS response message. */
export function decodeMessage(buf: Uint8Array): DnsMessage {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const flags = dv.getUint16(2);
  const rcode = flags & 0x0f;
  const qdcount = dv.getUint16(4);
  const ancount = dv.getUint16(6);

  let offset = 12;
  for (let i = 0; i < qdcount; i++) {
    const [, next] = readName(buf, dv, offset);
    offset = next + 4; // skip QTYPE + QCLASS
  }

  const answers: ResourceRecord[] = [];
  for (let i = 0; i < ancount; i++) {
    const [name, next] = readName(buf, dv, offset);
    const type = dv.getUint16(next);
    const ttl = dv.getUint32(next + 4);
    const rdlength = dv.getUint16(next + 8);
    const rdataStart = next + 10;
    const data = decodeRdata(buf, dv, type, rdataStart, rdlength);
    answers.push({ name, type, typeName: TYPE_BY_NUM[type] ?? `TYPE${type}`, ttl, data });
    offset = rdataStart + rdlength;
  }

  return { rcode, rcodeName: RCODE_NAMES[rcode] ?? `RCODE${rcode}`, answers };
}
