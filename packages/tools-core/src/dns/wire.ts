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
  LOC: 29,
  SRV: 33,
  CERT: 37,
  DS: 43,
  IPSECKEY: 45,
  RRSIG: 46,
  NSEC: 47,
  DNSKEY: 48,
  NSEC3PARAM: 51,
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
export interface DsData {
  keyTag: number;
  algorithm: number;
  digestType: number;
  digest: string;
}
export interface DnskeyData {
  flags: number;
  protocol: number;
  algorithm: number;
  keyTag: number;
  /** Secure Entry Point (key-signing key) when set. */
  sep: boolean;
}
export interface LocData {
  /** Human-readable "D M S.sss H" (e.g. "37 23 30.900 N"). */
  latitude: string;
  longitude: string;
  altitudeM: number;
  sizeM: number;
  horizPreM: number;
  vertPreM: number;
}
export interface CertData {
  certType: number;
  certTypeName: string;
  keyTag: number;
  algorithm: number;
  /** base64 certificate/CRL blob. */
  certificate: string;
}
export interface IpseckeyData {
  precedence: number;
  gatewayType: number;
  algorithm: number;
  /** "." (none), an IPv4/IPv6 address, or a domain name, per gatewayType. */
  gateway: string;
  /** base64 public key. */
  publicKey: string;
}
export interface RrsigData {
  typeCovered: string;
  algorithm: number;
  labels: number;
  originalTtl: number;
  /** ISO 8601 from the signature's expiration epoch. */
  expiration: string;
  inception: string;
  keyTag: number;
  signerName: string;
  /** base64 signature. */
  signature: string;
}
export interface NsecData {
  nextDomainName: string;
  types: string[];
}
export interface Nsec3ParamData {
  hashAlgorithm: number;
  flags: number;
  iterations: number;
  /** hex salt, or "-" when empty. */
  salt: string;
}

export type RecordData =
  | string
  | SoaData
  | MxData
  | SrvData
  | CaaData
  | DsData
  | DnskeyData
  | LocData
  | CertData
  | IpseckeyData
  | RrsigData
  | NsecData
  | Nsec3ParamData;

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
  /** Authenticated Data — the validating resolver verified the DNSSEC chain. */
  ad: boolean;
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

/** Build a wireformat query for a single question with RD (recursion desired) set. When
 *  `dnssecOk` is set, an EDNS0 OPT record carrying the DO bit is appended so a validating
 *  resolver returns the Authenticated Data flag. */
export function encodeQuery(name: string, type: RecordType, id = 0, dnssecOk = false): Uint8Array {
  const arcount = dnssecOk ? 1 : 0;
  const header = [(id >> 8) & 0xff, id & 0xff, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, arcount];
  const qtype = RECORD_TYPES[type];
  const question = [...encodeName(name), (qtype >> 8) & 0xff, qtype & 0xff, 0x00, 0x01];
  // EDNS0 OPT: name=root, type=OPT(41), UDP size=4096, TTL flags=DO(0x8000), rdlength=0.
  const opt = dnssecOk ? [0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00] : [];
  return new Uint8Array([...header, ...question, ...opt]);
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

/** RFC 4034 Appendix B key tag (the modern sum method; covers all current algorithms). */
function dnskeyKeyTag(dv: DataView, offset: number, rdlength: number): number {
  let ac = 0;
  for (let i = 0; i < rdlength; i++) {
    const b = dv.getUint8(offset + i);
    ac += (i & 1) === 0 ? b << 8 : b;
  }
  ac += (ac >> 16) & 0xffff;
  return ac & 0xffff;
}

function hex(buf: Uint8Array, start: number, end: number): string {
  return Array.from(buf.subarray(start, end))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Standard base64 (with padding) of a byte slice — for opaque RDATA (certs, signatures, keys). */
function base64(buf: Uint8Array, start: number, end: number): string {
  let bin = '';
  for (const b of buf.subarray(start, end)) bin += String.fromCharCode(b);
  return btoa(bin);
}

const CERT_TYPES: Record<number, string> = {
  1: 'PKIX',
  2: 'SPKI',
  3: 'PGP',
  4: 'IPKIX',
  5: 'ISPKI',
  6: 'IPGP',
  7: 'ACPKIX',
  8: 'IACPKIX',
  253: 'URI',
  254: 'OID',
};

/** RFC 1876 size/precision octet: high nibble mantissa, low nibble base-10 exponent; cm -> m. */
function decodeLocSize(b: number): number {
  return (((b >> 4) & 0x0f) * Math.pow(10, b & 0x0f)) / 100;
}

/** RFC 1876 lat/long: thousandths of an arc-second, biased by 2^31 -> "D M S.sss H". */
function decodeLocCoord(raw: number, posChar: string, negChar: string): string {
  let v = raw - 0x80000000;
  const hemi = v >= 0 ? posChar : negChar;
  v = Math.abs(v);
  const totalSec = v / 1000;
  const deg = Math.floor(totalSec / 3600);
  const min = Math.floor((totalSec % 3600) / 60);
  const sec = totalSec % 60;
  return `${deg} ${min} ${sec.toFixed(3)} ${hemi}`;
}

/** RFC 4034 type bit maps (window block, length, bitmap)+ -> list of RR type names. */
function decodeTypeBitmap(dv: DataView, offset: number, end: number): string[] {
  const types: string[] = [];
  let pos = offset;
  while (pos + 2 <= end) {
    const window = dv.getUint8(pos);
    const len = dv.getUint8(pos + 1);
    pos += 2;
    for (let i = 0; i < len; i++) {
      const octet = dv.getUint8(pos + i);
      for (let bit = 0; bit < 8; bit++) {
        if (octet & (0x80 >> bit)) {
          const t = window * 256 + i * 8 + bit;
          types.push(TYPE_BY_NUM[t] ?? `TYPE${t}`);
        }
      }
    }
    pos += len;
  }
  return types;
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
    case RECORD_TYPES.DS:
      return {
        keyTag: dv.getUint16(offset),
        algorithm: dv.getUint8(offset + 2),
        digestType: dv.getUint8(offset + 3),
        digest: hex(buf, offset + 4, offset + rdlength),
      };
    case RECORD_TYPES.DNSKEY: {
      const flags = dv.getUint16(offset);
      return {
        flags,
        protocol: dv.getUint8(offset + 2),
        algorithm: dv.getUint8(offset + 3),
        keyTag: dnskeyKeyTag(dv, offset, rdlength),
        sep: (flags & 0x0001) !== 0,
      };
    }
    case RECORD_TYPES.LOC:
      return {
        latitude: decodeLocCoord(dv.getUint32(offset + 4), 'N', 'S'),
        longitude: decodeLocCoord(dv.getUint32(offset + 8), 'E', 'W'),
        altitudeM: (dv.getUint32(offset + 12) - 10000000) / 100,
        sizeM: decodeLocSize(dv.getUint8(offset + 1)),
        horizPreM: decodeLocSize(dv.getUint8(offset + 2)),
        vertPreM: decodeLocSize(dv.getUint8(offset + 3)),
      };
    case RECORD_TYPES.CERT: {
      const certType = dv.getUint16(offset);
      return {
        certType,
        certTypeName: CERT_TYPES[certType] ?? `TYPE${certType}`,
        keyTag: dv.getUint16(offset + 2),
        algorithm: dv.getUint8(offset + 4),
        certificate: base64(buf, offset + 5, offset + rdlength),
      };
    }
    case RECORD_TYPES.IPSECKEY: {
      const gatewayType = dv.getUint8(offset + 1);
      let p = offset + 3;
      let gateway = '.';
      if (gatewayType === 1) {
        gateway = `${dv.getUint8(p)}.${dv.getUint8(p + 1)}.${dv.getUint8(p + 2)}.${dv.getUint8(p + 3)}`;
        p += 4;
      } else if (gatewayType === 2) {
        let n = 0n;
        for (let i = 0; i < 16; i++) n = (n << 8n) | BigInt(dv.getUint8(p + i));
        gateway = formatIPv6(n);
        p += 16;
      } else if (gatewayType === 3) {
        const [name, next] = readName(buf, dv, p);
        gateway = name;
        p = next;
      }
      return {
        precedence: dv.getUint8(offset),
        gatewayType,
        algorithm: dv.getUint8(offset + 2),
        gateway,
        publicKey: base64(buf, p, offset + rdlength),
      };
    }
    case RECORD_TYPES.RRSIG: {
      const typeCovered = dv.getUint16(offset);
      const [signerName, afterName] = readName(buf, dv, offset + 18);
      return {
        typeCovered: TYPE_BY_NUM[typeCovered] ?? `TYPE${typeCovered}`,
        algorithm: dv.getUint8(offset + 2),
        labels: dv.getUint8(offset + 3),
        originalTtl: dv.getUint32(offset + 4),
        expiration: new Date(dv.getUint32(offset + 8) * 1000).toISOString(),
        inception: new Date(dv.getUint32(offset + 12) * 1000).toISOString(),
        keyTag: dv.getUint16(offset + 16),
        signerName,
        signature: base64(buf, afterName, offset + rdlength),
      };
    }
    case RECORD_TYPES.NSEC: {
      const [nextDomainName, afterName] = readName(buf, dv, offset);
      return { nextDomainName, types: decodeTypeBitmap(dv, afterName, offset + rdlength) };
    }
    case RECORD_TYPES.NSEC3PARAM: {
      const saltLength = dv.getUint8(offset + 4);
      return {
        hashAlgorithm: dv.getUint8(offset),
        flags: dv.getUint8(offset + 1),
        iterations: dv.getUint16(offset + 2),
        salt: saltLength === 0 ? '-' : hex(buf, offset + 5, offset + 5 + saltLength),
      };
    }
    default:
      // Unknown type: hex dump of the rdata.
      return hex(buf, offset, offset + rdlength);
  }
}

/** Decode a wireformat DNS response message. */
export function decodeMessage(buf: Uint8Array): DnsMessage {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const flags = dv.getUint16(2);
  const rcode = flags & 0x0f;
  const ad = (flags & 0x0020) !== 0;
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

  return { rcode, rcodeName: RCODE_NAMES[rcode] ?? `RCODE${rcode}`, ad, answers };
}
