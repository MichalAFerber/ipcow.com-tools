import { describe, expect, it } from 'vitest';
import {
  type CertData,
  type DnskeyData,
  type DsData,
  decodeMessage,
  encodeQuery,
  type LocData,
  type MxData,
  type NsecData,
  type Nsec3ParamData,
  type RrsigData,
} from '../dns/wire';

const hex = (s: string): Uint8Array =>
  new Uint8Array((s.replace(/\s+/g, '').match(/../g) ?? []).map((h) => parseInt(h, 16)));

describe('encodeQuery', () => {
  it('builds a wireformat A query with RD set', () => {
    const q = encodeQuery('example.com', 'A');
    // Header: id=0, flags=0x0100 (RD), qd=1, an/ns/ar=0
    expect(Array.from(q.slice(0, 12))).toEqual([0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    // Question: 7 "example" 3 "com" 0, QTYPE=A(1), QCLASS=IN(1)
    expect(Array.from(q.slice(12))).toEqual([
      7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1,
    ]);
  });

  it('appends an EDNS0 OPT with the DO bit when dnssecOk is set', () => {
    const q = encodeQuery('example.com', 'SOA', 0, true);
    // ARCOUNT (header byte 11) = 1
    expect(Array.from(q.slice(0, 12))).toEqual([0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1]);
    // Trailing OPT RR: root name, type OPT(41), UDP 4096, TTL flags DO(0x8000), rdlen 0
    expect(Array.from(q.slice(-11))).toEqual([0, 0, 41, 16, 0, 0, 0, 128, 0, 0, 0]);
  });
});

describe('decodeMessage', () => {
  // Response for example.com A -> 93.184.216.34, with a compression pointer in the answer name.
  const aResponse = hex(
    '0000 8180 0001 0001 0000 0000' +
      '07 6578616d706c65 03 636f6d 00 0001 0001' +
      'c00c 0001 0001 00000e10 0004 5db8d822',
  );

  it('decodes an A record and follows the RCODE', () => {
    const msg = decodeMessage(aResponse);
    expect(msg.rcode).toBe(0);
    expect(msg.rcodeName).toBe('NOERROR');
    expect(msg.answers).toHaveLength(1);
    expect(msg.answers[0]!.typeName).toBe('A');
    expect(msg.answers[0]!.ttl).toBe(3600);
    expect(msg.answers[0]!.data).toBe('93.184.216.34');
  });

  it('decodes TXT char-strings concatenated', () => {
    const txtResponse = hex(
      '0000 8180 0001 0001 0000 0000' +
        '07 6578616d706c65 03 636f6d 00 0010 0001' +
        'c00c 0010 0001 00000e10 000c 05 68656c6c6f 05 776f726c64',
    );
    expect(decodeMessage(txtResponse).answers[0]!.data).toBe('helloworld');
  });

  it('decodes MX with a compressed exchange name', () => {
    const mxResponse = hex(
      '0000 8180 0001 0001 0000 0000' +
        '07 6578616d706c65 03 636f6d 00 000f 0001' +
        'c00c 000f 0001 00000e10 0009 000a 04 6d61696c c00c',
    );
    const data = decodeMessage(mxResponse).answers[0]!.data as MxData;
    expect(data.preference).toBe(10);
    expect(data.exchange).toBe('mail.example.com');
  });

  it('reads the Authenticated Data (AD) flag', () => {
    // flags 0x81a0 = QR + RD + RA + AD; 0x8180 = no AD.
    const adSet = hex('0000 81a0 0001 0000 0000 0000 07 6578616d706c65 03 636f6d 00 0006 0001');
    const adClear = hex('0000 8180 0001 0000 0000 0000 07 6578616d706c65 03 636f6d 00 0006 0001');
    expect(decodeMessage(adSet).ad).toBe(true);
    expect(decodeMessage(adClear).ad).toBe(false);
  });

  it('decodes a DS record', () => {
    const dsResponse = hex(
      '0000 81a0 0001 0001 0000 0000' +
        '07 6578616d706c65 03 636f6d 00 002b 0001' +
        'c00c 002b 0001 00000e10 000c 3039 0d 02 abcdef0123456789',
    );
    const data = decodeMessage(dsResponse).answers[0]!.data as DsData;
    expect(data).toEqual({
      keyTag: 12345,
      algorithm: 13,
      digestType: 2,
      digest: 'abcdef0123456789',
    });
  });

  it('decodes a DNSKEY record and computes the key tag', () => {
    // rdata 0101 03 0d 01020304: flags=257 (KSK), protocol=3, algo=13; key tag = 2068 (RFC 4034 B).
    const keyResponse = hex(
      '0000 81a0 0001 0001 0000 0000' +
        '07 6578616d706c65 03 636f6d 00 0030 0001' +
        'c00c 0030 0001 00000e10 0008 0101 03 0d 01020304',
    );
    const data = decodeMessage(keyResponse).answers[0]!.data as DnskeyData;
    expect(data).toEqual({ flags: 257, protocol: 3, algorithm: 13, keyTag: 2068, sep: true });
  });

  it('decodes a LOC record (equator/prime-meridian, 0 m)', () => {
    // version=0, size/horiz/vert=0, lat=2^31, lon=2^31, alt=10000000 (the 0 m base).
    const loc = hex(
      '0000 81a0 0001 0001 0000 0000' +
        '07 6578616d706c65 03 636f6d 00 001d 0001' +
        'c00c 001d 0001 00000e10 0010 00 00 00 00 80000000 80000000 00989680',
    );
    const data = decodeMessage(loc).answers[0]!.data as LocData;
    expect(data).toEqual({
      latitude: '0 0 0.000 N',
      longitude: '0 0 0.000 E',
      altitudeM: 0,
      sizeM: 0,
      horizPreM: 0,
      vertPreM: 0,
    });
  });

  it('decodes a CERT record', () => {
    // certType=1 (PKIX), keyTag=12345, algo=13, cert bytes 01020304 -> base64 AQIDBA==
    const cert = hex(
      '0000 81a0 0001 0001 0000 0000' +
        '07 6578616d706c65 03 636f6d 00 0025 0001' +
        'c00c 0025 0001 00000e10 0009 0001 3039 0d 01020304',
    );
    expect(decodeMessage(cert).answers[0]!.data as CertData).toEqual({
      certType: 1,
      certTypeName: 'PKIX',
      keyTag: 12345,
      algorithm: 13,
      certificate: 'AQIDBA==',
    });
  });

  it('decodes an NSEC3PARAM record', () => {
    // hashAlgo=1, flags=0, iterations=10, salt=aabbccdd
    const np = hex(
      '0000 81a0 0001 0001 0000 0000' +
        '07 6578616d706c65 03 636f6d 00 0033 0001' +
        'c00c 0033 0001 00000e10 0009 01 00 000a 04 aabbccdd',
    );
    expect(decodeMessage(np).answers[0]!.data as Nsec3ParamData).toEqual({
      hashAlgorithm: 1,
      flags: 0,
      iterations: 10,
      salt: 'aabbccdd',
    });
  });

  it('decodes an NSEC record (next name + type bitmap)', () => {
    // next "example.com" (uncompressed) + window 0 bitmap covering A(1) and TXT(16).
    const nsec = hex(
      '0000 81a0 0001 0001 0000 0000' +
        '07 6578616d706c65 03 636f6d 00 002f 0001' +
        'c00c 002f 0001 00000e10 0012' +
        '07 6578616d706c65 03 636f6d 00 00 03 40 00 80',
    );
    const data = decodeMessage(nsec).answers[0]!.data as NsecData;
    expect(data.nextDomainName).toBe('example.com');
    expect(data.types).toEqual(['A', 'TXT']);
  });

  it('decodes an RRSIG record', () => {
    // typeCovered=A, algo=13, labels=2, ttl=3600, exp=0x6553f100, inc=0x6544ab40,
    // keyTag=12345, signer "example.com", signature 01020304 -> AQIDBA==
    const rrsig = hex(
      '0000 81a0 0001 0001 0000 0000' +
        '07 6578616d706c65 03 636f6d 00 002e 0001' +
        'c00c 002e 0001 00000e10 0023' +
        '0001 0d 02 00000e10 6553f100 6544ab40 3039' +
        '07 6578616d706c65 03 636f6d 00 01020304',
    );
    const data = decodeMessage(rrsig).answers[0]!.data as RrsigData;
    expect(data.typeCovered).toBe('A');
    expect(data.algorithm).toBe(13);
    expect(data.labels).toBe(2);
    expect(data.keyTag).toBe(12345);
    expect(data.signerName).toBe('example.com');
    expect(data.signature).toBe('AQIDBA==');
    expect(data.expiration).toBe(new Date(0x6553f100 * 1000).toISOString());
    expect(data.inception).toBe(new Date(0x6544ab40 * 1000).toISOString());
  });
});
