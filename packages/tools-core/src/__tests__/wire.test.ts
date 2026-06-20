import { describe, expect, it } from 'vitest';
import { decodeMessage, encodeQuery, type MxData } from '../dns/wire';

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
});
