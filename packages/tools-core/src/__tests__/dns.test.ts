import { describe, expect, it } from 'vitest';
import { asnOriginQuery, parseAsnNameTxt, parseOriginTxt } from '../dns/asn';
import { formatRecordValue, isConsistent } from '../dns/propagation';
import { normalizeHostname } from '../dns/records';
import { reversePointer } from '../dns/reverse';
import { ToolError } from '../errors';

describe('normalizeHostname', () => {
  it('lowercases and strips trailing dots / URLs', () => {
    expect(normalizeHostname('Example.COM.')).toBe('example.com');
    expect(normalizeHostname('https://example.com/path?q=1')).toBe('example.com');
  });

  it('allows underscore labels used by email auth', () => {
    expect(normalizeHostname('_dmarc.example.com')).toBe('_dmarc.example.com');
  });

  it('rejects junk', () => {
    expect(() => normalizeHostname('not a host')).toThrow(ToolError);
    expect(() => normalizeHostname('')).toThrow(ToolError);
  });
});

describe('reversePointer', () => {
  it('builds in-addr.arpa for IPv4', () => {
    expect(reversePointer('8.8.4.4')).toBe('4.4.8.8.in-addr.arpa');
  });

  it('builds nibble-reversed ip6.arpa for IPv6', () => {
    const ptr = reversePointer('2001:db8::1');
    expect(ptr.endsWith('.ip6.arpa')).toBe(true);
    expect(ptr.startsWith('1.0.0.0')).toBe(true);
    // 32 nibbles + "ip6" + "arpa"
    expect(ptr.split('.')).toHaveLength(34);
  });

  it('rejects invalid IPs', () => {
    expect(() => reversePointer('999.1.1.1')).toThrow(ToolError);
  });
});

describe('asnOriginQuery', () => {
  it('reverses IPv4 octets under origin.asn.cymru.com', () => {
    expect(asnOriginQuery('9.9.9.9')).toBe('9.9.9.9.origin.asn.cymru.com');
    expect(asnOriginQuery('8.8.4.4')).toBe('4.4.8.8.origin.asn.cymru.com');
  });

  it('nibble-reverses IPv6 under origin6.asn.cymru.com', () => {
    const q = asnOriginQuery('2001:db8::1');
    expect(q.endsWith('.origin6.asn.cymru.com')).toBe(true);
    expect(q.startsWith('1.0.0.0')).toBe(true);
    // 32 nibbles + origin6 + asn + cymru + com
    expect(q.split('.')).toHaveLength(36);
  });

  it('rejects invalid IPs', () => {
    expect(() => asnOriginQuery('not-an-ip')).toThrow(ToolError);
  });
});

describe('parseOriginTxt', () => {
  it('parses a single-origin answer', () => {
    expect(parseOriginTxt('19281 | 9.9.9.0/24 | US | arin | 2017-09-13')).toEqual([
      {
        asn: 19281,
        prefix: '9.9.9.0/24',
        country: 'US',
        registry: 'arin',
        allocated: '2017-09-13',
      },
    ]);
  });

  it('splits a multi-origin first field into one record per ASN', () => {
    const recs = parseOriginTxt('"64500 64501 | 203.0.113.0/24 | AU | apnic | 2011-01-01"');
    expect(recs.map((r) => r.asn)).toEqual([64500, 64501]);
    expect(recs[0]?.prefix).toBe('203.0.113.0/24');
  });

  it('ignores malformed answers', () => {
    expect(parseOriginTxt('garbage')).toEqual([]);
  });
});

describe('parseAsnNameTxt', () => {
  it('extracts the AS name field', () => {
    expect(parseAsnNameTxt('19281 | US | arin | 2017-09-13 | QUAD9-AS-1 - Quad9, US')).toBe(
      'QUAD9-AS-1 - Quad9, US',
    );
  });
});

describe('isConsistent', () => {
  const entry = (resolver: string, values: string[], error?: string) => ({
    resolver,
    values,
    error,
  });

  it('is true only when every resolver answered with the same set', () => {
    expect(isConsistent([entry('A', ['1.2.3.4']), entry('B', ['1.2.3.4'])])).toBe(true);
  });

  it('treats an errored leg as not consistent even if the others agree', () => {
    expect(
      isConsistent([entry('A', [], 'DNS resolver returned HTTP 505'), entry('B', ['1.2.3.4'])]),
    ).toBe(false);
  });

  it('is false when resolvers disagree, and when there are none', () => {
    expect(isConsistent([entry('A', ['1.2.3.4']), entry('B', ['5.6.7.8'])])).toBe(false);
    expect(isConsistent([])).toBe(false);
  });
});

describe('formatRecordValue', () => {
  it('passes strings through and renders structured records stably', () => {
    expect(formatRecordValue('93.184.216.34')).toBe('93.184.216.34');
    expect(formatRecordValue({ preference: 10, exchange: 'mail.example.com' })).toBe(
      '10 mail.example.com',
    );
    expect(
      formatRecordValue({ flags: 257, protocol: 3, algorithm: 13, keyTag: 2068, sep: true }),
    ).toBe('2068 13 (KSK)');
    expect(formatRecordValue({ keyTag: 12345, algorithm: 13, digestType: 2, digest: 'abcd' })).toBe(
      '12345 13 2',
    );
  });
});
