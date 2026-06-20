import { describe, expect, it } from 'vitest';
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
