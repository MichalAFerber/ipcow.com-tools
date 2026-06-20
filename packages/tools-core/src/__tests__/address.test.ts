import { describe, expect, it } from 'vitest';
import {
  formatIPv4,
  formatIPv6,
  ipVersion,
  normalizeIp,
  parseIPv4,
  parseIPv6,
} from '../ip/address';

describe('IPv4 parsing', () => {
  it('parses dotted quads', () => {
    expect(parseIPv4('0.0.0.0')).toBe(0n);
    expect(parseIPv4('255.255.255.255')).toBe(0xffffffffn);
    expect(parseIPv4('192.168.1.1')).toBe(0xc0a80101n);
  });

  it('rejects malformed input', () => {
    expect(parseIPv4('256.0.0.1')).toBeNull();
    expect(parseIPv4('1.2.3')).toBeNull();
    expect(parseIPv4('1.2.3.4.5')).toBeNull();
    expect(parseIPv4('01.2.3.4')).toBeNull(); // leading zero (octal-ambiguous)
    expect(parseIPv4('1.2.3.x')).toBeNull();
  });

  it('round-trips through formatIPv4', () => {
    expect(formatIPv4(0xc0a80101n)).toBe('192.168.1.1');
  });
});

describe('IPv6 parsing', () => {
  it('handles :: compression', () => {
    expect(parseIPv6('::')).toBe(0n);
    expect(parseIPv6('::1')).toBe(1n);
    expect(parseIPv6('2001:db8::')).toBe(0x20010db8n << 96n);
  });

  it('handles full and embedded-IPv4 forms', () => {
    expect(parseIPv6('2001:0db8:0000:0000:0000:0000:0000:0001')).toBe((0x20010db8n << 96n) | 1n);
    expect(parseIPv6('::ffff:192.168.0.1')).toBe(0xffffn * (1n << 32n) + 0xc0a80001n);
  });

  it('rejects malformed input', () => {
    expect(parseIPv6('2001::db8::1')).toBeNull(); // two "::"
    expect(parseIPv6('gggg::')).toBeNull();
    expect(parseIPv6('1:2:3:4:5:6:7:8:9')).toBeNull();
  });

  it('compresses the longest zero run on format', () => {
    expect(formatIPv6((0x20010db8n << 96n) | 1n)).toBe('2001:db8::1');
    expect(formatIPv6(0n)).toBe('::');
    expect(formatIPv6(1n)).toBe('::1');
    expect(formatIPv6(0n, { expand: true })).toBe('0000:0000:0000:0000:0000:0000:0000:0000');
  });
});

describe('version detection + normalization', () => {
  it('detects the family', () => {
    expect(ipVersion('1.1.1.1')).toBe(4);
    expect(ipVersion('::1')).toBe(6);
    expect(ipVersion('not-an-ip')).toBeNull();
  });

  it('normalizes to canonical form', () => {
    expect(normalizeIp('2001:DB8:0:0:0:0:0:1')?.normalized).toBe('2001:db8::1');
    expect(normalizeIp('192.168.000.1')).toBeNull(); // leading zeros rejected
  });
});
