import { describe, expect, it } from 'vitest';
import { classifyIp, describeCidr, maskFor, rangeToCidrs } from '../ip/cidr';
import { ToolError } from '../errors';

describe('describeCidr (IPv4)', () => {
  it('breaks down a /24', () => {
    const info = describeCidr('192.168.1.0/24');
    expect(info.networkAddress).toBe('192.168.1.0');
    expect(info.broadcastAddress).toBe('192.168.1.255');
    expect(info.netmask).toBe('255.255.255.0');
    expect(info.wildcardMask).toBe('0.0.0.255');
    expect(info.firstHost).toBe('192.168.1.1');
    expect(info.lastHost).toBe('192.168.1.254');
    expect(info.totalAddresses).toBe('256');
    expect(info.usableHosts).toBe('254');
  });

  it('normalizes a non-network host address', () => {
    expect(describeCidr('192.168.1.137/24').networkAddress).toBe('192.168.1.0');
  });

  it('handles /31 (RFC 3021) and /32', () => {
    expect(describeCidr('10.0.0.0/31').usableHosts).toBe('2');
    expect(describeCidr('10.0.0.5/32').usableHosts).toBe('1');
  });
});

describe('describeCidr (IPv6)', () => {
  it('counts a /32 and finds the last address', () => {
    const info = describeCidr('2001:db8::/32');
    expect(info.networkAddress).toBe('2001:db8::');
    expect(info.lastAddress).toBe('2001:db8:ffff:ffff:ffff:ffff:ffff:ffff');
    expect(info.totalAddresses).toBe((1n << 96n).toString());
  });
});

describe('maskFor', () => {
  it('rejects out-of-range prefixes', () => {
    expect(() => maskFor(4, 33)).toThrow(ToolError);
    expect(() => maskFor(6, 129)).toThrow(ToolError);
  });
});

describe('rangeToCidrs', () => {
  it('produces the minimal covering set', () => {
    expect(rangeToCidrs('192.0.2.0', '192.0.2.130')).toEqual([
      '192.0.2.0/25',
      '192.0.2.128/31',
      '192.0.2.130/32',
    ]);
  });

  it('collapses an aligned block to a single CIDR', () => {
    expect(rangeToCidrs('10.0.0.0', '10.0.0.255')).toEqual(['10.0.0.0/24']);
  });
});

describe('classifyIp', () => {
  it('recognizes special-use ranges', () => {
    expect(classifyIp('10.0.0.1')?.scope).toBe('private');
    expect(classifyIp('127.0.0.1')?.scope).toBe('loopback');
    expect(classifyIp('169.254.1.1')?.scope).toBe('link-local');
    expect(classifyIp('::1')?.scope).toBe('loopback');
    expect(classifyIp('fe80::1')?.scope).toBe('link-local');
  });

  it('treats routable space as global unicast', () => {
    expect(classifyIp('9.9.9.9')?.global).toBe(true);
    expect(classifyIp('2606:4700::1')?.global).toBe(true);
  });
});
