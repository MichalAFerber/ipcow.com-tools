import { describe, expect, it } from 'vitest';
import { analyzeSpf, type TxtResolver } from '../email/spf';
import { analyzeDmarc } from '../email/dmarc';
import { analyzeDkim } from '../email/dkim';
import { ToolError } from '../errors';

/** Build a fake TXT resolver from a fixed map of name -> TXT strings. */
const fakeResolver =
  (map: Record<string, string[]>): TxtResolver =>
  async (name: string) =>
    map[name] ?? [];

describe('analyzeSpf', () => {
  it('counts DNS lookups recursively through includes', async () => {
    const res = await analyzeSpf(
      'example.com',
      fakeResolver({
        'example.com': ['v=spf1 include:one.test include:two.test -all'],
        'one.test': ['v=spf1 a mx -all'], // a + mx = 2 lookups
        'two.test': ['v=spf1 ip4:1.1.1.1 -all'], // 0 lookups
      }),
    );
    // include one (1) + a (1) + mx (1) + include two (1) = 4
    expect(res.found).toBe(true);
    expect(res.allQualifier).toBe('-all');
    expect(res.totalLookups).toBe(4);
    expect(res.withinLimit).toBe(true);
  });

  it('flags exceeding the 10-lookup limit', async () => {
    const includes = Array.from({ length: 11 }, (_, i) => `include:d${i}.test`).join(' ');
    const map: Record<string, string[]> = { 'example.com': [`v=spf1 ${includes} -all`] };
    const res = await analyzeSpf('example.com', fakeResolver(map));
    expect(res.withinLimit).toBe(false);
    expect(res.warnings.some((w) => w.includes('exceeds'))).toBe(true);
  });

  it('reports a missing record', async () => {
    const res = await analyzeSpf('example.com', fakeResolver({}));
    expect(res.found).toBe(false);
  });

  it('warns on +all', async () => {
    const res = await analyzeSpf(
      'example.com',
      fakeResolver({ 'example.com': ['v=spf1 +all'] }),
    );
    expect(res.warnings.some((w) => w.includes('+all'))).toBe(true);
  });
});

describe('analyzeDmarc', () => {
  it('parses an enforcing policy with reporting', () => {
    const res = analyzeDmarc('example.com', 'v=DMARC1; p=reject; rua=mailto:d@example.com; pct=100');
    expect(res.policy).toBe('reject');
    expect(res.rua).toEqual(['mailto:d@example.com']);
    expect(res.warnings).toHaveLength(0);
  });

  it('warns on p=none and missing reporting', () => {
    const res = analyzeDmarc('example.com', 'v=DMARC1; p=none');
    expect(res.warnings.some((w) => w.includes('p=none'))).toBe(true);
    expect(res.warnings.some((w) => w.includes('rua'))).toBe(true);
  });

  it('reports a missing record', () => {
    expect(analyzeDmarc('example.com', undefined).found).toBe(false);
  });
});

describe('analyzeDkim', () => {
  it('flags a weak (~1024-bit) RSA key', () => {
    const res = analyzeDkim('example.com', 'sel', `v=DKIM1; k=rsa; p=${'A'.repeat(140)}`);
    expect(res.hasPublicKey).toBe(true);
    expect(res.warnings.some((w) => w.toLowerCase().includes('2048'))).toBe(true);
  });

  it('rates a ~2048-bit key as good', () => {
    const res = analyzeDkim('example.com', 'sel', `v=DKIM1; k=rsa; p=${'A'.repeat(400)}`);
    expect(res.strengthHint).toContain('2048');
  });

  it('detects a revoked (empty p=) selector', () => {
    const res = analyzeDkim('example.com', 'sel', 'v=DKIM1; k=rsa; p=');
    expect(res.hasPublicKey).toBe(false);
    expect(res.warnings.some((w) => w.includes('revoked'))).toBe(true);
  });

  it('rejects an invalid selector', () => {
    expect(() => analyzeDkim('example.com', 'bad selector!', 'v=DKIM1; p=AAAA')).toThrow(ToolError);
  });
});
