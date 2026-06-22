import { describe, expect, it } from 'vitest';
import { extractSecurityHeaders } from '../http/headers';
import { parseMtaStsPolicy, parseStsId, parseTlsRpt } from '../email/mtasts';

describe('extractSecurityHeaders', () => {
  it('pulls present security headers and nulls the rest', () => {
    expect(
      extractSecurityHeaders({
        'strict-transport-security': 'max-age=63072000; includeSubDomains',
        'x-frame-options': 'DENY',
        'content-type': 'text/html',
      }),
    ).toEqual({
      hsts: 'max-age=63072000; includeSubDomains',
      csp: null,
      xContentTypeOptions: null,
      xFrameOptions: 'DENY',
      referrerPolicy: null,
      permissionsPolicy: null,
    });
  });
});

describe('parseStsId', () => {
  it('extracts the id from a v=STSv1 record and ignores others', () => {
    expect(parseStsId(['v=STSv1; id=20210803T010101;'])).toBe('20210803T010101');
    expect(parseStsId(['v=spf1 -all'])).toBeNull();
  });
});

describe('parseMtaStsPolicy', () => {
  it('parses mode, repeated mx, and max_age', () => {
    expect(
      parseMtaStsPolicy(
        'version: STSv1\nmode: enforce\nmx: a.example.com\nmx: b.example.com\nmax_age: 86400\n',
      ),
    ).toEqual({
      version: 'STSv1',
      mode: 'enforce',
      mx: ['a.example.com', 'b.example.com'],
      maxAge: 86400,
    });
  });

  it('returns null for a non-STS body', () => {
    expect(parseMtaStsPolicy('hello world')).toBeNull();
  });
});

describe('parseTlsRpt', () => {
  it('returns the TLS-RPT record when present', () => {
    expect(parseTlsRpt(['v=TLSRPTv1;rua=mailto:r@example.com'])).toBe(
      'v=TLSRPTv1;rua=mailto:r@example.com',
    );
    expect(parseTlsRpt(['v=spf1 -all'])).toBeNull();
  });
});
