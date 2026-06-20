import { type DohOptions } from '../dns/doh';
import { lookupTxt, normalizeHostname } from '../dns/records';
import { ToolError } from '../errors';

const SELECTOR_RE = /^[a-z0-9_-]{1,63}$/i;

export interface DkimResult {
  domain: string;
  selector: string;
  queryName: string;
  found: boolean;
  record?: string;
  tags: Record<string, string>;
  keyType?: string;
  hasPublicKey: boolean;
  keyByteLength?: number;
  strengthHint?: string;
  warnings: string[];
}

function base64ByteLength(b64: string): number {
  return atob(b64.replace(/\s+/g, '')).length;
}

/** Pure DKIM analysis given an already-fetched record (or undefined). Testable offline. */
export function analyzeDkim(
  domain: string,
  selectorInput: string,
  record: string | undefined,
): DkimResult {
  const selector = selectorInput.trim();
  if (!SELECTOR_RE.test(selector)) {
    throw new ToolError('invalid_input', `invalid DKIM selector: ${selectorInput}`);
  }
  const queryName = `${selector}._domainkey.${domain}`;
  const warnings: string[] = [];

  if (!record) {
    return {
      domain,
      selector,
      queryName,
      found: false,
      tags: {},
      hasPublicKey: false,
      warnings: [`No DKIM record found at ${queryName}.`],
    };
  }

  const tags: Record<string, string> = {};
  for (const part of record.split(';')) {
    const t = part.trim();
    const eq = t.indexOf('=');
    if (eq < 0) continue;
    tags[t.slice(0, eq).trim().toLowerCase()] = t.slice(eq + 1).trim();
  }

  const keyType = (tags['k'] ?? 'rsa').toLowerCase();
  const publicKey = tags['p'] ?? '';
  const hasPublicKey = publicKey.length > 0;
  let keyByteLength: number | undefined;
  let strengthHint: string | undefined;

  if (!hasPublicKey) {
    warnings.push('Public key "p=" is empty — this selector has been revoked.');
  } else {
    try {
      keyByteLength = base64ByteLength(publicKey);
      if (keyType === 'rsa') {
        // Heuristic on SPKI DER length (~24-38 bytes overhead over the modulus).
        if (keyByteLength < 160) {
          strengthHint = 'RSA ~1024-bit or smaller — weak.';
          warnings.push('DKIM key appears to be 1024-bit RSA or smaller; rotate to >=2048-bit.');
        } else if (keyByteLength < 320) {
          strengthHint = 'RSA ~2048-bit — good.';
        } else {
          strengthHint = 'RSA >=3072-bit — strong.';
        }
      } else if (keyType === 'ed25519') {
        strengthHint = 'Ed25519 — modern and strong.';
      }
    } catch {
      warnings.push('Public key is not valid base64.');
    }
  }

  return {
    domain,
    selector,
    queryName,
    found: true,
    record,
    tags,
    keyType,
    hasPublicKey,
    keyByteLength,
    strengthHint,
    warnings,
  };
}

/** Look up and analyze a DKIM public key at <selector>._domainkey.<domain> using live DNS. */
export async function checkDkim(
  domainInput: string,
  selectorInput: string,
  opts?: DohOptions,
): Promise<DkimResult> {
  const domain = normalizeHostname(domainInput);
  const selector = selectorInput.trim();
  if (!SELECTOR_RE.test(selector)) {
    throw new ToolError('invalid_input', `invalid DKIM selector: ${selectorInput}`);
  }
  const queryName = `${selector}._domainkey.${domain}`;
  const txts = await lookupTxt(queryName, opts);
  const record = txts.find((t) => /(^|;)\s*v\s*=\s*DKIM1/i.test(t) || /(^|;)\s*p\s*=/.test(t));
  return analyzeDkim(domain, selector, record);
}
