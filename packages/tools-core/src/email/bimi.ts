import { lookupTxt, normalizeHostname } from '../dns/records';

export interface BimiResult {
  domain: string;
  selector: string;
  /** The full record name queried, e.g. default._bimi.example.com. */
  name: string;
  found: boolean;
  record?: string;
  version?: string;
  /** `l=` — the SVG Tiny PS brand logo URL. */
  logoUrl?: string;
  /** `a=` — the Verified Mark Certificate (VMC) URL. */
  authorityUrl?: string;
  warnings: string[];
}

/**
 * Look up a domain's BIMI record (TXT at <selector>._bimi.<domain>) and pull out the logo (`l=`)
 * and VMC (`a=`) tags. BIMI lets mailbox providers show a brand logo next to authenticated mail.
 */
export async function checkBimi(domainInput: string, selector = 'default'): Promise<BimiResult> {
  const domain = normalizeHostname(domainInput);
  const name = `${selector}._bimi.${domain}`;
  const txts = await lookupTxt(name);
  const record = txts.find((t) => /v\s*=\s*BIMI1/i.test(t));
  const warnings: string[] = [];

  if (!record) {
    warnings.push(`No BIMI record found at ${name}.`);
    return { domain, selector, name, found: false, warnings };
  }

  const tags: Record<string, string> = {};
  for (const part of record.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    tags[part.slice(0, eq).trim().toLowerCase()] = part.slice(eq + 1).trim();
  }
  const logoUrl = tags.l || undefined;
  const authorityUrl = tags.a || undefined;

  if (!logoUrl) warnings.push('BIMI record has no logo (l=) URL.');
  else if (!/^https:\/\//i.test(logoUrl)) warnings.push('BIMI logo (l=) must be served over HTTPS.');
  if (!authorityUrl) {
    warnings.push(
      'No VMC (a=) — Gmail, Apple Mail and others require a Verified Mark Certificate to display the logo.',
    );
  }

  return { domain, selector, name, found: true, record, version: tags.v, logoUrl, authorityUrl, warnings };
}
