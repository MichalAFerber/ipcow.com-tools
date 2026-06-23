import { normalizeHostname } from '../dns/records';
import { type DmarcResult, checkDmarc } from './dmarc';
import { type MtaStsResult, checkMtaSts } from './mtasts';
import { type MxResult, lookupMx } from './mx';
import { type SpfResult, checkSpf } from './spf';

export interface EmailDeliverabilityResult {
  domain: string;
  /** Headline problems, surfaced as warnings by the UI. */
  warnings: string[];
  mx: MxResult;
  spf: SpfResult;
  dmarc: DmarcResult;
  mtaSts: MtaStsResult;
}

/**
 * One-shot email posture: MX + SPF + DMARC + MTA-STS in parallel, with the common
 * misconfigurations rolled up into a single warnings list. (DKIM needs a selector, so it stays a
 * separate tool.)
 */
export async function checkEmailDeliverability(
  domainInput: string,
): Promise<EmailDeliverabilityResult> {
  const domain = normalizeHostname(domainInput);
  const [mx, spf, dmarc, mtaSts] = await Promise.all([
    lookupMx(domain),
    checkSpf(domain),
    checkDmarc(domain),
    checkMtaSts(domain),
  ]);

  const warnings: string[] = [];
  if (!mx.found) warnings.push('No MX records — this domain cannot receive email.');
  if (!spf.found) warnings.push('No SPF record found.');
  else if (!spf.withinLimit)
    warnings.push(`SPF exceeds the RFC 7208 limit of 10 DNS lookups (${spf.totalLookups}).`);
  if (!dmarc.found) warnings.push('No DMARC record found.');
  else if (dmarc.policy === 'none')
    warnings.push('DMARC policy is p=none — monitoring only, not enforced.');
  if (!mtaSts.configured) warnings.push('No enforced MTA-STS policy — SMTP TLS is not pinned.');

  return { domain, warnings, mx, spf, dmarc, mtaSts };
}
