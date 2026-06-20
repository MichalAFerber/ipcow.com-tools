import { type DohOptions } from '../dns/doh';
import { lookupTxt, normalizeHostname } from '../dns/records';

const LOOKUP_MECHANISMS = new Set(['include', 'a', 'mx', 'ptr', 'exists']);
const QUALIFIERS = '+-~?';

export interface SpfMechanism {
  qualifier: '+' | '-' | '~' | '?';
  type: string;
  value?: string;
  countsAsLookup: boolean;
}

export interface SpfResult {
  domain: string;
  found: boolean;
  record?: string;
  multipleRecords: boolean;
  mechanisms: SpfMechanism[];
  allQualifier?: string;
  /** DNS-querying terms evaluated recursively; RFC 7208 caps this at 10. */
  totalLookups: number;
  withinLimit: boolean;
  warnings: string[];
}

/** Resolves the TXT records for a name. Injected so the analyzer is testable offline. */
export type TxtResolver = (name: string) => Promise<string[]>;

function selectSpf(txts: string[]): { record?: string; multiple: boolean } {
  const spf = txts.filter((t) => /^v=spf1(\s|$)/i.test(t.trim()));
  return { record: spf[0], multiple: spf.length > 1 };
}

export function parseMechanisms(record: string): {
  mechanisms: SpfMechanism[];
  allQualifier?: string;
} {
  const terms = record.trim().split(/\s+/).slice(1); // drop "v=spf1"
  const mechanisms: SpfMechanism[] = [];
  let allQualifier: string | undefined;

  for (const term of terms) {
    if (term === '') continue;
    const first = term[0] ?? '';

    // Modifiers (name=value), e.g. redirect= / exp=
    const eq = term.indexOf('=');
    if (eq > 0 && !QUALIFIERS.includes(first)) {
      const name = term.slice(0, eq).toLowerCase();
      const value = term.slice(eq + 1);
      mechanisms.push({ qualifier: '+', type: name, value, countsAsLookup: name === 'redirect' });
      continue;
    }

    let qualifier: SpfMechanism['qualifier'] = '+';
    let body = term;
    if (QUALIFIERS.includes(first)) {
      qualifier = first as SpfMechanism['qualifier'];
      body = term.slice(1);
    }
    const colon = body.indexOf(':');
    const type = (colon >= 0 ? body.slice(0, colon) : body).toLowerCase();
    const value = colon >= 0 ? body.slice(colon + 1) : undefined;

    if (type === 'all') {
      allQualifier = `${qualifier}all`;
      mechanisms.push({ qualifier, type: 'all', countsAsLookup: false });
    } else {
      mechanisms.push({ qualifier, type, value, countsAsLookup: LOOKUP_MECHANISMS.has(type) });
    }
  }

  return { mechanisms, allQualifier };
}

/**
 * Analyze a domain's SPF policy, including the recursive 10-lookup limit. Resolver is
 * injected so this is unit-testable without network.
 */
export async function analyzeSpf(domain: string, resolveTxt: TxtResolver): Promise<SpfResult> {
  const getRecord = async (d: string) => selectSpf(await resolveTxt(d));
  const { record, multiple } = await getRecord(domain);
  const warnings: string[] = [];

  if (!record) {
    return {
      domain,
      found: false,
      multipleRecords: false,
      mechanisms: [],
      totalLookups: 0,
      withinLimit: true,
      warnings: ['No SPF record found.'],
    };
  }

  if (multiple) {
    warnings.push('Multiple SPF records found — RFC 7208 requires exactly one (permerror).');
  }

  const { mechanisms, allQualifier } = parseMechanisms(record);
  if (!allQualifier) warnings.push('No "all" mechanism — the policy is open-ended.');
  if (allQualifier === '+all') {
    warnings.push('"+all" lets anyone send as your domain — almost always a misconfiguration.');
  }

  // Recursively count DNS-lookup terms across include/redirect, capped at 10.
  const seen = new Set<string>([domain]);
  let total = 0;
  let exceeded = false;

  const walk = async (rec: string): Promise<void> => {
    for (const m of parseMechanisms(rec).mechanisms) {
      if (!m.countsAsLookup) continue;
      total += 1;
      if (total > 10) {
        exceeded = true;
        return;
      }
      if ((m.type === 'include' || m.type === 'redirect') && m.value) {
        const target = m.value.toLowerCase();
        if (seen.has(target)) continue;
        seen.add(target);
        const sub = await getRecord(target);
        if (sub.record) await walk(sub.record);
        if (exceeded) return;
      }
    }
  };
  await walk(record);

  if (exceeded || total > 10) {
    warnings.push(
      `SPF requires ${exceeded ? 'more than 10' : total} DNS lookups — exceeds the RFC 7208 limit of 10 (permerror). Flatten or reduce includes.`,
    );
  }

  return {
    domain,
    found: true,
    record,
    multipleRecords: multiple,
    mechanisms,
    allQualifier,
    totalLookups: total,
    withinLimit: total <= 10,
    warnings,
  };
}

/** Resolve and analyze a domain's SPF policy using live DNS (Quad9 by default). */
export async function checkSpf(domainInput: string, opts?: DohOptions): Promise<SpfResult> {
  const domain = normalizeHostname(domainInput);
  return analyzeSpf(domain, (name) => lookupTxt(name, opts));
}
