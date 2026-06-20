import { normalizeHostname } from '../dns/records';
import { ToolError } from '../errors';
import { normalizeIp } from '../ip/address';

// rdap.org is a community bootstrap/redirector that forwards to the authoritative RIR or
// registry. Not a commercial whois API, and not big-tech.
const RDAP_BASE = 'https://rdap.org';

interface RdapEvent {
  eventAction?: string;
  eventDate?: string;
}
interface RdapEntity {
  roles?: string[];
  handle?: string;
  vcardArray?: unknown;
  entities?: RdapEntity[];
}

async function rdapFetch(path: string, timeoutMs = 6000): Promise<Record<string, unknown>> {
  let res: Response;
  try {
    res = await fetch(`${RDAP_BASE}${path}`, {
      headers: { accept: 'application/rdap+json' },
      redirect: 'follow',
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (err) {
    const name = (err as Error)?.name;
    if (name === 'TimeoutError' || name === 'AbortError') {
      throw new ToolError('timeout', 'RDAP request timed out');
    }
    throw new ToolError('upstream_error', `RDAP request failed: ${(err as Error)?.message}`);
  }
  if (res.status === 404) throw new ToolError('not_found', 'No RDAP record found for that query');
  if (!res.ok) throw new ToolError('upstream_error', `RDAP returned HTTP ${res.status}`);
  return (await res.json()) as Record<string, unknown>;
}

function vcardField(entity: RdapEntity | undefined, field: string): string | undefined {
  if (!entity || !Array.isArray(entity.vcardArray)) return undefined;
  const props = entity.vcardArray[1];
  if (!Array.isArray(props)) return undefined;
  for (const prop of props) {
    if (Array.isArray(prop) && prop[0] === field && typeof prop[3] === 'string') {
      return prop[3];
    }
  }
  return undefined;
}

function findEntity(entities: RdapEntity[] | undefined, role: string): RdapEntity | undefined {
  if (!entities) return undefined;
  for (const e of entities) {
    if (e.roles?.includes(role)) return e;
    const nested = findEntity(e.entities, role);
    if (nested) return nested;
  }
  return undefined;
}

function eventDate(events: unknown, action: string): string | undefined {
  if (!Array.isArray(events)) return undefined;
  return (events as RdapEvent[]).find((e) => e.eventAction === action)?.eventDate;
}

export interface RdapIpResult {
  query: string;
  handle?: string;
  name?: string;
  type?: string;
  country?: string;
  startAddress?: string;
  endAddress?: string;
  cidr?: string;
  abuseEmail?: string;
  registered?: string;
  lastChanged?: string;
  raw: unknown;
}

export async function rdapIp(ipInput: string): Promise<RdapIpResult> {
  const norm = normalizeIp(ipInput);
  if (!norm) throw new ToolError('invalid_input', `invalid IP address: ${ipInput}`);
  const data = await rdapFetch(`/ip/${norm.normalized}`);
  const entities = data['entities'] as RdapEntity[] | undefined;
  const abuse = findEntity(entities, 'abuse');

  let cidr: string | undefined;
  const cidrs = data['cidr0_cidrs'];
  if (Array.isArray(cidrs) && cidrs[0] && typeof cidrs[0] === 'object') {
    const c = cidrs[0] as Record<string, unknown>;
    const prefix = c['v4prefix'] ?? c['v6prefix'];
    if (prefix !== undefined) cidr = `${prefix}/${c['length']}`;
  }

  return {
    query: norm.normalized,
    handle: data['handle'] as string | undefined,
    name: data['name'] as string | undefined,
    type: data['type'] as string | undefined,
    country: data['country'] as string | undefined,
    startAddress: data['startAddress'] as string | undefined,
    endAddress: data['endAddress'] as string | undefined,
    cidr,
    abuseEmail: vcardField(abuse, 'email'),
    registered: eventDate(data['events'], 'registration'),
    lastChanged: eventDate(data['events'], 'last changed'),
    raw: data,
  };
}

export interface RdapDomainResult {
  query: string;
  ldhName?: string;
  status?: string[];
  registrar?: string;
  abuseEmail?: string;
  nameservers: string[];
  dnssec?: boolean;
  registered?: string;
  expires?: string;
  lastChanged?: string;
  raw: unknown;
}

export async function rdapDomain(domainInput: string): Promise<RdapDomainResult> {
  const domain = normalizeHostname(domainInput);
  const data = await rdapFetch(`/domain/${domain}`);
  const entities = data['entities'] as RdapEntity[] | undefined;
  const registrar = findEntity(entities, 'registrar');
  const abuse = findEntity(entities, 'abuse');

  const nsRaw = data['nameservers'];
  const nameservers = Array.isArray(nsRaw)
    ? nsRaw
        .map((n) => (n && typeof n === 'object' ? String((n as Record<string, unknown>)['ldhName'] ?? '') : ''))
        .filter(Boolean)
        .map((s) => s.toLowerCase())
    : [];

  const secureDns = data['secureDNS'];
  const dnssec =
    secureDns && typeof secureDns === 'object'
      ? Boolean((secureDns as Record<string, unknown>)['delegationSigned'])
      : undefined;

  return {
    query: domain,
    ldhName: data['ldhName'] as string | undefined,
    status: data['status'] as string[] | undefined,
    registrar: vcardField(registrar, 'fn'),
    abuseEmail: vcardField(abuse, 'email'),
    nameservers,
    dnssec,
    registered: eventDate(data['events'], 'registration'),
    expires: eventDate(data['events'], 'expiration'),
    lastChanged: eventDate(data['events'], 'last changed'),
    raw: data,
  };
}
