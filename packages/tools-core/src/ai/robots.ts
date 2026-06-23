import { ToolError } from '../errors';

export interface RobotsAgentRule {
  agent: string;
  /** The agent has its own group in robots.txt (otherwise it falls under `*`). */
  present: boolean;
  /** Blocked from the site root — its own group says Disallow: /, or the `*` group does. */
  blockedAtRoot: boolean;
  disallow: string[];
}

export interface RobotsLlmResult {
  url: string;
  found: boolean;
  status: number;
  /** The `*` group disallows everything. */
  wildcardBlocksAll: boolean;
  aiBots: RobotsAgentRule[];
  warnings: string[];
}

const UA = 'ipcow-robots-check/1.0 (+https://ipcow.com)';
const MAX_BYTES = 256 * 1024;

// Known AI / LLM crawler user-agents: training scrapers, retrieval/search bots, and the
// assistant-side fetchers that act on a user's behalf.
const AI_AGENTS = [
  'GPTBot',
  'ChatGPT-User',
  'OAI-SearchBot',
  'ClaudeBot',
  'Claude-User',
  'anthropic-ai',
  'Google-Extended',
  'CCBot',
  'PerplexityBot',
  'Bytespider',
  'Amazonbot',
  'Applebot-Extended',
  'Meta-ExternalAgent',
  'cohere-ai',
  'Diffbot',
];

function toRobotsUrl(input: string): string {
  let raw = input.trim();
  if (!raw) throw new ToolError('invalid_input', 'a domain or URL is required');
  if (!/^https?:\/\//i.test(raw)) raw = `https://${raw}`;
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new ToolError('invalid_input', `invalid domain or URL: ${input}`);
  }
  return `${u.protocol}//${u.host}/robots.txt`;
}

/** Parse robots.txt into Disallow rules grouped by (lowercased) user-agent. */
function parseGroups(body: string): Map<string, string[]> {
  const groups = new Map<string, string[]>();
  let current: string[] = [];
  let sawDirective = false;
  for (const rawLine of body.split('\n')) {
    const line = rawLine.replace(/#.*$/, '').trim();
    if (!line) continue;
    const colon = line.indexOf(':');
    if (colon < 0) continue;
    const field = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    if (field === 'user-agent') {
      if (sawDirective) current = []; // a new group starts after the previous one's rules
      const key = value.toLowerCase();
      if (groups.has(key)) current = groups.get(key)!;
      else groups.set(key, current);
      sawDirective = false;
    } else if (field === 'disallow') {
      current.push(value);
      sawDirective = true;
    } else {
      sawDirective = true;
    }
  }
  return groups;
}

const blocksAll = (rules: string[]) => rules.some((r) => r === '/');

/**
 * Fetch a site's robots.txt and report how it treats known AI/LLM crawlers — which are blocked at
 * the root, which fall through to the wildcard group, and whether anything restricts them at all.
 */
export async function checkRobotsLlm(
  input: string,
  opts?: { timeoutMs?: number },
): Promise<RobotsLlmResult> {
  const url = toRobotsUrl(input);
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), opts?.timeoutMs ?? 8000);
  let res: Response;
  try {
    res = await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      signal: ctrl.signal,
      headers: { 'user-agent': UA },
    });
  } catch (err) {
    const n = (err as Error)?.name;
    if (n === 'TimeoutError' || n === 'AbortError') {
      throw new ToolError('timeout', `request to ${url} timed out`);
    }
    throw new ToolError('upstream_error', `request to ${url} failed: ${(err as Error)?.message}`);
  } finally {
    clearTimeout(timer);
  }

  const warnings: string[] = [];
  if (res.status < 200 || res.status >= 300) {
    void res.body?.cancel().catch(() => {});
    warnings.push(`No robots.txt (HTTP ${res.status}) — nothing restricts AI crawlers.`);
    return { url, found: false, status: res.status, wildcardBlocksAll: false, aiBots: [], warnings };
  }

  const body = (await res.text()).slice(0, MAX_BYTES);
  const groups = parseGroups(body);
  const wildcardBlocksAll = blocksAll(groups.get('*') ?? []);

  const aiBots: RobotsAgentRule[] = AI_AGENTS.map((agent) => {
    const rules = groups.get(agent.toLowerCase());
    const present = rules !== undefined;
    return {
      agent,
      present,
      blockedAtRoot: present ? blocksAll(rules) : wildcardBlocksAll,
      disallow: rules ?? [],
    };
  });

  if (!aiBots.some((b) => b.blockedAtRoot)) {
    warnings.push('No known AI crawler is blocked at the root — every listed LLM bot may crawl this site.');
  }

  return { url, found: true, status: res.status, wildcardBlocksAll, aiBots, warnings };
}
