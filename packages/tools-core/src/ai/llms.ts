import { ToolError } from '../errors';

export interface LlmsTxtResult {
  url: string;
  found: boolean;
  status: number;
  contentType: string | null;
  sizeBytes: number;
  lineCount: number;
  /** First ~1.2 KB of the file, for a quick look. */
  preview: string;
}

const UA = 'ipcow-llms-check/1.0 (+https://ipcow.com)';
const MAX_BYTES = 64 * 1024;

function toUrl(input: string, file: string): string {
  let raw = input.trim();
  if (!raw) throw new ToolError('invalid_input', 'a domain or URL is required');
  if (!/^https?:\/\//i.test(raw)) raw = `https://${raw}`;
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new ToolError('invalid_input', `invalid domain or URL: ${input}`);
  }
  return `${u.protocol}//${u.host}/${file}`;
}

/**
 * Fetch a site's /llms.txt — the emerging convention for pointing LLMs at curated, model-friendly
 * documentation. Reports whether it exists and a short preview.
 */
export async function checkLlmsTxt(
  input: string,
  opts?: { timeoutMs?: number },
): Promise<LlmsTxtResult> {
  const url = toUrl(input, 'llms.txt');
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

  const contentType = res.headers.get('content-type');
  if (res.status < 200 || res.status >= 300) {
    void res.body?.cancel().catch(() => {});
    return { url, found: false, status: res.status, contentType, sizeBytes: 0, lineCount: 0, preview: '' };
  }

  const text = (await res.text()).slice(0, MAX_BYTES);
  // A real llms.txt is markdown / plain text, not an HTML soft-404 page.
  const looksHtml = /^\s*<(?:!doctype|html)\b/i.test(text);
  const found = !looksHtml && text.trim().length > 0;

  return {
    url,
    found,
    status: res.status,
    contentType,
    sizeBytes: text.length,
    lineCount: found ? text.split('\n').length : 0,
    preview: found ? text.slice(0, 1200) : '',
  };
}
