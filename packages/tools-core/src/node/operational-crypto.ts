// Node-only (kept out of the package index). Operational-tier encryption at rest (ADR 0002): for
// data the SERVICE must read to do its job — monitored/parked domains, configs, results. AES-256-GCM
// via node:crypto with a server-held key from the environment, and key rotation. Public so the
// scheme is reviewable; the keys stay secret in OPERATIONAL_KEYS on the box.
//
// This is honest encryption-at-rest, NOT zero-knowledge: the operator CAN decrypt it (the service
// has to, to run your checks). Personal, zero-knowledge data uses a separate client-side scheme. A
// stolen disk/DB doesn't leak operational data without the env key; the running operator can read it.
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

const VERSION = '1';
const IV_BYTES = 12;
const KEY_BYTES = 32;

export interface Keyring {
  /** Key id used for new encryptions. */
  current: string;
  /** All known keys (current + older ones still needed to decrypt existing data during rotation). */
  keys: Record<string, Buffer>;
}

export interface OperationalCipher {
  /** Encrypt with the current key → a self-describing `version.keyId.iv.ct.tag` string. */
  encrypt(plaintext: string): string;
  /** Decrypt a blob; throws on tampering, an unknown key id, or a malformed blob. */
  decrypt(blob: string): string;
  /** True if a blob was written under a non-current key (re-encrypt it on the next write). */
  needsReencrypt(blob: string): boolean;
  readonly currentKeyId: string;
}

const b64u = (b: Buffer) => b.toString('base64url');
const ub64 = (s: string) => Buffer.from(s, 'base64url');

export function makeOperationalCipher(keyring: Keyring): OperationalCipher {
  const currentKey = keyring.keys[keyring.current];
  if (!currentKey || currentKey.length !== KEY_BYTES) {
    throw new Error('operational-crypto: current key is missing or not 32 bytes');
  }

  const parse = (blob: string) => {
    const parts = blob.split('.');
    if (parts.length !== 5 || parts[0] !== VERSION) {
      throw new Error('operational-crypto: malformed blob');
    }
    return { keyId: parts[1], iv: ub64(parts[2]), ct: ub64(parts[3]), tag: ub64(parts[4]) };
  };

  return {
    currentKeyId: keyring.current,

    encrypt(plaintext: string): string {
      const iv = randomBytes(IV_BYTES);
      const cipher = createCipheriv('aes-256-gcm', currentKey, iv);
      const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
      return [VERSION, keyring.current, b64u(iv), b64u(ct), b64u(cipher.getAuthTag())].join('.');
    },

    decrypt(blob: string): string {
      const { keyId, iv, ct, tag } = parse(blob);
      const key = keyring.keys[keyId];
      if (!key) throw new Error(`operational-crypto: unknown key id "${keyId}"`);
      const decipher = createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAuthTag(tag);
      return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
    },

    needsReencrypt(blob: string): boolean {
      return parse(blob).keyId !== keyring.current;
    },
  };
}

/** Parse a keyring from OPERATIONAL_KEYS: comma-separated `id:base64key` entries; the FIRST is the
 *  current (encrypt) key, the rest are kept for decrypting older data. Returns null when unset. */
export function keyringFromEnv(env: NodeJS.ProcessEnv = process.env): Keyring | null {
  const raw = env.OPERATIONAL_KEYS?.trim();
  if (!raw) return null;
  const keys: Record<string, Buffer> = {};
  let current = '';
  for (const entry of raw.split(',').map((s) => s.trim()).filter(Boolean)) {
    const idx = entry.indexOf(':');
    if (idx <= 0) throw new Error('operational-crypto: OPERATIONAL_KEYS entries must be "id:base64key"');
    const id = entry.slice(0, idx);
    const key = Buffer.from(entry.slice(idx + 1), 'base64');
    if (key.length !== KEY_BYTES) throw new Error(`operational-crypto: key "${id}" must decode to 32 bytes`);
    keys[id] = key;
    if (!current) current = id;
  }
  return current ? { current, keys } : null;
}

let cached: OperationalCipher | null = null;
/** The process-wide operational cipher, built from OPERATIONAL_KEYS. Throws if not configured —
 *  callers should treat that as "operational features unavailable". */
export function operationalCipher(): OperationalCipher {
  if (!cached) {
    const keyring = keyringFromEnv();
    if (!keyring) throw new Error('operational-crypto: OPERATIONAL_KEYS is not set');
    cached = makeOperationalCipher(keyring);
  }
  return cached;
}
