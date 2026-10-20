import { StartupError } from './startup.mjs';
import { randomBytes, scrypt as derive, timingSafeEqual, createHash } from 'node:crypto';
import { promisify } from 'node:util';
const scrypt = promisify(derive);
export const digest = value => createHash('sha256').update(value).digest('hex');
export class HttpError extends Error {
  constructor(status, code, message) { super(message); this.status = status; this.code = code; }
}
export async function hashPassword(password) {
  if (typeof password !== 'string' || password.length < 12 || password.length > 128)
    throw new StartupError('CONFIG_INVALID','A senha deve conter entre 12 e 128 caracteres.');
  const salt = randomBytes(16).toString('hex');
  const key = await scrypt(password, salt, 64, { N: 32768, r: 8, p: 3, maxmem: 128 * 1024 * 1024 });
  return 'scrypt$v1$' + salt + '$' + key.toString('hex');
}
export async function verifyPassword(password, hash) {
  if (typeof password !== 'string' || password.length > 128) return false;
  const [, , salt, expected] = hash.split('$');
  const key = await scrypt(password, salt, 64, { N: 32768, r: 8, p: 3, maxmem: 128 * 1024 * 1024 });
  return timingSafeEqual(key, Buffer.from(expected, 'hex'));
}
export function readConfig(env = process.env) {
  const production = env.NODE_ENV === 'production';
  function configUrl(key) {
    try {
      if (!env[key]) throw new Error();
      return new URL(env[key]);
    } catch { throw new StartupError('CONFIG_INVALID', key + ' ausente ou com URL inválida. Confira o valor no Environment do Render.'); }
  }
  const origin = configUrl('APP_ORIGIN');
  if (origin.origin !== env.APP_ORIGIN || origin.username || origin.password || (production && origin.protocol !== 'https:') || !['https:', 'http:'].includes(origin.protocol))
    throw new StartupError('CONFIG_INVALID','APP_ORIGIN deve conter a origem exata, HTTPS em produção.');
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(env.ADMIN_EMAIL || '')) throw new StartupError('CONFIG_INVALID','ADMIN_EMAIL inválido.');
  if (!/^scrypt\$v1\$[a-f0-9]{32}\$[a-f0-9]{128}$/.test(env.ADMIN_PASSWORD_HASH || ''))
    throw new StartupError('CONFIG_INVALID','Gere ADMIN_PASSWORD_HASH com npm run password:hash.');
  if ((env.SESSION_SECRET || '').length < 32) throw new StartupError('CONFIG_INVALID','SESSION_SECRET deve ter pelo menos 32 caracteres.');
  for (const [key, role] of [['ADMIN_READ_DATABASE_URL', 'bonamassa_admin_reader'], ['ADMIN_AUDIT_DATABASE_URL', 'bonamassa_admin_logger']]) {
    const url = configUrl(key);
    if (!['postgres:', 'postgresql:'].includes(url.protocol) || url.username !== role)
      throw new StartupError('CONFIG_INVALID',key + ' deve usar o usuário restrito ' + role + '.');
    if (production && (url.searchParams.getAll('sslmode').length !== 1 || url.searchParams.get('sslmode') !== 'verify-full'))
      throw new StartupError('CONFIG_INVALID',key + ' deve usar sslmode=verify-full em produção.');
  }
  const port = Number(env.PORT || 3002);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new StartupError('CONFIG_INVALID','PORT inválido.');
  return { production, origin: origin.origin, email: env.ADMIN_EMAIL.toLowerCase(), passwordHash: env.ADMIN_PASSWORD_HASH,
    secret: env.SESSION_SECRET, readUrl: env.ADMIN_READ_DATABASE_URL, auditUrl: env.ADMIN_AUDIT_DATABASE_URL, port };
}
export class Sessions {
  constructor() { this.entries = new Map(); }
  create(actor) {
    this.cleanup();
    if (this.entries.size >= 20) this.entries.delete(this.entries.keys().next().value);
    const token = randomBytes(32).toString('base64url');
    const session = { actor, expiresAt: Date.now() + 30 * 60_000 };
    this.entries.set(digest(token), session);
    return { token, ...session };
  }
  cleanup() { for (const [key, entry] of this.entries) if (entry.expiresAt <= Date.now()) this.entries.delete(key); }
  get(token) { this.cleanup(); return typeof token === 'string' ? this.entries.get(digest(token)) : undefined; }
  revoke(token) { if (typeof token === 'string') this.entries.delete(digest(token)); }
}
export class RateLimit {
  constructor(limit, interval) { this.limit = limit; this.interval = interval; this.count = 0; this.until = 0; }
  take() {
    const now = Date.now();
    if (now >= this.until) { this.until = now + this.interval; this.count = 0; }
    if (++this.count > this.limit) throw new HttpError(429, 'RATE_LIMIT', 'Limite de tentativas atingido. Aguarde alguns minutos.');
  }
}
export function csv(columns, rows) {
  const cell = v => {
    let text = v == null ? '' : typeof v === 'object' ? JSON.stringify(v) : String(v);
    if (/^[\s\u0000-\u001f]*[=+\-@]/.test(text)) text = "'" + text;
    return '"' + text.replaceAll('"', '""') + '"';
  };
  return '\uFEFF' + [columns, ...rows].map(row => row.map(cell).join(';')).join('\r\n');
}
