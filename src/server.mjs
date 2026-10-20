import { startupDiagnostic } from './startup.mjs';
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { randomUUID, createHmac } from 'node:crypto';
import { Database } from './db.mjs';
import { readConfig, verifyPassword, Sessions, RateLimit, HttpError, csv } from './security.mjs';
const assets = new Map([['/', ['index.html', 'text/html; charset=utf-8']], ['/app.js', ['app.js', 'text/javascript; charset=utf-8']], ['/style.css', ['style.css', 'text/css; charset=utf-8']]]);
export async function createServer(config, db = new Database(config)) {
  await db.verify();
  const sessions = new Sessions();
  const loginRate = new RateLimit(10, 15 * 60_000);
  const queryRate = new RateLimit(120, 60_000);
  let checkingPassword = false;
  const files = new Map();
  for (const [url, [name, mime]] of assets) files.set(url, { mime, bytes: await readFile(new URL('../public/' + name, import.meta.url)) });
  const server = http.createServer(async (req, res) => {
    const requestId = randomUUID();
    const context = { id: requestId, actor: config.email, peerHash: createHmac('sha256', config.secret).update(req.socket.remoteAddress || '').digest('hex') };
    res.setHeader('X-Request-Id', requestId);
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
    if (config.production) res.setHeader('Strict-Transport-Security', 'max-age=31536000');
    function json(code, data) { res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(data)); }
    try {
      const path = new URL(req.url, 'http://local').pathname;
      if (req.method === 'GET' && path === '/health') return json(200, { status: 'ok', version: '0.1.1', commit: process.env.RENDER_GIT_COMMIT || null });
      if (req.method === 'GET' && files.has(path)) {
        const file = files.get(path);
        res.writeHead(200, { 'Content-Type': file.mime }); return res.end(file.bytes);
      }
      if (!path.startsWith('/api/')) throw new HttpError(404, 'NOT_FOUND', 'Recurso não encontrado.');
      if (req.headers['sec-fetch-site'] === 'cross-site') throw new HttpError(403, 'ORIGIN_REJECTED', 'Origem não permitida.');
      let body = {};
      if (req.method === 'POST') {
        if (req.headers.origin !== config.origin) throw new HttpError(403, 'ORIGIN_REJECTED', 'Origem não permitida.');
        if (req.headers['content-type']?.split(';')[0] !== 'application/json') throw new HttpError(415, 'INVALID_CONTENT_TYPE', 'Envie JSON.');
        const chunks = [];
        let length = 0;
        for await (const chunk of req) {
          length += chunk.length;
          if (length > 16_384) throw new HttpError(413, 'BODY_TOO_LARGE', 'Requisição muito grande.');
          chunks.push(chunk);
        }
        try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { throw new HttpError(400, 'INVALID_JSON', 'JSON inválido.'); }
        if (!body || typeof body !== 'object' || Array.isArray(body)) throw new HttpError(400, 'INVALID_JSON', 'Envie um objeto JSON.');
      } else if (req.method !== 'GET') throw new HttpError(405, 'METHOD_NOT_ALLOWED', 'Método não permitido.');
      const cookieName = config.production ? '__Host-bonamassa-admin' : 'bonamassa-admin';
      const token = (req.headers.cookie || '').split(';').map(v => v.trim()).find(v => v.startsWith(cookieName + '='))?.slice(cookieName.length + 1);
      const setCookie = (value, age) => res.setHeader('Set-Cookie', cookieName + '=' + value + '; Path=/; HttpOnly; SameSite=Strict; Max-Age=' + age + (config.production ? '; Secure' : ''));
      if (req.method === 'POST' && path === '/api/login') {
        loginRate.take();
        if (checkingPassword) throw new HttpError(429, 'BUSY', 'Autenticação em andamento. Tente novamente.');
        checkingPassword = true;
        let valid;
        try { valid = await verifyPassword(body.password, config.passwordHash); } finally { checkingPassword = false; }
        if (typeof body.email !== 'string' || body.email.toLowerCase() !== config.email || !valid) {
          await db.log(context, 'login', 'failed');
          throw new HttpError(401, 'INVALID_CREDENTIALS', 'E-mail ou senha inválidos.');
        }
        await db.log(context, 'login', 'completed');
        const session = sessions.create(config.email);
        setCookie(session.token, 1800);
        return json(200, { actor: session.actor, expiresAt: session.expiresAt });
      }
      const session = sessions.get(token);
      if (!session) throw new HttpError(401, 'UNAUTHENTICATED', 'Entre com sua conta técnica.');
      if (req.method === 'GET' && path === '/api/session') return json(200, session);
      if (req.method === 'POST' && path === '/api/logout') {
        sessions.revoke(token); setCookie('', 0);
        await db.log(context, 'logout', 'completed');
        return json(200, { revoked: true });
      }
      queryRate.take();
      if (req.method === 'GET' && path === '/api/catalog') {
        await db.log(context, 'catalog', 'completed');
        return json(200, { tables: await db.catalog(), apiVersion: '0.13.1' });
      }
      if (req.method === 'POST' && path === '/api/browse') return json(200, await db.browse(context, body));
      if (req.method === 'POST' && ['/api/query', '/api/export'].includes(path)) {
        const result = await db.run(context, body.sql, path === '/api/export' ? 'export' : 'query');
        if (path === '/api/export') {
          res.writeHead(200, { 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename="bonamassa-consulta.csv"' });
          return res.end(csv(result.columns, result.rows));
        }
        return json(200, result);
      }
      throw new HttpError(404, 'NOT_FOUND', 'Recurso não encontrado.');
    } catch (e) {
      const known = e instanceof HttpError;
      if (!known) console.error(JSON.stringify({ event: 'request.error', requestId, code: 'INTERNAL_ERROR' }));
      if (e.status === 429) res.setHeader('Retry-After', '60');
      if (!res.headersSent) json(known ? e.status : 500, { code: known ? e.code : 'INTERNAL_ERROR', message: known ? e.message : 'Falha interna. Consulte o identificador da requisição.', requestId });
      else res.end();
    }
  });
  server.requestTimeout = 45_000;
  server.headersTimeout = 15_000;
  return { server, db };
}
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  let app;
  let stage = 'CONFIG';
  try {
    const config = readConfig();
    stage = 'DATABASE';
    app = await createServer(config);
    stage = 'SERVER';
    app.server.listen(config.port, '0.0.0.0', () => console.log('Bonamassa Admin 0.1.1 disponível na porta ' + config.port));
    for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => app.server.close(async () => { await app.db.close(); process.exit(0); }));
  } catch (error) {
    console.error(JSON.stringify(startupDiagnostic(error, error.stage || stage)));
    if (app) await app.db.close();
    process.exit(1);
  }
}
