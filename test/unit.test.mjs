import test from 'node:test';
import assert from 'node:assert/strict';
import { validateSQL } from '../src/sql.mjs';
import { hashPassword, verifyPassword, Sessions, RateLimit, csv, readConfig } from '../src/security.mjs';

test('SELECTs, JOINs, aggregate and nested projections are regenerated against authorized views', () => {
  for (const sql of [
    'SELECT * FROM "Order" ORDER BY "createdAt" DESC',
    'SELECT channel, count(*) AS pedidos, sum(total) FROM "Order" GROUP BY channel',
    'SELECT o.id, u.name FROM "Order" o LEFT JOIN "User" u ON o."driverId" = u.id',
    'SELECT * FROM (SELECT id FROM "User") users',
    'SELECT data->>\'name\' FROM "Product" WHERE id = \'x\'',
    'SELECT CAST(id AS text) FROM "Store"',
    'SELECT 1 AS teste'
  ]) {
    const result = validateSQL(sql);
    assert.ok(result.query); assert.equal(typeof result.template, 'string');
    if (result.tables.length) assert.match(result.query, /bonamassa_admin/);
  }
});
test('rejects writes, CTEs, catalogs, external functions, locking and multi-statements', () => {
  for (const sql of [
    'DELETE FROM "Order"', 'UPDATE "User" SET enabled = false', 'SELECT 1; DELETE FROM "Order"',
    'WITH x AS (DELETE FROM "Order" RETURNING *) SELECT * FROM x',
    'WITH x AS (SELECT * FROM "User") SELECT * FROM x',
    'SELECT * FROM public."User"', 'SELECT * FROM pg_catalog.pg_authid', 'SELECT * FROM information_schema.tables',
    'SELECT pg_sleep(10)', 'SELECT pg_read_file(\'/etc/passwd\')', 'SELECT set_config(\'x\',\'y\',false)',
    'SELECT pg_catalog.count(*) FROM "User"', 'SELECT * FROM "User" FOR UPDATE',
    'SELECT * INTO copied FROM "User"', 'COPY "User" TO STDOUT',
    'SELECT \'public.User\'::regclass', 'SELECT repeat(\'x\',9999999)',
    'SELECT current_user', 'SELECT * FROM generate_series(1,1000000)',
    'SELECT * FROM "User" UNION SELECT * FROM "User"', 'SELECT $1'
  ]) assert.throws(() => validateSQL(sql), /SELECT/);
});
test('audit templates do not persist query literal values', () => {
  const output = validateSQL('SELECT id FROM "User" WHERE name = \'confidential-value\' AND version > 123');
  assert.ok(!output.template.includes('confidential-value'));
  assert.ok(!output.template.includes('123'));
});
test('password hashing, expiry, revocation, rate limit and CSV formula neutralization', async () => {
  const hash = await hashPassword('test-only-password-123');
  assert.equal(await verifyPassword('test-only-password-123', hash), true);
  assert.equal(await verifyPassword('wrong', hash), false);
  const sessions = new Sessions(); const session = sessions.create('tech@example.test');
  assert.equal(sessions.get(session.token).actor, 'tech@example.test');
  assert.equal(sessions.get('bad'), undefined);
  sessions.revoke(session.token); assert.equal(sessions.get(session.token), undefined);
  const expired = sessions.create('x'); sessions.entries.values().next().value.expiresAt = Date.now() - 1;
  assert.equal(sessions.get(expired.token), undefined);
  const limit = new RateLimit(1, 60000); limit.take(); assert.throws(() => limit.take());
  const output = csv(['name'], [['=SUM(1,2)'], ['\t@evil'], ['normal "quote"'], [null]]);
  assert.ok(output.includes("'=SUM")); assert.ok(output.includes("'\t@evil")); assert.ok(output.includes('""quote""'));
});
test('production configuration refuses owner credentials and unverified TLS', async () => {
  const env = { NODE_ENV: 'production', PORT: '3002', APP_ORIGIN: 'https://admin.example.com', ADMIN_EMAIL: 'tech@example.com',
    ADMIN_PASSWORD_HASH: await hashPassword('test-only-password-123'), SESSION_SECRET: 'x'.repeat(40),
    ADMIN_READ_DATABASE_URL: 'postgresql://bonamassa_admin_reader:pw@localhost/test?sslmode=verify-full',
    ADMIN_AUDIT_DATABASE_URL: 'postgresql://bonamassa_admin_logger:pw@localhost/test?sslmode=verify-full' };
  assert.equal(readConfig(env).production, true);
  assert.throws(() => readConfig({ ...env, ADMIN_READ_DATABASE_URL: env.ADMIN_READ_DATABASE_URL.replace('bonamassa_admin_reader', 'neondb_owner') }));
  assert.throws(() => readConfig({ ...env, ADMIN_READ_DATABASE_URL: env.ADMIN_READ_DATABASE_URL.replace('verify-full', 'require') }));
  assert.throws(() => readConfig({ ...env, APP_ORIGIN: 'http://admin.example.com' }));
});
