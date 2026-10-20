import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdir } from 'node:fs/promises';
import { once } from 'node:events';
import { randomUUID } from 'node:crypto';
import pg from 'pg';
import { chromium } from '@playwright/test';
import { Database } from '../src/db.mjs';
import { createServer } from '../src/server.mjs';
import { hashPassword, readConfig } from '../src/security.mjs';
const rootUrl = process.env.TEST_DATABASE_URL;
test('isolated PostgreSQL and browser integration', { skip: !rootUrl, timeout: 180000 }, async t => {
  if (new URL(rootUrl).pathname !== '/bonamassa_admin_test') throw new Error('Use only bonamassa_admin_test.');
  const root = new pg.Pool({ connectionString: rootUrl });
  let db, app, browser;
  try {
    await root.query(await readFile('db/001_admin.sql', 'utf8'));
    await root.query("ALTER ROLE bonamassa_admin_reader PASSWORD 'ci-reader-only'; ALTER ROLE bonamassa_admin_logger PASSWORD 'ci-logger-only'");
    const store = randomUUID(), user = randomUUID();
    await root.query('INSERT INTO "Store" (id, slug, name) VALUES ($1,$2,$3)', [store, 'admin-test', 'Loja teste']);
    await root.query('INSERT INTO "User" (id,"storeId",email,name,phone,"passwordHash",role) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [user,store,'private@example.test','=1+1','11999999999','never-expose-password-hash','DRIVER']);
    await root.query('INSERT INTO "Product" ("storeId",id,category,"nameKey",data) VALUES ($1,$2,$3,$4,$5)',
      [store,'test-product','PIZZA','pizza-teste',{ name:'Pizza teste', nested: { password:'secret', token:'token-secret', email:'private@example.test', safe:'visible' } }]);
    const config = readConfig({ NODE_ENV:'test', APP_ORIGIN:'http://localhost:3002', PORT:'3002', ADMIN_EMAIL:'tech@example.test',
      ADMIN_PASSWORD_HASH:await hashPassword('test-only-password-123'), SESSION_SECRET:'x'.repeat(40),
      ADMIN_READ_DATABASE_URL:'postgresql://bonamassa_admin_reader:ci-reader-only@localhost:5432/bonamassa_admin_test',
      ADMIN_AUDIT_DATABASE_URL:'postgresql://bonamassa_admin_logger:ci-logger-only@localhost:5432/bonamassa_admin_test' });
    db = new Database(config); await db.verify();
    const ctx = () => ({ id:randomUUID(), actor:config.email });
    await t.test('restricted roles cannot access base tables or mutate business records', async () => {
      await assert.rejects(db.reader.query('SELECT "passwordHash" FROM public."User"'));
      await assert.rejects(db.reader.query('SELECT * FROM bonamassa_admin_private."AdminAccessLog"'));
      await assert.rejects(db.reader.query('UPDATE bonamassa_admin."User" SET enabled=false'));
      await assert.rejects(db.logger.query('SELECT * FROM public."User"'));
      await assert.rejects(db.logger.query('UPDATE bonamassa_admin_private."AdminAccessLog" SET actor=\'x\''));
      const catalog = await db.catalog(); assert.equal(catalog.length,16);
      const fields = catalog.find(x => x.name === 'User').fields.map(x => x.name);
      assert.ok(!fields.includes('passwordHash')); assert.ok(!fields.includes('email'));
    });
    await t.test('queries execute, JSON is redacted, filters cannot inject SQL and logs are append-only', async () => {
      const response = await db.run(ctx(), 'SELECT data FROM "Product"');
      assert.equal(response.rows[0][0].nested.password,'[REDACTED]');
      assert.equal(response.rows[0][0].nested.safe,'visible');
      const filtered = await db.browse(ctx(), {table:'User',field:'name',operator:'equals',value:"' OR 1=1; DROP TABLE x; --"});
      assert.equal(filtered.rows.length,0);
      const joined = await db.run(ctx(), 'SELECT u.id, s.name FROM "User" u JOIN "Store" s ON s.id=u."storeId"');
      assert.equal(joined.rows.length,1);
      await assert.rejects(db.run(ctx(), 'SELECT "passwordHash" FROM "User"'));
      await assert.rejects(db.run(ctx(), 'SELECT pg_sleep(1)'));
      const log = await root.query('SELECT event,outcome,"queryTemplate" FROM bonamassa_admin_private."AdminAccessLog"');
      assert.ok(log.rows.some(r => r.outcome === 'completed'));
      assert.ok(log.rows.some(r => r.outcome === 'rejected'));
      await assert.rejects(root.query('DELETE FROM bonamassa_admin_private."AdminAccessLog"'));
      const before = await root.query('SELECT count(*) FROM "User"'); assert.equal(before.rows[0].count,'1');
    });
    await t.test('permissions fail closed if a grant is accidentally widened', async () => {
      await root.query('GRANT SELECT ON public."User" TO bonamassa_admin_reader');
      await assert.rejects(db.verify(), /fora/);
      await root.query('REVOKE SELECT ON public."User" FROM bonamassa_admin_reader');
      await db.verify();
    });
    const created = await createServer(config, db); app = created.server; app.listen(0,'127.0.0.1'); await once(app,'listening');
    const origin = 'http://127.0.0.1:' + app.address().port; config.origin = origin;
    const request = (path, body, cookie, originHeader = origin) => fetch(origin + path, { method: body ? 'POST' : 'GET',
      headers: { ...(body ? {'Content-Type':'application/json', Origin:originHeader} : {}), ...(cookie ? {Cookie:cookie} : {}) }, ...(body ? {body:JSON.stringify(body)} : {}) });
    await t.test('HTTP authentication, origin protection, export and revocation', async () => {
      assert.equal((await request('/api/catalog')).status,401);
      assert.equal((await request('/api/login',{email:config.email,password:'test-only-password-123'},null,'https://evil.test')).status,403);
      const login = await request('/api/login',{email:config.email,password:'test-only-password-123'}); assert.equal(login.status,200);
      const cookie = login.headers.get('set-cookie').split(';')[0]; assert.match(login.headers.get('set-cookie'),/HttpOnly/);
      assert.equal((await request('/api/catalog',null,cookie)).status,200);
      const result = await request('/api/query',{sql:'SELECT id, name FROM "User"'},cookie); assert.equal(result.status,200);
      const exported = await request('/api/export',{sql:'SELECT name FROM "User"'},cookie); assert.equal(exported.status,200); assert.match(await exported.text(),/'=1\+1/);
      assert.equal((await request('/api/logout',{},cookie)).status,200);
      assert.equal((await request('/api/catalog',null,cookie)).status,401);
    });
    await t.test('browser explorer, SQL, audit, JSON details and responsive layout', async () => {
      browser = await chromium.launch({headless:true});
      const page = await browser.newPage({viewport:{width:1440,height:1000}});
      const errors = []; page.on('pageerror', error => errors.push(error.message));
      await page.goto(origin);
      await page.locator('#email').fill(config.email); await page.locator('#password').fill('test-only-password-123');
      await page.locator('#login-button').click();
      await page.locator('#app-view').waitFor({state:'visible'});
      await page.getByRole('button',{name:'▦ User',exact:true}).click();
      await page.locator('#results tbody tr').first().waitFor();
      assert.ok(!(await page.locator('#results thead').textContent()).includes('passwordHash'));
      await page.getByRole('button',{name:'Abrir detalhes do registro'}).first().click();
      await page.locator('#detail').waitFor({state:'visible'});
      await page.locator('#close-detail').click();
      await page.locator('[data-mode="sql"]').click();
      await page.locator('#sql-input').fill('SELECT data FROM "Product"');
      await page.locator('#run-sql').click();
      await page.getByRole('button',{name:'{ } Ver JSON'}).first().click();
      assert.match(await page.locator('#detail-content').textContent(),/REDACTED/);
      await page.locator('#close-detail').click();
      await page.locator('[data-mode="audit"]').click();
      await page.locator('#selected-table').filter({hasText:'AuditTrail'}).waitFor();
      await mkdir('test-results',{recursive:true});
      await page.screenshot({path:'test-results/admin-desktop.png',fullPage:true});
      await page.setViewportSize({width:390,height:844});
      await page.screenshot({path:'test-results/admin-mobile.png',fullPage:true});
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth),false);
      assert.deepEqual(errors,[]);
      await browser.close(); browser = undefined;
    });
    await t.test('audit failure blocks query results', async () => {
      const original = db.logger.query.bind(db.logger);
      db.logger.query = async () => { throw new Error('offline'); };
      await assert.rejects(db.run(ctx(),'SELECT id FROM "User"'), /registrar/);
      db.logger.query = original;
    });
  } finally {
    if (browser) await browser.close();
    if (app) await new Promise(resolve => app.close(resolve));
    if (db) await db.close();
    await root.end();
  }
});
