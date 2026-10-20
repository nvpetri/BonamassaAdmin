import pg from 'pg';
import { validateSQL, tables, quote, literalSQL } from './sql.mjs';
import { digest, HttpError } from './security.mjs';
import { relations } from './relations.mjs';
const { Pool } = pg;
const error = () => new HttpError(503, 'DATABASE_UNAVAILABLE', 'Banco indisponível. Consulte os logs técnicos pelo identificador da requisição.');
export class Database {
  constructor(config) {
    this.reader = new Pool({ connectionString: config.readUrl, max: 2, connectionTimeoutMillis: 30_000, idleTimeoutMillis: 10_000, application_name: 'BonamassaAdmin/read' });
    this.logger = new Pool({ connectionString: config.auditUrl, max: 2, connectionTimeoutMillis: 30_000, idleTimeoutMillis: 10_000, application_name: 'BonamassaAdmin/audit' });
    this.reader.on('error', () => console.error('PostgreSQL read connection lost'));
    this.logger.on('error', () => console.error('PostgreSQL audit connection lost'));
    this.active = 0;
  }
  async close() { await Promise.all([this.reader.end(), this.logger.end()]); }
  async assertRole(pool, expected) {
    const { rows: [role] } = await pool.query(`SELECT current_user AS name, r.rolsuper, r.rolcreaterole, r.rolcreatedb, r.rolbypassrls, r.rolreplication,
      EXISTS(SELECT FROM pg_auth_members WHERE member = r.oid) AS membership
      FROM pg_roles r WHERE r.rolname = current_user`);
    if (role.name !== expected || role.rolsuper || role.rolcreaterole || role.rolcreatedb || role.rolbypassrls || role.rolreplication || role.membership)
      throw new Error('O Admin exige papéis restritos, sem associações nem poderes administrativos.');
    const { rows } = await pool.query(`SELECT n.nspname, c.relname,
      has_any_column_privilege(current_user, c.oid, 'SELECT') AS readable,
      has_any_column_privilege(current_user, c.oid, 'UPDATE,REFERENCES') OR has_table_privilege(current_user, c.oid, 'DELETE,TRUNCATE,TRIGGER') AS bad_mutation,
      has_any_column_privilege(current_user, c.oid, 'INSERT,UPDATE,REFERENCES') OR has_table_privilege(current_user, c.oid, 'DELETE,TRUNCATE,TRIGGER') AS writable
      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE c.relkind IN ('r','p','v','m','f') AND n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%'`);
    for (const row of rows) {
      if (expected === 'bonamassa_admin_reader') {
        if (row.writable || (row.readable && (row.nspname !== 'bonamassa_admin' || !tables.includes(row.relname))))
          throw new Error('Leitor possui acesso fora das views autorizadas.');
      } else if (row.bad_mutation || row.readable || (row.writable && !(row.nspname === 'bonamassa_admin_private' && row.relname === 'AdminAccessLog'))) {
        throw new Error('Logger possui acesso fora do log técnico.');
      }
    }
    const { rows: [schema] } = await pool.query(`SELECT EXISTS (SELECT FROM pg_namespace WHERE nspname NOT LIKE 'pg_%' AND has_schema_privilege(current_user, oid, 'CREATE')) AS writable`);
    if (schema.writable) throw new Error('O papel técnico não pode criar objetos.');
  }
  async verify() {
    await this.assertRole(this.reader, 'bonamassa_admin_reader');
    await this.assertRole(this.logger, 'bonamassa_admin_logger');
    const catalog = await this.catalog();
    if (catalog.length !== tables.length) throw new Error('Execute db/001_admin.sql para disponibilizar todas as views.');
  }
  async log(context, event, outcome, extra = {}) {
    try {
      await this.logger.query(`INSERT INTO bonamassa_admin_private."AdminAccessLog"
        ("requestId", actor, event, outcome, fingerprint, "queryTemplate", tables, "rowCount", "durationMs", "peerHash")
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [context.id, context.actor, event, outcome, extra.fingerprint || null, extra.template || null, extra.tables || [], extra.rowCount ?? null, extra.durationMs ?? null, context.peerHash || null]);
    } catch { throw new HttpError(503, 'AUDIT_UNAVAILABLE', 'Não foi possível registrar a operação. Acesso temporariamente indisponível.'); }
  }
  async catalog() {
    const { rows } = await this.reader.query(`SELECT table_name AS table, column_name AS name, data_type AS type, ordinal_position AS position
      FROM information_schema.columns WHERE table_schema = 'bonamassa_admin' ORDER BY table_name, ordinal_position`);
    return tables.filter(name => rows.some(r => r.table === name)).map(name => ({
      name, fields: rows.filter(r => r.table === name).map(({ name, type }) => ({ name, type })),
      relations: relations.filter(r => r[0] === name).map(([,fields,target,targetFields]) => ({ fields, target, targetFields }))
    }));
  }
  async run(context, input, event = 'query') {
    const fingerprint = digest(typeof input === 'string' ? input : '');
    let validated;
    try { validated = validateSQL(input); }
    catch (e) { await this.log(context, event, 'rejected', { fingerprint }); throw e; }
    return this.execute(context, validated, fingerprint, event);
  }
  async execute(context, validated, fingerprint, event, values = []) {
    if (this.active >= 2) throw new HttpError(429, 'BUSY', 'Há duas consultas em execução. Aguarde e tente novamente.');
    this.active++;
    const started = Date.now();
    let client;
    try {
      await this.log(context, event, 'started', { ...validated, fingerprint });
      client = await this.reader.connect();
      await client.query('BEGIN READ ONLY');
      await client.query("SET LOCAL search_path = pg_catalog, bonamassa_admin");
      await client.query("SET LOCAL statement_timeout = '5s'");
      await client.query("SET LOCAL lock_timeout = '1s'");
      await client.query("SET LOCAL work_mem = '4MB'");
      const result = await client.query({ text: 'SELECT * FROM (' + validated.query.replace(/;\s*$/, '') + ') AS admin_result LIMIT 201', values, rowMode: 'array' });
      await client.query('ROLLBACK');
      const rows = result.rows.slice(0, 200);
      const payload = { columns: result.fields.map(f => f.name), rows, truncated: result.rows.length > 200, durationMs: Date.now() - started };
      if (Buffer.byteLength(JSON.stringify(payload)) > 2 * 1024 * 1024)
        throw new HttpError(413, 'RESULT_TOO_LARGE', 'Resultado acima de 2 MB. Selecione menos campos ou restrinja os filtros.');
      await this.log(context, event, 'completed', { ...validated, fingerprint, rowCount: rows.length, durationMs: payload.durationMs });
      return payload;
    } catch (e) {
      if (client) await client.query('ROLLBACK').catch(() => {});
      if (e.code !== 'AUDIT_UNAVAILABLE') await this.log(context, event, 'failed', { ...validated, fingerprint, durationMs: Date.now() - started });
      if (e instanceof HttpError) throw e;
      // Never return PostgreSQL DETAIL or user input (can contain sensitive values).
      throw new HttpError(400, e.code === '57014' ? 'QUERY_TIMEOUT' : 'QUERY_FAILED',
        e.code === '57014' ? 'A consulta excedeu 5 segundos. Reduza o período ou adicione filtros.' : 'Consulta inválida. Confira nomes, tipos e filtros; use aspas duplas nos campos e tabelas.');
    } finally { if (client) client.release(); this.active--; }
  }
  async browse(context, body) {
    const catalog = await this.catalog();
    const table = catalog.find(t => t.name === body.table);
    if (!table) throw new HttpError(400, 'INVALID_TABLE', 'Tabela inválida.');
    const offset = Number(body.offset || 0);
    if (!Number.isInteger(offset) || offset < 0 || offset > 100_000) throw new HttpError(400, 'INVALID_OFFSET', 'Paginação inválida.');
    const field = table.fields.find(f => f.name === body.field);
    const sort = table.fields.find(f => f.name === body.sort) || table.fields.find(f => f.name === 'id') || table.fields[0];
    const order = body.direction === 'ASC' ? 'ASC' : 'DESC';
    const value = body.value == null ? '' : String(body.value);
    if (value.length > 200) throw new HttpError(400, 'INVALID_FILTER', 'Filtro muito longo.');
    const where = value && field ? ' WHERE CAST(' + quote(field.name) + ' AS text) ' + (body.operator === 'equals' ? '= $1' : 'ILIKE $1') : '';
    const parameter = body.operator === 'equals' ? value : '%' + value.replaceAll('\\', '\\\\').replaceAll('%', '\\%').replaceAll('_', '\\_') + '%';
    const sql = 'SELECT * FROM bonamassa_admin.' + quote(table.name) + where +
      ' ORDER BY ' + quote(sort.name) + ' ' + order + ', ' + table.fields.map(f => quote(f.name) + '::text').join(', ') + ' LIMIT 101 OFFSET ' + offset;
    const result = await this.execute(context, { query: sql, template: sql, tables: [table.name] }, digest(JSON.stringify([sql, parameter])), 'browse', where ? [parameter] : []);
    return { ...result, rows: result.rows.slice(0, 100), truncated: result.rows.length > 100, offset, pageSize: 100, exportSql: where ? sql.replace(' LIMIT 101 OFFSET ', ' LIMIT 100 OFFSET ').replace('$1', () => literalSQL(parameter)) : sql.replace(' LIMIT 101 OFFSET ', ' LIMIT 100 OFFSET ') };
  }
}
