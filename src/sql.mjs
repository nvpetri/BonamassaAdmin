import parser from 'pgsql-ast-parser';
import { HttpError } from './security.mjs';
const { parse, toSql } = parser;
export const tables = ['Store', 'User', 'Product', 'ProductImage', 'Promotion', 'Quote', 'Order', 'OrderEvent', 'Session', 'VerificationCode', 'StaffInvitation', 'Idempotency', 'RateBucket', 'Audit', 'AuditTrail', 'AdminAccessLog'];
const functions = new Set(['count', 'sum', 'avg', 'min', 'max', 'round', 'abs', 'lower', 'upper', 'length', 'coalesce', 'nullif', 'date_trunc', 'date_part', 'to_char']);
const nodeTypes = new Set(['select', 'table', 'statement', 'ref', 'call', 'binary', 'unary', 'integer', 'numeric', 'string', 'boolean', 'null', 'cast', 'member', 'case', 'list', 'keyword', 'ternary',
  'INNER JOIN', 'LEFT JOIN', 'RIGHT JOIN', 'FULL JOIN', 'CROSS JOIN']);
const operators = new Set(['=', '!=', '<>', '>', '>=', '<', '<=', 'AND', 'OR', 'IN', 'NOT IN', 'LIKE', 'NOT LIKE', 'ILIKE', 'NOT ILIKE', '+', '-', '*', '/', '%', '||', 'NOT', 'IS NULL', 'IS NOT NULL', 'IS TRUE', 'IS FALSE', 'IS NOT TRUE', 'IS NOT FALSE', 'BETWEEN', 'NOT BETWEEN', '->', '->>']);
const castTypes = new Set(['text', 'int', 'integer', 'bigint', 'numeric', 'decimal', 'boolean', 'date', 'timestamp', 'timestamptz', 'uuid']);
const forbidden = () => { throw new HttpError(400, 'SQL_NOT_ALLOWED', 'Use um único SELECT nas views disponíveis, sem CTE, funções externas ou comandos de escrita.'); };
export function validateSQL(sql) {
  if (typeof sql !== 'string' || !sql.trim() || sql.length > 10_000) forbidden();
  let statements;
  try { statements = parse(sql); } catch { forbidden(); }
  if (statements.length !== 1 || statements[0].type !== 'select') forbidden();
  const used = new Set();
  let count = 0;
  function visit(node, depth = 0) {
    if (node == null || typeof node !== 'object') return;
    if (depth > 35 || ++count > 1000) forbidden();
    if (Array.isArray(node)) { for (const child of node) visit(child, depth + 1); return; }
    if (node.type && !nodeTypes.has(node.type)) forbidden();
    if (node.type === 'select' && (node.for || node.skip || node.into)) forbidden();
    if (node.type === 'table') {
      if (node.name.schema && node.name.schema !== 'bonamassa_admin') forbidden();
      if (!tables.includes(node.name.name)) forbidden();
      used.add(node.name.name);
      node.name.schema = 'bonamassa_admin';
    }
    if (node.type === 'call') {
      if (node.function.schema || !functions.has(node.function.name.toLowerCase())) forbidden();
      // coalesce/nullif are SQL constructs rather than pg_catalog functions.
      if (!['coalesce', 'nullif'].includes(node.function.name.toLowerCase())) node.function.schema = 'pg_catalog';
      if (node.over || node.withinGroup) forbidden();
    }
    if (node.type === 'ref' && node.table?.schema && node.table.schema !== 'bonamassa_admin') forbidden();
    if (node.opSchema || (node.op && !operators.has(node.op))) forbidden();
    if (node.type === 'keyword' && !['current_date', 'current_timestamp'].includes(node.keyword)) forbidden();
    if (node.type === 'cast') {
      if (node.to.schema || node.to.kind || !castTypes.has(node.to.name.toLowerCase())) forbidden();
      node.to.name = ({ int: 'int4', integer: 'int4', bigint: 'int8', boolean: 'bool', decimal: 'numeric' })[node.to.name.toLowerCase()] || node.to.name.toLowerCase();
      node.to.schema = 'pg_catalog';
    }
    for (const [key, value] of Object.entries(node)) {
      if (key !== '_location') visit(value, depth + 1);
    }
  }
  visit(statements[0]);
  // Execute only regenerated SQL, never the untrusted input string.
  const query = toSql.statement(statements[0]);
  const template = structuredClone(statements[0]);
  function redact(node) {
    if (!node || typeof node !== 'object') return;
    if (['string', 'integer', 'numeric', 'boolean'].includes(node.type)) {
      if (node.type === 'string') node.value = '[VALUE]';
      else if (node.type === 'boolean') node.value = false;
      else node.value = 0;
    }
    for (const value of Object.values(node)) redact(value);
  }
  redact(template);
  return { query, template: toSql.statement(template), tables: [...used] };
}
export const quote = name => '"' + name.replaceAll('"', '""') + '"';

export const literalSQL = value => toSql.expr({ type: 'string', value });
