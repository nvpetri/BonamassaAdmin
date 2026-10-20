const $ = selector => document.querySelector(selector);
let catalog = [], selected, mode = 'explorer', offset = 0, exportSql = '', currentResult, busy = false;
const presets = {
  orders: 'SELECT "number", "storeId", status, channel, total, "createdAt"\nFROM "Order"\nORDER BY "createdAt" DESC',
  sales: 'SELECT "storeId", channel, count(*) AS pedidos, sum(total) AS total_centavos\nFROM "Order"\nWHERE status = \'DELIVERED\'\nGROUP BY "storeId", channel\nORDER BY total_centavos DESC',
  drivers: 'SELECT id, "storeId", name, enabled, available\nFROM "User"\nWHERE role = \'DRIVER\'\nORDER BY name',
  trail: 'SELECT id, "storeId", "tableName", "recordId", operation, "actorName", "sharedAccount", "changedFields", "createdAt"\nFROM "AuditTrail"\nORDER BY id DESC',
  access: 'SELECT id, actor, event, outcome, tables, "rowCount", "durationMs", "createdAt"\nFROM "AdminAccessLog"\nORDER BY id DESC'
};
function notice(message = '') { $('#notice').hidden = !message; $('#notice').textContent = message; }
async function api(path, body) {
  const response = await fetch(path, { method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin',
    headers: body === undefined ? {} : { 'Content-Type': 'application/json' }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  if (!response.ok) {
    const error = await response.json().catch(() => ({ message: 'Não foi possível acessar o servidor.' }));
    if (response.status === 401) showLogin();
    throw new Error(error.message + (error.requestId ? ' ID: ' + error.requestId : ''));
  }
  return response;
}
function showLogin() {
  $('#app-view').hidden = true; $('#login-view').hidden = false;
  catalog = []; selected = undefined; exportSql = ''; currentResult = undefined;
  $('#actor').textContent = ''; $('#results thead').replaceChildren(); $('#results tbody').replaceChildren();
  $('#sql-input').value = ''; $('#table-list').replaceChildren(); $('#export').disabled = true;
  $('#detail').close(); $('#detail-content').textContent = '';
}
async function showApp(actor) {
  $('#actor').textContent = actor;
  $('#login-view').hidden = true; $('#app-view').hidden = false; $('#password').value = '';
  const response = await (await api('/api/catalog')).json();
  catalog = response.tables;
  $('#table-count').textContent = catalog.length;
  $('#contract').textContent = 'Contrato da API ' + response.apiVersion;
  $('#sql-input').value = presets.orders;
  renderTables();
  setMode('explorer');
  const initial = catalog.find(t => t.name === 'Order') || catalog[0];
  if (initial) await selectTable(initial.name);
}
function renderTables() {
  const search = $('#table-search').value.toLowerCase();
  $('#table-list').replaceChildren();
  for (const table of catalog.filter(t => t.name.toLowerCase().includes(search))) {
    const button = document.createElement('button');
    button.className = 'table-item' + (selected?.name === table.name ? ' active' : '');
    const icon = document.createElement('span'); icon.textContent = '▦'; icon.setAttribute('aria-hidden', 'true');
    button.append(icon, document.createTextNode(table.name));
    button.addEventListener('click', () => selectTable(table.name).catch(e => notice(e.message)));
    $('#table-list').append(button);
  }
}
function setMode(next) {
  mode = next;
  $('#browser-panel').hidden = next === 'sql';
  $('#sql-panel').hidden = next !== 'sql';
  $('#page-title').textContent = ({ explorer: 'Explorador de dados', sql: 'Editor de consultas', audit: 'Histórico de alterações' })[next];
  $('#breadcrumb').textContent = ({ explorer: 'Explorador', sql: 'Editor SQL', audit: 'Auditoria' })[next];
  $('#page-description').textContent = next === 'audit' ? 'Rastreie alterações por tabela, registro, usuário e requisição.' :
    next === 'sql' ? 'Investigue os dados com consultas SELECT nas views disponíveis.' : 'Consulte registros, filtre resultados e confira os detalhes da operação.';
  for (const button of document.querySelectorAll('[data-mode]')) button.classList.toggle('active', button.dataset.mode === next);
  $('#pagination').hidden = next === 'sql' || !currentResult;
  $('#export').disabled = true; exportSql = '';
}
function schema() {
  $('#schema').replaceChildren();
  const tags = document.createElement('div'); tags.className = 'field-tags';
  for (const field of selected.fields) {
    const span = document.createElement('span'); span.textContent = field.name + ' · ' + field.type; tags.append(span);
  }
  $('#schema').append(tags);
  const description = document.createElement('p');
  description.textContent = selected.relations.length ? 'Relações da tabela original: ' + selected.relations.map(r => r.fields.join(' + ') + ' → ' + r.target + '(' + r.targetFields.join(', ') + ')').join(' • ') : 'Esta view não tem relacionamento declarado no contrato.';
  $('#schema').append(description);
  const help = document.createElement('p'); help.className = 'muted';
  help.textContent = 'View de consulta: campos sensíveis são omitidos ou substituídos por [REDACTED]. Os tipos exibidos são os tipos das colunas da view.';
  $('#schema').append(help);
}
async function selectTable(name, preserveMode = false) {
  if (busy) return;
  selected = catalog.find(t => t.name === name); if (!selected) return;
  if (!preserveMode) setMode('explorer');
  offset = 0; $('#filter-value').value = '';
  for (const select of [$('#filter-field'), $('#sort-field')]) {
    select.replaceChildren();
    for (const field of selected.fields) {
      const option = document.createElement('option'); option.value = field.name; option.textContent = field.name; select.append(option);
    }
  }
  $('#sort-field').value = selected.fields.some(f => f.name === 'id') ? 'id' : selected.fields[0].name;
  $('#selected-table').textContent = selected.name; schema(); renderTables();
  await browse();
}
function setBusy(value) {
  busy = value;
  $('#run-sql').disabled = value;
  $('#filter-form button').disabled = value;
  $('#export').disabled = value || !exportSql;
  $('#previous').disabled = value || offset === 0;
  $('#next').disabled = value || !currentResult?.truncated;
  if (value) { $('#result-meta').textContent = 'Consultando…'; notice(); }
}
async function browse() {
  if (!selected || busy) return;
  setBusy(true);
  try {
    const data = await (await api('/api/browse', { table: selected.name, offset, field: $('#filter-field').value, operator: $('#filter-operator').value,
      value: $('#filter-value').value, sort: $('#sort-field').value, direction: $('#sort-direction').value })).json();
    exportSql = data.exportSql; renderResult(data);
  } catch (e) { exportSql = ''; notice(e.message); }
  finally { setBusy(false); }
}
async function runSQL() {
  if (busy) return;
  const sql = $('#sql-input').value; setBusy(true);
  try {
    const data = await (await api('/api/query', { sql })).json();
    exportSql = sql; renderResult(data);
  } catch (e) { exportSql = ''; notice(e.message); }
  finally { setBusy(false); }
}
function showDetail(title, value) {
  $('#detail-title').textContent = title;
  $('#detail-content').textContent = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  $('#detail').showModal();
}
function renderResult(data) {
  currentResult = data;
  $('#empty').hidden = data.rows.length > 0;
  if (!data.rows.length) {
    $('#empty h3').textContent = 'Nenhum registro encontrado';
    $('#empty p').textContent = 'Revise os filtros ou escolha outra tabela.';
  }
  $('#result-scroll').hidden = !data.rows.length;
  $('#results thead').replaceChildren(); $('#results tbody').replaceChildren();
  const head = document.createElement('tr');
  for (const column of data.columns) { const th = document.createElement('th'); th.scope = 'col'; th.textContent = column; head.append(th); }
  const th = document.createElement('th'); th.scope = 'col'; th.textContent = 'Detalhes'; head.append(th);
  $('#results thead').append(head);
  for (const row of data.rows) {
    const tr = document.createElement('tr');
    row.forEach((value, index) => {
      const td = document.createElement('td');
      if (value === null) { td.textContent = 'NULL'; td.className = 'muted'; }
      else if (typeof value === 'object') {
        const button = document.createElement('button'); button.textContent = Array.isArray(value) ? '[ ] ' + value.length + ' itens' : '{ } Ver JSON';
        button.addEventListener('click', () => showDetail(data.columns[index], value)); td.append(button);
      } else { td.textContent = String(value); td.title = String(value).slice(0, 1000); }
      tr.append(td);
    });
    const action = document.createElement('td'), button = document.createElement('button');
    button.textContent = 'Abrir ↗'; button.setAttribute('aria-label', 'Abrir detalhes do registro');
    button.addEventListener('click', () => {
      const record = {};
      data.columns.forEach((key, i) => record[key + (data.columns.indexOf(key) !== i ? ' [' + (i + 1) + ']' : '')] = row[i]);
      showDetail('Detalhes do registro', record);
    });
    action.append(button); tr.append(action); $('#results tbody').append(tr);
  }
  $('#result-meta').textContent = data.rows.length + ' registros · ' + data.durationMs + ' ms';
  $('#result-note').textContent = data.truncated ? mode === 'sql' ? 'Limite de 200 linhas. Refine a consulta para acessar outros registros.' : 'Há mais registros disponíveis na próxima página.' : 'Fim dos resultados desta consulta.';
  $('#pagination').hidden = mode === 'sql';
  $('#page-number').textContent = 'Página ' + (Math.floor(offset / 100) + 1);
}
$('#login-form').addEventListener('submit', async event => {
  event.preventDefault(); $('#login-button').disabled = true; $('#login-error').textContent = '';
  try {
    const session = await (await api('/api/login', { email: $('#email').value, password: $('#password').value })).json();
    await showApp(session.actor);
  } catch (e) { $('#login-error').textContent = e.message; } finally { $('#login-button').disabled = false; }
});
$('#logout').addEventListener('click', async () => { try { await api('/api/logout', {}); showLogin(); } catch (e) { notice(e.message); } });
$('#table-search').addEventListener('input', renderTables);
$('#filter-form').addEventListener('submit', event => { event.preventDefault(); offset = 0; browse(); });
$('#toggle-schema').addEventListener('click', () => { $('#schema').hidden = !$('#schema').hidden; $('#toggle-schema').setAttribute('aria-expanded', String(!$('#schema').hidden)); });
$('#previous').addEventListener('click', () => { offset = Math.max(0, offset - 100); browse(); });
$('#next').addEventListener('click', () => { offset += 100; browse(); });
$('#run-sql').addEventListener('click', runSQL);
$('#sql-input').addEventListener('keydown', event => { if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') { event.preventDefault(); runSQL(); } });
for (const button of document.querySelectorAll('[data-preset]')) button.addEventListener('click', () => { $('#sql-input').value = presets[button.dataset.preset]; });
for (const button of document.querySelectorAll('[data-mode]')) button.addEventListener('click', async () => {
  if (busy) return;
  setMode(button.dataset.mode);
  if (mode === 'audit') await selectTable('AuditTrail', true).catch(e => notice(e.message));
});
$('#close-detail').addEventListener('click', () => $('#detail').close());
$('#export').addEventListener('click', async () => {
  if (!exportSql || busy) return;
  setBusy(true);
  try {
    const response = await api('/api/export', { sql: exportSql });
    const href = URL.createObjectURL(await response.blob());
    const link = document.createElement('a'); link.href = href; link.download = 'bonamassa-consulta.csv'; link.click();
    setTimeout(() => URL.revokeObjectURL(href), 1000);
    notice('CSV gerado. A exportação reexecuta a consulta e pode refletir atualizações recentes; limite de 200 linhas.');
  } catch (e) { notice(e.message); } finally { setBusy(false); }
});
api('/api/session').then(r => r.json()).then(s => showApp(s.actor)).catch(e => {
  if (!$('#app-view').hidden) notice(e.message);
});
