const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const i18n = require('../src/clibroker/dashboard/i18n.js');
const source = fs.readFileSync(require.resolve('../src/clibroker/dashboard/app.js'), 'utf8');

// Exercise the actual shipped state machine with controllable HTTP responses.
function dashboard(fetcher = async () => ({ ok: true, json: async () => ({ agents: [], requests: [], activity: [] }) })) {
  const nodes = new Map();
  function node() {
    return { value: '', checked: false, dataset: {}, children: [], attributes: {}, classList: { toggle() {} },
      append(...items) { this.children.push(...items); }, replaceChildren(...items) { this.children = items; },
      addEventListener() {}, setAttribute(name, value) { this.attributes[name] = value; },
      querySelectorAll() { return []; }, close() { this.open = false; }, showModal() { this.open = true; },
    };
  }
  function field(id) { if (!nodes.has(id)) nodes.set(id, node()); return nodes.get(id); }
  const context = vm.createContext({
    URL, AbortController, setTimeout() { return 1; }, clearTimeout() {}, fetch: fetcher,
    window: { DashboardI18n: i18n, location: { href: 'https://example.com/broker/dashboard/' } },
    localStorage: { getItem() { return null; } }, navigator: { languages: ['en'] },
    document: { currentScript: { src: 'https://example.com/broker/dashboard/app.js' }, documentElement: {},
      getElementById: field, querySelectorAll() { return []; }, createElement: node,
    },
  });
  vm.runInContext(source, context);
  return { context, field, evaluate(code) { return vm.runInContext(code, context); } };
}
const setup = `token = 'test-only'; config = {client_name:'owner', tools:[], control:{enabled:true,role:'owner'}};`;
const response = value => ({ ok: true, status: 200, json: async () => value });

test('authenticated URLs reject cross-origin and deployment-prefix escapes', () => {
  const app = dashboard();
  assert.equal(app.evaluate(`apiUrl('/files/tool/share/file').href`), 'https://example.com/broker/files/tool/share/file');
  for (const endpoint of ['https://evil.example/files/x', '../files/x', 'https://example.com/files/x', 'https://user:pass@example.com/broker/files/x']) {
    assert.throws(() => app.context.apiUrl(endpoint), /invalidEndpoint/);
  }
});

test('late control responses cannot restore data after disconnect', async () => {
  let resolve;
  const app = dashboard(() => new Promise(done => { resolve = done; }));
  app.evaluate(setup);
  const pending = app.context.refreshControl();
  app.evaluate(`generation += 1; resetControl(); token=''; config=null; render();`);
  resolve(response({ agents: [{ name: 'private agent', rules: [] }], requests: [], activity: [] }));
  await pending;
  assert.equal(app.evaluate('controlData'), null);
  assert.equal(app.field('control-section').hidden, true);
});

test('a permission change invalidates an older in-flight snapshot', async () => {
  let resolveOld;
  let gets = 0;
  const fresh = { agents: [{ name: 'worker', paused: true, rules: [] }], requests: [], activity: [] };
  const app = dashboard(async (_url, options) => {
    if (options.method === 'PATCH') return response({ name: 'worker', paused: true });
    if (++gets === 1) return new Promise(done => { resolveOld = done; });
    return response(fresh);
  });
  app.evaluate(setup);
  const old = app.context.refreshControl();
  await app.context.changeControl('control/agents/worker', { paused: true }, 'PATCH');
  resolveOld(response({ agents: [{ name: 'worker', paused: false, rules: [] }], requests: [], activity: [] }));
  await old;
  assert.equal(app.evaluate('controlData.agents[0].paused'), true);
});

test('owner credentials never enable copying an assistant endpoint', () => {
  const app = dashboard();
  app.evaluate(setup + 'render();');
  assert.equal(app.field('copy-mcp').disabled, true);
  app.evaluate(`config.control.role='agent'; render();`);
  assert.equal(app.field('copy-mcp').disabled, false);
});

test('an owner approval can only be submitted once while awaiting the server', async () => {
  let resolve;
  let posts = 0;
  const item = { id: 'req', client: 'worker', tool: 'echo', argv: ['send'], rule_id: 'send', state: 'pending', created_at: '2026-01-01T00:00:00Z' };
  const app = dashboard(async (_url, options) => {
    if (options.method === 'POST') { posts += 1; return new Promise(done => { resolve = done; }); }
    return response({ agents: [], requests: [], activity: [] });
  });
  app.evaluate(setup + `currentRequest=${JSON.stringify(item)};`);
  const first = app.context.decideRequest('approve');
  await app.context.decideRequest('approve');
  assert.equal(posts, 1);
  resolve(response({ ...item, state: 'succeeded', result: { ok: true } }));
  await first;
  assert.equal(app.evaluate('currentRequest.state'), 'succeeded');
});

test('history filters combine a case-insensitive identity search with outcome', () => {
  const app = dashboard();
  const rows = [{ client: 'Claude', tool: 'mail', rule_id: 'send', state: 'pending' }, { client: 'Claude', tool: 'mail', rule_id: 'read', state: 'succeeded' }, { client: 'Other', tool: 'files', state: 'pending' }];
  const filtered = app.context.filterHistory(rows, ' CLAUDE ', 'pending');
  assert.deepEqual(Array.from(filtered), [rows[0]]);
});

test('history polling preserves a detailed result already opened by the user', async () => {
  const item = { id: 'req', client: 'worker', tool: 'echo', argv: ['read'], rule_id: 'read', state: 'succeeded', created_at: '2026-01-01T00:00:00Z' };
  const app = dashboard(async () => response({ agents: [], requests: [], activity: [{ ...item, result: null }] }));
  app.evaluate(setup + `currentRequest=${JSON.stringify({ ...item, result: { ok: true, stdout: 'kept' } })};`);
  await app.context.refreshControl();
  assert.equal(app.evaluate('currentRequest.result.stdout'), 'kept');
});

test('a slow polling detail response cannot replace a newly selected request', async () => {
  let resolveDetail;
  const initial = { id: 'first', client: 'worker', tool: 'echo', argv: ['read'], rule_id: 'read', state: 'pending' };
  const app = dashboard(async (url) => {
    if (url.pathname.endsWith('/requests/first')) return new Promise(done => { resolveDetail = done; });
    return response({ agents: [], requests: [], activity: [{ ...initial, state: 'succeeded', result: null }] });
  });
  app.evaluate(setup + `currentRequest=${JSON.stringify(initial)};`);
  const pending = app.context.refreshControl();
  while (!resolveDetail) await Promise.resolve();
  app.evaluate(`requestGeneration += 1; currentRequest={id:'second', tool:'echo', state:'pending'};`);
  resolveDetail(response({ ...initial, state: 'succeeded', result: { stdout: 'old' } }));
  await pending;
  assert.equal(app.evaluate('currentRequest.id'), 'second');
});

test('unchanged polling preserves agent controls and their keyboard focus targets', async () => {
  const data = { agents: [{ name: 'worker', rules: [{ id: 'read', tool: 'echo', decision: 'allow' }] }], requests: [], activity: [] };
  const app = dashboard(async () => response(data));
  app.evaluate(setup);
  await app.context.refreshControl();
  const originalCard = app.field('agents').children[0];
  await app.context.refreshControl();
  assert.equal(app.field('agents').children[0], originalCard);
});

test('owners with no command grants still see friendly approval labels', () => {
  const app = dashboard();
  app.evaluate(setup + `controlData={agents:[{name:'worker',rules:[{id:'send',title:'Send mail'}]}]};`);
  assert.equal(app.context.visibleRule('send', 'worker').title, 'Send mail');
});
