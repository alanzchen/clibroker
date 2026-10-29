const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const i18n = require('../src/clibroker/dashboard/i18n.js');

const source = fs.readFileSync(path.join(__dirname, '../src/clibroker/dashboard/app.js'), 'utf8');

// Run the shipped client, with only the DOM methods needed by its initial render.
// Argument construction then reads the same input nodes as the browser client.
function dashboard(pageUrl = 'https://example.com/dashboard/') {
  const nodes = new Map();
  function node() {
    return {
      value: '', checked: false, dataset: {}, classList: { toggle() {} },
      append() {}, replaceChildren() {}, addEventListener() {}, setAttribute() {},
      querySelectorAll() { return []; },
    };
  }
  function field(id) {
    if (!nodes.has(id)) nodes.set(id, node());
    return nodes.get(id);
  }
  const context = vm.createContext({
    URL,
    window: { DashboardI18n: i18n },
    localStorage: { getItem() { return null; } },
    navigator: { languages: ['en'] },
    document: {
      currentScript: { src: new URL('./app.js', pageUrl).href },
      documentElement: {},
      getElementById: field,
      querySelectorAll() { return []; },
      createElement: node,
    },
  });
  vm.runInContext(source, context, { filename: 'dashboard/app.js' });
  return {
    field,
    apiUrl(endpoint) { return vm.runInContext(`new URL(${JSON.stringify(endpoint)}, apiBase).href`, context); },
    argv(rule) { return Array.from(context.buildArgv(rule)); },
  };
}

function rule(overrides = {}) {
  return { command: ['read'], flags: [], standalone_flags: [], positionals: [], ...overrides };
}

test('API requests preserve the deployment prefix from either dashboard entry URL', () => {
  for (const prefix of ['', '/broker']) {
    for (const entry of ['', 'index.html']) {
      const app = dashboard(`https://example.com${prefix}/dashboard/${entry}`);
      assert.equal(app.apiUrl('client-config'), `https://example.com${prefix}/client-config`);
      assert.equal(app.apiUrl('execute'), `https://example.com${prefix}/execute`);
      assert.equal(app.apiUrl('mcp/token-slug/'), `https://example.com${prefix}/mcp/token-slug/`);
    }
  }
});

test('dash-prefixed scalar positionals follow the configured and extra options', () => {
  const app = dashboard();
  app.field('pos-0').value = '-report.txt';
  app.field('flag-0').value = '-json';
  app.field('switch-0').checked = true;
  app.field('extra-args').value = '["--account", "work"]';
  assert.deepEqual(app.argv(rule({
    flags: ['--format', '--account'],
    standalone_flags: ['--verbose'],
    positionals: [{ name: 'filename' }],
  })), ['read', '--format', '-json', '--verbose', '--account', 'work', '--', '-report.txt']);
});

test('dash-prefixed variadic values remain literal after all fixed positionals', () => {
  const app = dashboard();
  app.field('pos-0').value = 'inbox';
  app.field('pos-1').value = '["report.txt", "-notes.txt"]';
  assert.deepEqual(app.argv(rule({
    positionals: [{ name: 'folder' }, { name: 'filenames', variadic: true }],
  })), ['read', '--', 'inbox', 'report.txt', '-notes.txt']);
});

test('dash-prefixed flag values do not introduce an end-of-options marker', () => {
  const app = dashboard();
  app.field('flag-0').value = '-json';
  app.field('pos-0').value = 'report.txt';
  assert.deepEqual(app.argv(rule({
    flags: ['--format'], positionals: [{ name: 'filename' }],
  })), ['read', '--format', '-json', 'report.txt']);
});

test('raw operation arguments keep their exact order and existing separator', () => {
  const app = dashboard();
  app.field('command-0').value = 'events';
  app.field('extra-args').value = '["list", "--from", "-1", "--", "--literal"]';
  assert.deepEqual(app.argv(rule({ command: ['*'], allow_any_args: true })),
    ['events', 'list', '--from', '-1', '--', '--literal']);
});

test('extra positional values follow generated variadic values', () => {
  for (const first of ['first.txt', '-first.txt']) {
    const app = dashboard();
    app.field('pos-0').value = JSON.stringify([first]);
    app.field('extra-args').value = '["second.txt", "--format", "-json", "third.txt"]';
    const expected = first.startsWith('-')
      ? ['read', '--format', '-json', '--', first, 'second.txt', 'third.txt']
      : ['read', first, 'second.txt', '--format', '-json', 'third.txt'];
    assert.deepEqual(app.argv(rule({
      flags: ['--format'], positionals: [{ name: 'filenames', variadic: true }],
    })), expected);
  }
});

test('unknown extra options remain options for server policy validation', () => {
  const app = dashboard();
  app.field('pos-0').value = '-report.txt';
  app.field('extra-args').value = '["--unapproved", "--unapproved=secret"]';
  assert.deepEqual(app.argv(rule({ positionals: [{ name: 'filename' }] })),
    ['read', '--unapproved', '--unapproved=secret', '--', '-report.txt']);
});

test('an explicit extra separator keeps its following options literal', () => {
  const app = dashboard();
  app.field('pos-0').value = '["-first.txt"]';
  app.field('extra-args').value = '["--format=json", "--", "--literal.txt", "second.txt"]';
  assert.deepEqual(app.argv(rule({
    flags: ['--format'], positionals: [{ name: 'filenames', variadic: true }],
  })), ['read', '--format=json', '--', '-first.txt', '--literal.txt', 'second.txt']);
});
