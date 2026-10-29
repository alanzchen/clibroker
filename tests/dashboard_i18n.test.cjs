const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const i18n = require('../src/clibroker/dashboard/i18n.js');

test('language negotiation follows saved preference, then browser order, then English', () => {
  assert.equal(i18n.detectLanguage(['en-US'], 'zh-CN'), 'zh-CN');
  assert.equal(i18n.detectLanguage(['fr-FR', 'zh-SG', 'en-US']), 'zh-CN');
  assert.equal(i18n.detectLanguage(['zh-TW']), 'zh-CN');
  assert.equal(i18n.detectLanguage(['en-GB', 'zh-CN']), 'en');
  assert.equal(i18n.detectLanguage(['fr-FR'], 'invalid'), 'en');
  assert.equal(i18n.detectLanguage([]), 'en');
});

test('every supported dictionary has the same messages and interpolation fields', () => {
  assert.deepEqual(Object.keys(i18n.messages).sort(), Object.keys(i18n.locales).sort());
  const keys = Object.keys(i18n.messages.en).sort();
  const fields = value => [...value.matchAll(/\{(\w+)\}/g)].map(x => x[1]).sort();
  for (const [locale, messages] of Object.entries(i18n.messages)) {
    assert.deepEqual(Object.keys(messages).sort(), keys, locale);
    for (const key of keys) {
      assert.ok(typeof messages[key] === 'string' && messages[key].length, `${locale}:${key}`);
      assert.deepEqual(fields(messages[key]), fields(i18n.messages.en[key]), `${locale}:${key}`);
    }
  }
});

test('interpolation preserves server-owned strings and unsupported locales use English', () => {
  const tool = '<工具> {name} $&';
  assert.equal(i18n.text('en', 'viewOperationsAria', { tool }), `View operations and permissions for ${tool}`);
  assert.equal(i18n.text('zh-CN', 'viewOperationsAria', { tool }), `查看 ${tool} 的操作与权限`);
  assert.equal(i18n.text('fr', 'connect'), 'Connect');
  assert.throws(() => i18n.text('en', 'missingTranslation'), /Unknown translation key/);
});

test('all static HTML translation references resolve in both languages', () => {
  const html = fs.readFileSync(path.join(__dirname, '../src/clibroker/dashboard/index.html'), 'utf8');
  const keys = [...html.matchAll(/data-i18n(?:-aria-label|-placeholder)?="([^"]+)"/g)].map(x => x[1]);
  assert.ok(keys.length > 50);
  for (const locale of Object.keys(i18n.locales)) {
    for (const key of keys) assert.ok(i18n.text(locale, key).length, `${locale}:${key}`);
  }
});
