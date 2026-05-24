'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const g = require('../mcp-ecosystem-intelligence/scripts/generate_registry_page.cjs');

test('slimEntry keeps public registry fields only', () => {
  const out = g.slimEntry({
    name: 'x',
    category: 'database',
    classification: 'Core',
    trust: 'verified',
    license: 'MIT',
    health_score: 100,
    est_tools_count: 3,
    install_cmd: 'npx -y x@1.0.0',
    source_url: 'https://github.com/a/b',
    notes: 'internal audit trail',
  });
  assert.deepEqual(Object.keys(out).sort(), [
    'category',
    'classification',
    'est_tools_count',
    'health_score',
    'install_cmd',
    'license',
    'name',
    'source_url',
    'trust',
  ].sort());
});

test('renderHtml includes filters and escaped install command', () => {
  const html = g.renderHtml([{
    name: 'x<y',
    category: 'database',
    classification: 'Core',
    trust: 'verified',
    license: 'MIT',
    health_score: 100,
    est_tools_count: 3,
    install_cmd: 'npx -y x@1.0.0 --flag "<bad>"',
    source_url: 'https://github.com/a/b',
  }]);
  assert.match(html, /id="q"/);
  assert.match(html, /x&lt;y/);
  assert.match(html, /&lt;bad&gt;/);
});
