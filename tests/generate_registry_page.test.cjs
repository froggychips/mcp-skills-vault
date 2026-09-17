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
    'evidence',
    'health_score',
    'install_cmd',
    'license',
    'name',
    'smoke',
    'source_url',
    'trust',
  ].sort());
  // The audit trail in `notes` stays internal.
  assert.equal(out.notes, undefined);
  // Nothing was checked for this entry, and the page says so rather than
  // implying a clean result.
  assert.equal(out.evidence, null);
  assert.equal(out.smoke, null);
});

test('slimEntry publishes evidence with its dates, and nothing else from it', () => {
  const out = g.slimEntry(
    { name: 'x', trust: 'verified' },
    {
      artifact_id: 'npm:x@1.0.0',
      dimensions: {
        artifact:   { status: 'verified', checked_at: '2026-09-17', method: 'deep-hash' },
        advisories: { status: 'clean',    checked_at: '2026-09-10' },
      },
    },
    { name: 'x', status: 'pass', tool_count: 12, checked_at: '2026-09-10T00:00:00.000Z', stderr_tail: 'secret-ish path' },
  );
  assert.deepEqual(out.evidence, {
    artifact:   { status: 'verified', checked_at: '2026-09-17' },
    advisories: { status: 'clean',    checked_at: '2026-09-10' },
  });
  // The method is internal detail; the date is the part a reader needs.
  assert.equal(out.evidence.artifact.method, undefined);
  assert.deepEqual(out.smoke, { status: 'pass', tools: 12, checked_at: '2026-09-10' });
  // A stderr tail can carry paths and tokens from a failing server.
  assert.equal(JSON.stringify(out).includes('secret-ish'), false);
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
