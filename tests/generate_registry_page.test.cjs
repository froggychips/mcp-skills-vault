'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const g = require('../mcp-ecosystem-intelligence/scripts/generate_registry_page.cjs');

test('slimEntry keeps public registry fields only', () => {
  const out = g.slimEntry({
    name: 'x',
    category: 'database',
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
    'tier_reason',
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
  // The tier is derived here, and an entry with no evidence cannot be Core no
  // matter what a submitted row claims — the field is not read off the entry.
  assert.equal(out.classification, 'Experimental');
  assert.match(out.tier_reason, /no evidence recorded/);
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

test('committed docs/site/registry.{json,html} match tools_database.json', () => {
  // The public registry is a generated copy of the DB. A DB edit that is not
  // followed by `mcp-vault site-registry` ships the old install commands to
  // everyone who reads the site. Tiers age with the clock, so replay the build
  // at the committed generated_at instead of today.
  const fs = require('node:fs');
  const path = require('node:path');
  const db = JSON.parse(fs.readFileSync(g.DB_PATH, 'utf8'));
  let evals = null;
  try { evals = JSON.parse(fs.readFileSync(g.EVAL_PATH, 'utf8')); } catch { /* none shipped */ }
  const committed = JSON.parse(fs.readFileSync(path.join(g.OUT_DIR, 'registry.json'), 'utf8'));
  const entries = g.buildEntries(db, evals, Date.parse(committed.generated_at));
  const hint = 'docs/site is stale: run `mcp-vault site-registry` and commit both files';
  assert.equal(committed.count, entries.length, hint);
  assert.deepEqual(committed.entries, entries, hint);
  assert.equal(fs.readFileSync(path.join(g.OUT_DIR, 'registry.html'), 'utf8'), g.renderHtml(entries), hint);
});
