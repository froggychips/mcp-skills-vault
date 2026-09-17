'use strict';
const { test } = require('node:test');
const assert   = require('node:assert/strict');
const r = require('../mcp-ecosystem-intelligence/scripts/lib/report.cjs');

const resultsFixture = [
  {
    tool: { name: 'ok-entry', version: '1.0.0', pkg_integrity: 'sha512-x', trust: 'verified', install_cmd: 'npx -y ok-entry@1.0.0' },
    status: 'OK', msg: 'ok-entry@1.0.0', lines: [['NOTE', 'npm declares no license']], failures: 0,
  },
  {
    tool: { name: 'bad-entry', version: '2.0.0', pkg_integrity: 'sha512-y', trust: 'verified', install_cmd: 'npx -y bad-entry@2.0.0' },
    status: 'FAIL', msg: 'bad-entry@2.0.0',
    lines: [['FAIL', 'integrity mismatch\n        stored: a\n        npm   : b'], ['CVE', '[CRITICAL] (GHSA) rce']],
    failures: 2,
  },
  {
    tool: { name: 'unknown-entry', install_cmd: 'uvx --from git+https://x/y z' },
    status: 'UNVERIFIED', msg: 'unknown-entry: uvx --from / git URL not verifiable', failures: 0,
  },
];

test('toJsonReport: counts, statuses and flattened findings', () => {
  const report = r.toJsonReport({ results: resultsFixture, meta: { mode: 'offline' } });
  assert.equal(report.schema, 'mcp-vault/verify-report@1');
  assert.equal(report.mode, 'offline');
  assert.equal(report.checked, 3);
  assert.equal(report.failures, 2);
  assert.equal(report.unverified, 1);

  const bad = report.entries.find(e => e.name === 'bad-entry');
  assert.equal(bad.status, 'FAIL');
  assert.deepEqual(bad.findings.map(f => f.rule), ['integrity-mismatch', 'known-advisory']);
  // Multi-line report text collapses to one message line.
  assert.doesNotMatch(bad.findings[0].message, /\n/);
  assert.match(bad.findings[0].message, /stored: a npm   : b/);

  // A single-line UNVERIFIED result still produces a finding.
  const unknown = report.entries.find(e => e.name === 'unknown-entry');
  assert.equal(unknown.findings.length, 1);
  assert.equal(unknown.findings[0].rule, 'unverified-entry');
  assert.equal(unknown.findings[0].level, 'warning');
});

test('toSarif: errors and warnings only, anchored at the DB line', () => {
  const report = r.toJsonReport({ results: resultsFixture });
  const lineOf = (name) => ({ 'bad-entry': 42, 'unknown-entry': 99 })[name] || 1;
  const sarif  = r.toSarif(report, { dbPath: 'db.json', lineOf });

  assert.equal(sarif.version, '2.1.0');
  const run = sarif.runs[0];
  // The NOTE on ok-entry is dropped; three findings remain.
  assert.deepEqual(run.results.map(x => x.ruleId), ['integrity-mismatch', 'known-advisory', 'unverified-entry']);
  assert.deepEqual(run.results.map(x => x.level), ['error', 'error', 'warning']);
  assert.equal(run.results[0].locations[0].physicalLocation.region.startLine, 42);
  assert.equal(run.results[0].locations[0].physicalLocation.artifactLocation.uri, 'db.json');
  assert.equal(run.results[2].locations[0].physicalLocation.region.startLine, 99);
  // Every referenced rule is declared, with help text.
  const declared = run.tool.driver.rules.map(x => x.id);
  for (const id of new Set(run.results.map(x => x.ruleId))) assert.ok(declared.includes(id), id);
  for (const rule of run.tool.driver.rules) assert.ok(rule.help.text.length > 10, rule.id);
  // Fingerprints keep an alert stable when the entry moves in the file.
  assert.equal(run.results[0].partialFingerprints.entryRule, 'bad-entry:integrity-mismatch');
});

test('toSarif: does not repeat the entry name already in the message', () => {
  const report = r.toJsonReport({ results: resultsFixture });
  const sarif  = r.toSarif(report, {});
  const msg = sarif.runs[0].results.find(x => x.ruleId === 'unverified-entry').message.text;
  assert.equal(msg.startsWith('unknown-entry: unknown-entry'), false);
});

test('dbLineIndex: maps entry names to their line in the raw JSON', () => {
  const raw = [
    '{',
    '  "tools": [',
    '    {',
    '      "name": "first",',
    '      "install_cmd": "npx -y first"',
    '    },',
    '    {',
    '      "name": "second",',
    '      "install_cmd": "npx -y second"',
    '    }',
    '  ]',
    '}',
  ].join('\n');
  const lineOf = r.dbLineIndex(raw);
  assert.equal(lineOf('first'), 4);
  assert.equal(lineOf('second'), 8);
  assert.equal(lineOf('absent'), 1);   // never point outside the file
});

test('dbLineIndex: handles escaped characters in names', () => {
  const raw = '{\n  "tools": [\n    {\n      "name": "a\\u002fb"\n    }\n  ]\n}';
  assert.equal(r.dbLineIndex(raw)('a/b'), 4);
});

test('levelForTag: unknown tags degrade to note, never to error', () => {
  assert.equal(r.levelForTag('FAIL'), 'error');
  assert.equal(r.levelForTag('UNVERIFIED'), 'warning');
  assert.equal(r.levelForTag('SOMETHING-NEW'), 'note');
});
