'use strict';
const { test } = require('node:test');
const assert   = require('node:assert/strict');
const o = require('../mcp-ecosystem-intelligence/scripts/orchestrate.cjs');

// unmappedSignals(db, stack) returns one record per stack signal that
// either has no mapping in SIGNAL_TO_TOOLS or whose mapping references
// a tool absent from the DB.

const dbWith = (...names) => ({ tools: names.map(name => ({ name })) });
const stackWith = ({ dbs = [], infra = [] }) => ({ dbs: new Set(dbs), infra: new Set(infra) });

test('unmappedSignals: returns [] when every signal maps to a present tool', () => {
  // postgres maps to mcp-server-neon per SIGNAL_TO_TOOLS.
  const db    = dbWith('mcp-server-neon');
  const stack = stackWith({ dbs: ['postgres'] });
  assert.deepEqual(o.unmappedSignals(db, stack), []);
});

test('unmappedSignals: flags signals without any mapping or fallback (mysql in empty DB)', () => {
  // mysql is detected by orchestrate.detectStack but absent from SIGNAL_TO_TOOLS
  // AND no tool name/notes contains "mysql" — true gap.
  const db    = dbWith('mcp-server-neon');
  const stack = stackWith({ dbs: ['mysql'] });
  const out   = o.unmappedSignals(db, stack);
  assert.equal(out.length, 1);
  assert.equal(out[0].signal, 'mysql');
  assert.equal(out[0].reason, 'no mapping');
  assert.equal(out[0].fallback, undefined);
});

test('unmappedSignals: signal resolved via fallback is marked fallback, not gap', () => {
  // Use a signal NOT in SIGNAL_TO_TOOLS (datadog isn't curated today)
  // but with a matching tool name in the synthetic DB. Substring scan
  // should classify this as a fallback hit, not a gap.
  const db = {
    tools: [
      { name: 'datadog-mcp', notes: 'Datadog MCP server.', classification: 'Core' },
      { name: 'noise',       notes: 'unrelated',           classification: 'Core' },
    ],
  };
  const stack = stackWith({ infra: ['datadog'] });
  const out = o.unmappedSignals(db, stack);
  assert.equal(out.length, 1);
  assert.equal(out[0].signal, 'datadog');
  assert.deepEqual(out[0].fallback, ['datadog-mcp']);
  assert.match(out[0].reason, /^fallback →/);
});

test('fallbackBySignal: substring match against name+notes, skips Deprecated', () => {
  const db = {
    tools: [
      { name: '@salesforce/mcp', notes: 'CRM server', classification: 'Core' },
      { name: 'salesforce-legacy', notes: '', classification: 'Deprecated' },
      { name: 'irrelevant', notes: 'no match', classification: 'Core' },
    ],
  };
  const hits = o.fallbackBySignal(db, 'salesforce');
  assert.deepEqual(hits, ['@salesforce/mcp']); // Deprecated filtered out
});

test('matchDB: uses fallback when SIGNAL_TO_TOOLS has no mapping for the signal', () => {
  // datadog is not in SIGNAL_TO_TOOLS today; datadog-mcp would be picked up
  // via substring fallback. Synthetic DB to keep the test deterministic.
  const db = {
    tools: [
      { name: 'datadog-mcp',           notes: 'Datadog MCP', classification: 'Core', est_tools_count: 5 },
      { name: 'mcp-server-filesystem', notes: '', classification: 'Core', est_tools_count: 10 },
      { name: 'mcp-server-memory',     notes: '', classification: 'Core', est_tools_count: 9 },
      { name: 'context7',              notes: '', classification: 'Core', est_tools_count: 4 },
    ],
  };
  const stack = stackWith({ infra: ['datadog'] });
  const matched = o.matchDB(db, stack, null);
  const names = matched.map(t => t.name);
  assert.ok(names.includes('datadog-mcp'), `Expected datadog match via fallback, got ${names}`);
});

test('unmappedSignals: flags mappings whose referenced tool is missing in DB', () => {
  // postgres maps to mcp-server-neon, but DB doesn't contain it → drift.
  const db    = dbWith('something-else');
  const stack = stackWith({ dbs: ['postgres'] });
  const out   = o.unmappedSignals(db, stack);
  assert.equal(out.length, 1);
  assert.equal(out[0].signal, 'postgres');
  assert.match(out[0].reason, /not in DB/);
});

test('unmappedSignals: handles both dbs and infra signals', () => {
  // kubernetes is infra; mapped to mcp-server-kubernetes per SIGNAL_TO_TOOLS.
  const db    = dbWith();        // empty DB
  const stack = stackWith({ dbs: ['postgres'], infra: ['kubernetes'] });
  const out   = o.unmappedSignals(db, stack);
  assert.equal(out.length, 2);
  const signals = out.map(u => u.signal).sort();
  assert.deepEqual(signals, ['kubernetes', 'postgres']);
});

test('unmappedSignals: empty stack returns empty array', () => {
  assert.deepEqual(o.unmappedSignals(dbWith(), stackWith({})), []);
});

test('SIGNAL_TO_TOOLS keys reference tools that exist in the seeded DB', () => {
  // This is a structural lint: if a mapping points at a deleted entry,
  // unmappedSignals will flag it for users — but we should catch it in
  // CI too. Load the real DB and check each mapped tool name is present.
  const path = require('path');
  const fs   = require('fs');
  const dbPath = path.resolve(__dirname, '../mcp-ecosystem-intelligence/assets/tools_database.json');
  const realDb = JSON.parse(fs.readFileSync(dbPath, 'utf8'));
  const dbNames = new Set(realDb.tools.map(t => t.name));
  const missing = [];
  for (const [signal, tools] of Object.entries(o.SIGNAL_TO_TOOLS)) {
    for (const name of tools) {
      if (!dbNames.has(name)) missing.push({ signal, name });
    }
  }
  assert.deepEqual(missing, [], `SIGNAL_TO_TOOLS references tools missing from DB: ${JSON.stringify(missing)}`);
});

test('UNIVERSAL_TOOLS members all exist in the seeded DB', () => {
  const path = require('path');
  const fs   = require('fs');
  const dbPath = path.resolve(__dirname, '../mcp-ecosystem-intelligence/assets/tools_database.json');
  const realDb = JSON.parse(fs.readFileSync(dbPath, 'utf8'));
  const dbNames = new Set(realDb.tools.map(t => t.name));
  const missing = [...o.UNIVERSAL_TOOLS].filter(n => !dbNames.has(n));
  assert.deepEqual(missing, [], `UNIVERSAL_TOOLS members missing from DB: ${missing}`);
});

// ── detectStack regression: new signals from the WO/infra expansion ─────────

const fs   = require('node:fs');
const os   = require('node:os');

function envProject(envContent, files = {}) {
  const dir = fs.mkdtempSync(`${os.tmpdir()}/orch-stack-`);
  fs.writeFileSync(`${dir}/.env.example`, envContent);
  for (const [name, body] of Object.entries(files)) {
    const full = `${dir}/${name}`;
    fs.mkdirSync(require('node:path').dirname(full), { recursive: true });
    fs.writeFileSync(full, body);
  }
  return dir;
}

test('detectStack: TEAMCITY_URL env-key adds teamcity signal', () => {
  const dir = envProject('TEAMCITY_URL=https://tc.example.com\n');
  const stack = o.detectStack(dir);
  assert.ok(stack.infra.has('teamcity'), `infra=${[...stack.infra]}`);
  assert.ok(stack.cats.has('ci-cd'));
});

test('detectStack: .teamcity/ directory adds teamcity signal', () => {
  const dir = envProject('', { '.teamcity/.keep': '' });
  const stack = o.detectStack(dir);
  assert.ok(stack.infra.has('teamcity'));
});

test('detectStack: SALESFORCE_TOKEN adds salesforce → @salesforce/mcp via SIGNAL_TO_TOOLS', () => {
  const dir = envProject('SALESFORCE_TOKEN=x\n');
  const stack = o.detectStack(dir);
  assert.ok(stack.infra.has('salesforce'));
  assert.deepEqual(o.SIGNAL_TO_TOOLS['salesforce'], ['@salesforce/mcp']);
});

test('detectStack: helm/Chart.yaml adds helm signal', () => {
  const dir = envProject('', { 'helm/Chart.yaml': 'apiVersion: v2\n' });
  const stack = o.detectStack(dir);
  assert.ok(stack.infra.has('helm'));
});

test('detectStack: argocd directory adds argocd signal', () => {
  const dir = envProject('', { 'argocd/.keep': '' });
  const stack = o.detectStack(dir);
  assert.ok(stack.infra.has('argocd'));
});

test('detectStack: top-level .tf file adds terraform signal', () => {
  const dir = envProject('', { 'main.tf': 'terraform {}\n' });
  const stack = o.detectStack(dir);
  assert.ok(stack.infra.has('terraform'));
});

test('detectStack: docker-compose with kafka image adds kafka signal', () => {
  const dir = envProject('', { 'docker-compose.yml': 'services:\n  kafka:\n    image: confluentinc/cp-kafka:7\n' });
  const stack = o.detectStack(dir);
  assert.ok(stack.infra.has('kafka'));
});

test('detectStack: PROMETHEUS_* env-key adds prometheus signal', () => {
  const dir = envProject('PROMETHEUS_URL=http://p:9090\n');
  const stack = o.detectStack(dir);
  assert.ok(stack.infra.has('prometheus'));
  assert.ok(stack.cats.has('observability'));
});

test('detectStack: ATLASSIAN_* env-key adds atlassian → mcp-atlassian via SIGNAL_TO_TOOLS', () => {
  const dir = envProject('ATLASSIAN_URL=https://x.atlassian.net\n');
  const stack = o.detectStack(dir);
  assert.ok(stack.infra.has('atlassian'));
  assert.deepEqual(o.SIGNAL_TO_TOOLS['atlassian'], ['mcp-atlassian']);
});

test('detectStack: PG_* env-key adds postgres signal', () => {
  const dir = envProject('PG_HOST=db.example.com\n');
  const stack = o.detectStack(dir);
  assert.ok(stack.dbs.has('postgres'));
});
