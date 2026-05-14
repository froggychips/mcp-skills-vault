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
  // SIGNAL_TO_TOOLS has no entry for "mapbox" but @mapbox/mcp-server exists.
  // Fallback substring scan should find it → record carries `fallback`,
  // reason starts with "fallback →".
  const db = {
    tools: [
      { name: '@mapbox/mcp-server', notes: 'Mapbox MCP server.', classification: 'Core' },
      { name: 'noise', notes: 'unrelated', classification: 'Core' },
    ],
  };
  const stack = stackWith({ infra: ['mapbox'] });
  const out = o.unmappedSignals(db, stack);
  assert.equal(out.length, 1);
  assert.equal(out[0].signal, 'mapbox');
  assert.deepEqual(out[0].fallback, ['@mapbox/mcp-server']);
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
  // mapbox is not in SIGNAL_TO_TOOLS today; @mapbox/mcp-server is in DB.
  const db = {
    tools: [
      { name: '@mapbox/mcp-server', notes: 'Mapbox MCP server.', classification: 'Core', est_tools_count: 5 },
      { name: 'mcp-server-filesystem', notes: '', classification: 'Core', est_tools_count: 10 },
      { name: 'mcp-server-memory',     notes: '', classification: 'Core', est_tools_count: 9 },
      { name: 'context7',              notes: '', classification: 'Core', est_tools_count: 4 },
    ],
  };
  const stack = stackWith({ infra: ['mapbox'] });
  const matched = o.matchDB(db, stack, null);
  const names = matched.map(t => t.name);
  assert.ok(names.includes('@mapbox/mcp-server'), `Expected mapbox match via fallback, got ${names}`);
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
