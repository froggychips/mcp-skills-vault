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

test('unmappedSignals: flags signals without any mapping (mysql today)', () => {
  // mysql is detected by orchestrate.detectStack but absent from SIGNAL_TO_TOOLS.
  const db    = dbWith('mcp-server-neon');
  const stack = stackWith({ dbs: ['mysql'] });
  const out   = o.unmappedSignals(db, stack);
  assert.equal(out.length, 1);
  assert.equal(out[0].signal, 'mysql');
  assert.equal(out[0].reason, 'no mapping');
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
