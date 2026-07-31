'use strict';
const { test }      = require('node:test');
const assert        = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path          = require('node:path');

const LIB = path.resolve(__dirname, '../mcp-ecosystem-intelligence/scripts/lib/exit.cjs');

// Writes `bytes` of payload to stdout, then leaves via `mode`. Run as a child
// with stdout piped, which is the condition that makes stdout writes async.
function child(mode, bytes, code) {
  const src = `
    const { exitAfterFlush } = require(${JSON.stringify(LIB)});
    process.stdout.write('x'.repeat(${bytes}));
    process.stdout.write('END');
    ${mode === 'flush' ? `exitAfterFlush(${code});` : `process.exit(${code});`}
  `;
  return spawnSync(process.execPath, ['-e', src], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
}

test('exitAfterFlush delivers a large payload intact and keeps the exit code', () => {
  // 4 MB is comfortably past any pipe buffer, so an un-flushed exit has no
  // chance of getting away with it.
  const r = child('flush', 4 * 1024 * 1024, 3);
  assert.equal(r.status, 3);
  assert.ok(r.stdout.endsWith('END'), `tail: ${JSON.stringify(r.stdout.slice(-40))}`);
  assert.equal(r.stdout.length, 4 * 1024 * 1024 + 3);
});

test('exitAfterFlush preserves exit code 0', () => {
  const r = child('flush', 1024, 0);
  assert.equal(r.status, 0);
  assert.ok(r.stdout.endsWith('END'));
});

test('a large JSON payload survives and still parses', () => {
  // The failure mode this guards: mcp_eval --json writes the whole result set
  // to stdout, and a truncated object surfaces downstream as
  // "Unexpected end of JSON input" rather than as an obvious CLI error.
  const src = `
    const { exitAfterFlush } = require(${JSON.stringify(LIB)});
    const rows = Array.from({length: 20000}, (_, i) => ({ i, name: 'entry-' + i, status: 'pass' }));
    process.stdout.write(JSON.stringify({ results: rows }));
    exitAfterFlush(0);
  `;
  const r = spawnSync(process.execPath, ['-e', src], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  assert.equal(r.status, 0);
  const parsed = JSON.parse(r.stdout);   // throws if truncated
  assert.equal(parsed.results.length, 20000);
});

test('plain process.exit is the behaviour we moved away from', () => {
  // Measured on macOS/arm64: a bare exit loses the tail 5 times out of 5 at
  // this size, while exitAfterFlush loses it 0 out of 5. We deliberately do
  // NOT assert the loss — it depends on pipe buffer size and scheduling, so a
  // different platform could flush in time and turn this into a false alarm.
  // Assert only what is invariant here, and let the tests above carry the fix.
  const r = child('bare', 4 * 1024 * 1024, 3);
  assert.equal(r.status, 3);
});
