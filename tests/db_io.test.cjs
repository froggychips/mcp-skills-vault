'use strict';
/**
 * Regression tests for the DB I/O helper.
 *
 * tools_database.json stores non-ASCII characters as `\uXXXX` escape
 * sequences. A bare JSON.stringify emits raw UTF-8 instead, which produces
 * a large cosmetic diff when automation round-trips the file. `writeDb()`
 * normalizes the output to match the on-disk convention; these tests
 * enforce that.
 */

const { test } = require('node:test');
const assert   = require('node:assert/strict');
const fs       = require('node:fs');
const os       = require('node:os');
const path     = require('node:path');

const { readDb, writeDb, escapeNonAscii } =
  require('../mcp-ecosystem-intelligence/scripts/lib/db_io.cjs');

const DB_PATH = path.resolve(
  __dirname,
  '../mcp-ecosystem-intelligence/assets/tools_database.json'
);

function tmpFile(label) {
  return path.join(
    os.tmpdir(),
    `db_io.test.${label}.${process.pid}.${Date.now()}.${Math.random().toString(36).slice(2)}.json`
  );
}

test('round-trips the live tools_database.json byte-for-byte', () => {
  const orig = fs.readFileSync(DB_PATH, 'utf8');
  const { db } = readDb(DB_PATH);
  const out = tmpFile('roundtrip');
  try {
    writeDb(out, db);
    const written = fs.readFileSync(out, 'utf8');
    // writeDb guarantees exactly one trailing newline; compare with the
    // same normalization on both sides so a missing terminator on the
    // source file (unlikely but possible) does not trip the test.
    assert.equal(written.trimEnd(), orig.trimEnd(),
      'round-trip produced a different byte stream — writer drift detected');
    // Sanity: there must be at least one \uXXXX escape in the output, or
    // the writer is bypassing the convention entirely.
    assert.match(written, /\\u[0-9a-f]{4}/,
      'output contains no \\uXXXX escapes — writer is not escaping');
  } finally {
    if (fs.existsSync(out)) fs.unlinkSync(out);
  }
});

test('escapes BMP, supplementary, and common typographic chars', () => {
  const out = tmpFile('synth');
  try {
    writeDb(out, {
      section:  '§',   // §  (Latin-1 supplement)
      emdash:   '—',   // —  (general punctuation)
      ellipsis: '…',   // …
      cyrillic: 'я',   // я  (single BMP code point)
      emoji:    '🚀', // 🚀 (surrogate pair, U+1F680)
    });
    const written = fs.readFileSync(out, 'utf8');
    assert.match(written, /"section": "\\u00a7"/);
    assert.match(written, /"emdash": "\\u2014"/);
    assert.match(written, /"ellipsis": "\\u2026"/);
    assert.match(written, /"cyrillic": "\\u044f"/);
    assert.match(written, /"emoji": "\\ud83d\\ude80"/);
    // No literal multi-byte UTF-8 should sneak through.
    assert.doesNotMatch(written, /[-￿]/);
  } finally {
    if (fs.existsSync(out)) fs.unlinkSync(out);
  }
});

test('writeDb produces 2-space indent and a single trailing newline', () => {
  const out = tmpFile('empty');
  try {
    writeDb(out, {});
    assert.equal(fs.readFileSync(out, 'utf8'), '{}\n');
  } finally {
    if (fs.existsSync(out)) fs.unlinkSync(out);
  }

  const out2 = tmpFile('indent');
  try {
    writeDb(out2, { a: 1, nested: { b: 2 } });
    assert.equal(
      fs.readFileSync(out2, 'utf8'),
      '{\n  "a": 1,\n  "nested": {\n    "b": 2\n  }\n}\n'
    );
  } finally {
    if (fs.existsSync(out2)) fs.unlinkSync(out2);
  }
});

test('preserves insertion order (does not sort keys)', () => {
  const out = tmpFile('order');
  try {
    writeDb(out, { b: 1, a: 2, c: 3 });
    assert.equal(
      fs.readFileSync(out, 'utf8'),
      '{\n  "b": 1,\n  "a": 2,\n  "c": 3\n}\n'
    );
  } finally {
    if (fs.existsSync(out)) fs.unlinkSync(out);
  }
});

test('escapeNonAscii leaves printable ASCII unchanged', () => {
  // Printable ASCII range (0x20–0x7E) plus tab/newline/cr should pass
  // through untouched. We don't claim anything about control chars
  // below 0x20 — JSON.stringify already escapes those before we run.
  const s = ' !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ' +
            '[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~';
  assert.equal(escapeNonAscii(s), s);
});

test('readDb returns parsed object and raw text', () => {
  const { db, raw } = readDb(DB_PATH);
  assert.equal(typeof raw, 'string');
  assert.ok(Array.isArray(db.tools), 'parsed DB should have a tools array');
  assert.ok(db.tools.length > 0, 'tools array should be non-empty');
});
