'use strict';
/**
 * Shared I/O helper for tools_database.json.
 *
 * The on-disk DB stores non-ASCII characters as `\uXXXX` escape sequences
 * (lowercase hex). Bare `JSON.stringify` emits literal multi-byte UTF-8
 * instead, which produces large cosmetic diffs when automation round-trips
 * the file. Use `writeDb()` from any script that mutates the DB.
 *
 * API:
 *   readDb(path)            -> { db, raw }
 *   writeDb(path, db)       -> void   (utf-8, 2-space indent, trailing \n,
 *                                      all chars > U+007E escaped as \uXXXX)
 *
 * Insertion order is preserved (no key reordering). Surrogate pairs for
 * code points beyond the BMP are emitted as the canonical two-`\uXXXX` form,
 * which is what `JSON.stringify` would have produced anyway in ASCII mode.
 */

const fs = require('fs');

function readDb(dbPath) {
  const raw = fs.readFileSync(dbPath, 'utf8');
  const db  = JSON.parse(raw);
  return { db, raw };
}

// Re-escape any character with a code unit value above 0x7E (printable ASCII
// upper bound) as `\uXXXX`. The regex iterates UTF-16 code units, so a
// surrogate pair becomes two consecutive `\uXXXX` escapes — that is the
// canonical JSON ASCII-safe encoding of an astral code point.
const NON_ASCII = /[-￿]/g;

function escapeNonAscii(s) {
  return s.replace(NON_ASCII, (c) =>
    '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')
  );
}

function writeDb(dbPath, db) {
  const json = JSON.stringify(db, null, 2);
  const out  = escapeNonAscii(json) + '\n';
  fs.writeFileSync(dbPath, out, 'utf8');
}

module.exports = { readDb, writeDb, escapeNonAscii };
