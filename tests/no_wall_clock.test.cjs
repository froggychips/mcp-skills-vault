'use strict';
/**
 * No decision reads the wall clock on its own.
 *
 * Two tests went red on master a week after the evidence they read did, with
 * no commit behind the failure: library code defaulted `now = Date.now()`, so
 * a verdict was a function of the day the suite happened to run. The fix is
 * structural (docs/adr/0001-findings-and-time.md): the clock is read in one
 * place, lib/clock.cjs, and everything that decides takes the instant as an
 * argument. This test is what keeps it that way — it fails on the first new
 * `Date.now()` / `new Date()` outside the list below, and on an allowlist
 * entry that no longer matches anything, so the list cannot rot.
 *
 * What is allowed, and why, is written next to each entry. The rule of thumb:
 * time that *measures* (a cache TTL, a timeout, a backup filename) is not time
 * that *decides*, and it may keep reading the clock. `performance.now()` for
 * durations is not matched at all.
 */
const { test } = require('node:test');
const assert   = require('node:assert/strict');
const fs       = require('fs');
const path     = require('path');

const ROOT    = path.resolve(__dirname, '..');
const SCRIPTS = path.join(ROOT, 'mcp-ecosystem-intelligence', 'scripts');

// file (relative to scripts/, or bin/…) + a substring of the offending line.
const ALLOWLIST = [
  { file: 'lib/clock.cjs',  line: 'return Date.now();',
    reason: 'the one sanctioned read: readWallClock(), called once per CLI entry point' },
  { file: 'lib/http.cjs',   line: 'function retryAfterMs(header, now = Date.now())',
    reason: 'HTTP Retry-After backoff: a wait, not a verdict' },
  { file: 'lib/http.cjs',   line: 'return Date.now() - (record.stored_at || 0) < ttlMs;',
    reason: 'response cache freshness: which bytes to reuse, not what they mean' },
  { file: 'lib/http.cjs',   line: 'writeCache(key, { ...cached, stored_at: Date.now() });',
    reason: 'response cache write timestamp' },
  { file: 'lib/http.cjs',   line: 'writeCache(key, { stored_at: Date.now(), etag:',
    reason: 'response cache write timestamp' },
  { file: 'lib/deps.cjs',   line: 'const age = Date.now() - (rec.stored_at || 0);',
    reason: 'dependency-tree cache TTL; an install gate turns the cache off (cacheTtlMs: 0)' },
  { file: 'lib/deps.cjs',   line: 'JSON.stringify({ stored_at: Date.now(), packages:',
    reason: 'dependency-tree cache write timestamp' },
  { file: 'lib/mcp_stdio.cjs', line: 'now = () => Date.now()',
    reason: 'in-process TTL cache for sandbox probes, injectable for tests' },
  { file: 'lib/hosts.cjs',  line: 'backup = `${target.path}.bak.${Date.now()}`;',
    reason: 'a unique backup filename for a host config about to be rewritten' },
];

const PATTERNS = [
  { name: 'Date.now()',  re: /\bDate\.now\s*\(/ },
  { name: 'new Date()',  re: /\bnew\s+Date\s*\(\s*\)/ },
  // `Date()` without `new` returns *now* as a string.
  { name: 'Date()',      re: /(?<![\w.$])Date\s*\(\s*\)/ },
];

/**
 * Blank out comments, keeping line structure, so that prose which *mentions*
 * `Date.now()` — this file's neighbours do, to explain why it is gone — is not
 * read as a call. String and template literals are skipped over rather than
 * scanned for comment markers, so `'https://…'` is not half a line comment.
 */
function stripComments(src) {
  let out = '';
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i];
    const d = src[i + 1];
    if (c === '/' && d === '/') {
      while (i < n && src[i] !== '\n') i++;
      continue;
    }
    if (c === '/' && d === '*') {
      i += 2;
      while (i < n && !(src[i] === '*' && src[i + 1] === '/')) { out += src[i] === '\n' ? '\n' : ' '; i++; }
      i += 2;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') {
      const q = c;
      out += c; i++;
      while (i < n && src[i] !== q) {
        if (src[i] === '\\') { out += src[i] + (src[i + 1] || ''); i += 2; continue; }
        out += src[i]; i++;
      }
      out += q; i++;
      continue;
    }
    out += c; i++;
  }
  return out;
}

function scanFiles() {
  const files = [];
  for (const dir of [SCRIPTS, path.join(SCRIPTS, 'lib')]) {
    for (const f of fs.readdirSync(dir)) if (f.endsWith('.cjs')) files.push(path.join(dir, f));
  }
  for (const f of fs.readdirSync(path.join(ROOT, 'bin'))) if (f.endsWith('.cjs')) files.push(path.join(ROOT, 'bin', f));
  return files.sort();
}

const rel = (abs) => (abs.startsWith(SCRIPTS) ? path.relative(SCRIPTS, abs) : path.relative(ROOT, abs)).split(path.sep).join('/');

function findReads() {
  const hits = [];
  for (const file of scanFiles()) {
    const raw = fs.readFileSync(file, 'utf8').split('\n');
    const code = stripComments(fs.readFileSync(file, 'utf8')).split('\n');
    raw.forEach((rawLine, i) => {
      // Two readings, and either one counts: the comment-stripped line, and —
      // because a regex literal with a quote in it can derail the stripper —
      // the raw line unless it is a comment line outright.
      const trimmed = rawLine.trim();
      const plainComment = /^(\/\/|\/\*|\*)/.test(trimmed);
      for (const p of PATTERNS) {
        if (p.re.test(code[i] || '') || (!plainComment && p.re.test(rawLine))) {
          hits.push({ file: rel(file), lineNo: i + 1, text: trimmed, pattern: p.name });
        }
      }
    });
  }
  return hits;
}

test('stripComments: prose and strings are not calls', () => {
  assert.equal(PATTERNS[0].re.test(stripComments('// used to be Date.now()\nconst x = 1;')), false);
  assert.equal(PATTERNS[0].re.test(stripComments('/* `now = Date.now()` */ const y = 2;')), false);
  // A URL in a string is not the start of a comment that would hide a call.
  assert.equal(PATTERNS[0].re.test(stripComments("const u = 'https://x'; const t = Date.now();")), true);
  assert.equal(PATTERNS[1].re.test('const d = new Date();'), true);
  assert.equal(PATTERNS[1].re.test('const d = new Date(asOf);'), false);
  assert.equal(PATTERNS[2].re.test('const s = Date();'), true);
  assert.equal(PATTERNS[2].re.test('const s = toDate();'), false);
});

test('no scripts/ or lib/ code reads the wall clock outside the allowlist', () => {
  const offenders = findReads().filter((h) => !ALLOWLIST.some((a) => a.file === h.file && h.text.includes(a.line)));
  assert.deepEqual(offenders.map((h) => `${h.file}:${h.lineNo}  ${h.pattern}  ${h.text}`), [],
    'a decision must take asOf from its caller; the CLI entry point reads the clock once via lib/clock.cjs '
    + '(asOfFromArgv for decisions, readWallClock for observation timestamps). '
    + 'If this is a measurement — a cache TTL, a timeout — add it to ALLOWLIST with the reason.');
});

test('every allowlist entry still matches something, and says why', () => {
  const hits = findReads();
  for (const a of ALLOWLIST) {
    assert.ok(a.reason && a.reason.length > 10, `${a.file}: an allowlist entry needs a reason`);
    assert.ok(hits.some((h) => h.file === a.file && h.text.includes(a.line)),
      `stale allowlist entry — ${a.file}: "${a.line}" no longer occurs; remove it`);
  }
});
