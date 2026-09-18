'use strict';
/**
 * The compatibility promise, checked against the thing it promises about.
 *
 * A promise document is worth exactly as much as its accuracy. The two ways
 * this one goes wrong on its own are: a new `--json` payload ships with a
 * schema id nobody listed, so a consumer has no idea what stability it has;
 * and a command appears in `--help` without being covered. Both are silent.
 */

const test   = require('node:test');
const assert = require('node:assert/strict');
const fs     = require('fs');
const path   = require('path');

const ROOT    = path.resolve(__dirname, '..');
const PROMISE = fs.readFileSync(path.join(ROOT, 'docs/COMPATIBILITY.md'), 'utf8');
const SCRIPTS = path.join(ROOT, 'mcp-ecosystem-intelligence/scripts');

/** Every `mcp-vault/<name>@<n>` identifier that appears anywhere in the code. */
function emittedSchemas() {
  const found = new Set();
  const walk = (dir) => {
    for (const name of fs.readdirSync(dir)) {
      const full = path.join(dir, name);
      if (fs.statSync(full).isDirectory()) { walk(full); continue; }
      if (!name.endsWith('.cjs')) continue;
      for (const m of fs.readFileSync(full, 'utf8').matchAll(/mcp-vault\/[a-z-]+@\d+/g)) found.add(m[0]);
    }
  };
  walk(SCRIPTS);
  return [...found].sort();
}

test('every schema identifier the code emits is listed in the promise', () => {
  const missing = emittedSchemas().filter((id) => !PROMISE.includes(id));
  assert.deepEqual(missing, [],
    `these schema ids are written by the tool but not covered by docs/COMPATIBILITY.md:\n  ${missing.join('\n  ')}\n`
    + 'A consumer reading one of these has no statement about what may change under it.');
});

test('the promise lists no schema identifier the code does not emit', () => {
  // The other direction: a promise about something that no longer exists is
  // how a document starts being ignored.
  const emitted = new Set(emittedSchemas());
  const claimed = [...PROMISE.matchAll(/`(mcp-vault\/[a-z-]+@\d+)`/g)].map((m) => m[1]);
  const stale = [...new Set(claimed)].filter((id) => !emitted.has(id));
  assert.deepEqual(stale, [], `docs/COMPATIBILITY.md promises about ids nothing writes: ${stale.join(', ')}`);
});

test('every command in --help is a command the promise covers by name', () => {
  // The promise covers "every command listed in `mcp-vault --help`", so the
  // list has to be reachable and non-empty for that sentence to mean anything.
  const bin = fs.readFileSync(path.join(ROOT, 'bin/mcp-vault.cjs'), 'utf8');
  const block = bin.slice(bin.indexOf('const COMMANDS = {'), bin.indexOf('};', bin.indexOf('const COMMANDS = {')));
  const commands = [...block.matchAll(/^\s*"?([a-z-]+)"?:\s*"/gm)].map((m) => m[1]);
  assert.ok(commands.length > 15, `only found ${commands.length} commands — the parse broke`);

  const help = bin.slice(bin.indexOf('COMMANDS\n'), bin.indexOf('COMMON OPTIONS'));
  const undocumented = commands.filter((c) => !new RegExp(`^\\s{2}${c}\\b`, 'm').test(help));
  // Aliases are documented next to their primary name, not on their own line.
  const aliases = new Set(['ls', 'install']);
  assert.deepEqual(undocumented.filter((c) => !aliases.has(c)), [],
    'commands that exist but are not in --help, so the promise does not reach them');
});

test('the three exit codes are the ones the scripts actually document', () => {
  // The promise makes a specific claim — 2 never means "clean" — and it is
  // only true if every script agrees on the convention. Checked against the
  // header block each script carries.
  const offenders = [];
  for (const name of fs.readdirSync(SCRIPTS).filter((f) => f.endsWith('.cjs'))) {
    const src = fs.readFileSync(path.join(SCRIPTS, name), 'utf8');
    const m = src.match(/Exit codes:\n([\s\S]{0,400}?)(?:\n \*\/|\n\n)/);
    if (!m) continue;                                  // not every script declares them
    const block = m[1];
    // Any phrasing of "I could not answer" is fine; what must never appear on
    // the 2 line is a word that reads as a verdict.
    const two = block.split('\n').find((l) => /^\s*[*/]*\s*2\s/.test(l)) || '';
    const answersTheQuestion = /\b(bad|not found|could not be found|unknown|unreadable|not readable|nothing to|missing|invalid|bad invocation)\b/i.test(two);
    if (two && !answersTheQuestion) {
      offenders.push(`${name}: ${two.trim()}`);
    }
  }
  assert.deepEqual(offenders, [],
    `exit code 2 is documented as something other than "could not answer":\n${offenders.join('\n')}`);
});
