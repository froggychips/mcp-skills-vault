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

test('every offline --json command actually emits a listed schema', () => {
  // The document said "every JSON document this tool writes carries a schema
  // identifier" while `list --json`, `audit --json` and `doctor --json` wrote
  // none. Grepping the source for schema strings could not catch that: the
  // strings it found were the ones that existed. So this runs the commands.
  //
  // Only the offline ones: asserting on `availability --json` would make the
  // suite fail on a bad afternoon at npm, which is its own dishonesty.
  const { spawnSync } = require('child_process');
  const os = require('os');
  const cwd  = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-compat-'));
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-compat-home-'));

  for (const script of ['list_entries.cjs', 'doctor.cjs', 'audit_setup.cjs', 'status.cjs']) {
    const r = spawnSync(process.execPath, [path.join(SCRIPTS, script), '--json', '--cwd', cwd], {
      encoding: 'utf8',
      env: { ...process.env, HOME: home, NO_COLOR: '1' },
    });
    assert.ok([0, 1].includes(r.status), `${script} exited ${r.status}: ${r.stderr}`);
    let doc;
    assert.doesNotThrow(() => { doc = JSON.parse(r.stdout); }, `${script} --json did not emit JSON`);
    const id = doc.schema || doc.$schema;
    assert.ok(id, `${script} --json emits no schema identifier`);
    assert.ok(PROMISE.includes(id), `${script} emits ${id}, which docs/COMPATIBILITY.md does not list`);
  }
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
