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

  const cases = [
    ['list_entries.cjs',     ['--json', '--cwd', cwd]],
    ['doctor.cjs',           ['--json', '--cwd', cwd]],
    ['audit_setup.cjs',      ['--json', '--cwd', cwd]],
    ['status.cjs',           ['--json', '--cwd', cwd]],
    ['orchestrate.cjs',      ['--json', '--cwd', cwd]],
    // `health` has no --json: its only output is the document.
    ['calculate_health.cjs', ['100', '30', 'true', '1', 'MIT']],
  ];
  for (const [script, argv] of cases) {
    const r = spawnSync(process.execPath, [path.join(SCRIPTS, script), ...argv], {
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

test('every command that reads a host config answers 2 when it cannot', () => {
  // The contract says 2 never means clean. Measured across the CLI, the same
  // malformed `.mcp.json` produced 2 from `status`, 1 from `doctor` and **0
  // from `audit --strict`** — the last reporting a clean setup for servers it
  // had never seen, and `budget` totalling an unknown subset of them.
  const { spawnSync } = require('child_process');
  const os = require('os');
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-exit-home-'));

  const broken = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-exit-'));
  fs.writeFileSync(path.join(broken, '.mcp.json'), '{ "mcpServers": { oops');

  const commands = [
    ['status.cjs', []],
    ['audit_setup.cjs', []],
    ['doctor.cjs', []],
    ['token_budget.cjs', []],
    ['lock.cjs', ['--check']],
    ['sbom.cjs', ['--installed']],
    ['verify_integrity.cjs', ['--installed', '--offline']],
  ];
  for (const [script, extra] of commands) {
    const r = spawnSync(process.execPath, [path.join(SCRIPTS, script), ...extra, '--cwd', broken], {
      encoding: 'utf8',
      env: { ...process.env, HOME: home, NO_COLOR: '1' },
    });
    assert.equal(r.status, 2, `${script} exited ${r.status} on a config it could not read`);
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

test('a finding outranks an unreadable input, in every command that has both', () => {
  // The document says so, and `status` was the only command that did it.
  // `audit --strict` returned 2 for a definite version drift in a config it
  // *could* read, because a second unreadable config took precedence — hiding
  // the drift behind our own inability to read something else. `doctor`
  // scheduled its 2 before considering an unsupported Node version.
  const { spawnSync } = require('child_process');
  const os = require('os');
  const dir  = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-rank-'));
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-rank-home-'));

  // A readable project config with a drifted version…
  fs.writeFileSync(path.join(dir, '.mcp.json'), JSON.stringify({
    mcpServers: {
      'mcp-server-filesystem': { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem@0.0.1', '/tmp'] },
    },
  }));
  // …and an unreadable global one.
  fs.writeFileSync(path.join(home, '.claude.json'), '{ oops');

  for (const [script, extra] of [['audit_setup.cjs', ['--strict']], ['status.cjs', ['--strict']]]) {
    const r = spawnSync(process.execPath, [path.join(SCRIPTS, script), ...extra, '--cwd', dir], {
      encoding: 'utf8',
      env: { ...process.env, HOME: home, NO_COLOR: '1' },
    });
    assert.equal(r.status, 1, `${script} returned ${r.status}: a finding must outrank an incomplete scope`);
  }
});
