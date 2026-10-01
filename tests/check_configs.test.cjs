'use strict';
/**
 * `mcp-vault check` — the configs in a repository, in one pass, with one
 * answer. It decides nothing itself: every line of a config is decided as the
 * command that owns that question decides it (verify --config, secrets, the
 * lookalike row), and that is what the consistency test below compares.
 */

const { test } = require('node:test');
const assert   = require('node:assert/strict');
const fs       = require('node:fs');
const os       = require('node:os');
const path     = require('node:path');
const { spawnSync } = require('node:child_process');

const REPO    = path.resolve(__dirname, '..');
const S       = path.join(REPO, 'mcp-ecosystem-intelligence', 'scripts');
const CHECK   = path.join(S, 'check_configs.cjs');
const VERIFY  = path.join(S, 'verify_integrity.cjs');
const SECRETS = path.join(S, 'check_secrets.cjs');
const BIN     = path.join(REPO, 'bin', 'mcp-vault.cjs');
const SHAPES  = path.join(REPO, 'tests', 'fixtures', 'launch-shapes');
const ACTION  = path.join(REPO, 'tests', 'fixtures', 'action');
const F = require('../mcp-ecosystem-intelligence/scripts/lib/finding.cjs');
const { deepFreeze } = require('../mcp-ecosystem-intelligence/scripts/lib/policy_rules.cjs');

const AS_OF = '2026-09-30T12:00:00Z';
// Nobody's home directory: check must not read one, and the commands it is
// compared with read only what is in the project then.
const HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-vault-check-home-'));
const ENV = { ...process.env, HOME, NO_COLOR: '1', CI: '', MCP_VAULT_ALLOW_UNSIGNED_DB: '', MCP_VAULT_REQUIRE_SIGNED_DB: '' };

const run = (script, args, cwd) => spawnSync(process.execPath, [script, ...args], { cwd, encoding: 'utf8', env: ENV });
const check = (args, cwd) => run(CHECK, ['--as-of', AS_OF, ...args], cwd);
const json = (args, cwd) => {
  const r = check(['--json', ...args], cwd);
  return { status: r.status, doc: JSON.parse(r.stdout), stderr: r.stderr };
};

/** A project directory holding `config` as its .mcp.json. */
function project(config) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-vault-check-'));
  fs.writeFileSync(path.join(dir, '.mcp.json'), typeof config === 'string' ? config : JSON.stringify(config, null, 2));
  return dir;
}

const decisionOf = (doc, id) => doc.decisions.find((d) => d.subject.id === id);
const outcomes = (d) => d.rules.map((o) => `${o.rule}:${o.effect}`);

/** decide() over the document's own inputs: the property every command keeps. */
function recompute(doc) {
  return F.decide(doc.findings, deepFreeze(JSON.parse(JSON.stringify(doc.policy))), Date.parse(doc.as_of), {
    subjects: F.documentSubjects(doc), facts: doc.facts,
  });
}

// Built at runtime so no credential-shaped string is committed to the repo.
const TOKEN = ['ghp', 'Zq7Xw2Lp9Rt4Vb8Nc3Md6Fk1Hs5Jy0Ug7Ae2Qx'].join('_');

// ── outcomes ───────────────────────────────────────────────────────────────

test('check: a clean config is 0, decided line by line', () => {
  const { status, doc } = json([], path.join(ACTION, 'clean'));
  assert.equal(status, 0);
  assert.equal(doc.schema, 'mcp-vault/findings@1');
  assert.deepEqual(doc.decisions.filter((d) => d.subject.type === 'host-config').map((d) => [d.subject.id, d.effect, d.decided_by]), [
    ['.mcp.json:3', 'allow', 'finding/none'],
    ['.vscode/mcp.json:3', 'allow', 'finding/none'],
  ]);
  assert.ok(!doc.decisions.some((d) => d.fails));
  assert.deepEqual(recompute(doc), doc.decisions);
});

test('check: an unpinned launch warns, and fails under --strict', () => {
  const { status, doc } = json(['single-latest.json'], SHAPES);
  assert.equal(status, 0);
  const d = decisionOf(doc, 'single-latest.json:3');
  assert.ok(outcomes(d).includes('config/unpinned-launch:warn'), outcomes(d).join(' '));
  assert.equal(d.fails, false);
  assert.equal(check(['--strict', 'single-latest.json'], SHAPES).status, 1);
  assert.equal(check(['--fail-on', 'warn', 'single-latest.json'], SHAPES).status, 1);
  // The text says what is wrong on one line and how to fix it on the next.
  const text = check(['single-latest.json'], SHAPES).stdout;
  assert.match(text, /^single-latest\.json$/m);
  assert.match(text, /^ {2}:3 nx$/m);
  assert.match(text, /^ {4}! this config launches nx-mcp@latest, a tag rather than a version: .* \[config\/unpinned-launch: warn; so pin\/missing: unknown\]$/m);
  assert.match(text, /^ {6}fix: pin to an exact version \(nx-mcp@<x\.y\.z>\)$/m);
  assert.match(text.trim().split('\n').pop(), /^PASS — 1 to look at \(--strict fails on these\) · 1 server in 1 config · fail on deny · offline$/);
});

test('check text: one line per cause — the gate\'s "nothing to compare" follows from the config\'s own finding', () => {
  const lines = (r) => r.stdout.split('\n').filter((l) => /^ {4}[!✗?] /.test(l));
  // Unpinned: one line, and the consequence is named in its tag — including
  // when it is the part that fails (fail-on unknown).
  const plain = check(['single-latest.json'], SHAPES);
  assert.equal(lines(plain).length, 1, plain.stdout);
  assert.doesNotMatch(plain.stdout, /no stored hash to compare/);
  const strictish = check(['--fail-on', 'unknown', 'single-latest.json'], SHAPES);
  assert.equal(strictish.status, 1);
  assert.deepEqual(lines(strictish).map((l) => l.trim()[0]), ['✗']);
  assert.match(lines(strictish)[0], /\[config\/unpinned-launch: warn; so pin\/missing: unknown, fails\]$/);
  assert.match(strictish.stdout.trim().split('\n').pop(), /^FAIL — 1 failing · /);
  // An overridden source: one line, no second "cannot verify".
  const dir = project({ mcpServers: { tool: { command: 'npx', args: ['-y', '--registry', 'https://registry.example', 'some-pkg@1.0.0'] } } });
  const ovr = check([], dir);
  const l = lines(ovr).filter((x) => !/flows\//.test(x));
  assert.equal(l.length, 1, ovr.stdout);
  assert.match(l[0], /from a source other than the public registry.*\[config\/launch-source-override: unknown; so verify\/unverified: unknown\]$/);
  // The model keeps both findings, and the decision rests on both.
  for (const [args, cwd, id, rules] of [
    [['single-latest.json'], SHAPES, 'single-latest.json:3', ['config/unpinned-launch', 'pin/missing']],
    [[], dir, '.mcp.json:3', ['config/launch-source-override', 'verify/unverified']],
  ]) {
    const { doc } = json(args, cwd);
    const got = doc.findings.filter((f) => f.subject.id === id).map((f) => f.rule).sort();
    assert.deepEqual(got, rules);
    assert.equal(decisionOf(doc, id).effect, 'unknown');
    const sarif = JSON.parse(check(['--sarif', ...args], cwd).stdout).runs[0].results.map((x) => x.ruleId);
    for (const r of rules) assert.ok(sarif.includes(r), `${r} missing from SARIF`);
  }
});

test('check: the fix line is the exact launch with the version the vault verified', () => {
  const text = check([], path.join(ACTION, 'bad')).stdout;
  assert.ok(text.includes('fix: pin it to the version the vault verified (playwright-mcp): "args": ["-y","@playwright/mcp@0.0.75"]'), text);
});

test('check: a plain-text secret is 1, and its value is in no output format', () => {
  // A committed fixture (tracked, so high) with a connection string, and a
  // token in both env and args — the second place verify's launch command sees.
  const shapes = run(CHECK, ['--as-of', AS_OF, 'npx-yes-flags.json'], SHAPES);
  assert.equal(shapes.status, 1, shapes.stdout + shapes.stderr);
  const dir = project({ mcpServers: { gh: { command: 'npx', args: ['-y', '@playwright/mcp@0.0.75', `--token=${TOKEN}`], env: { GITHUB_TOKEN: TOKEN } } } });
  for (const [args, cwd, secret] of [[['npx-yes-flags.json'], SHAPES, 'fake-password'], [[], dir, TOKEN.slice(4)]]) {
    for (const fmt of [[], ['--json'], ['--sarif'], ['--strict'], ['--no-color']]) {
      const r = check([...fmt, ...args], cwd);
      assert.equal(r.status, 1, `${fmt.join(' ')}: ${r.stderr}`);
      assert.ok(!(r.stdout + r.stderr).includes(secret), `${fmt.join(' ') || 'text'}: the secret is printed`);
      assert.ok(!(r.stdout + r.stderr).includes(secret.slice(0, 12)), `${fmt.join(' ') || 'text'}: part of the secret is printed`);
    }
  }
  const { doc } = json([], dir);
  const denied = doc.decisions.filter((d) => d.decided_by.startsWith('secrets/'));
  assert.ok(denied.length && denied.every((d) => d.effect === 'deny' && d.fails), JSON.stringify(doc.decisions.map((d) => d.decided_by)));
  const text = check([], dir).stdout;
  assert.match(text, /✗ GitHub token in plain text at mcpServers\.gh\.env\.GITHUB_TOKEN \(\d+ chars, ghp_…\) \[secrets\/github-token: deny, fails\]/);
  assert.match(text, /fix: replace it with mcpServers\.gh\.env\.GITHUB_TOKEN: "\$\{GITHUB_TOKEN\}"/);
  assert.match(text.trim().split('\n').pop(), /^FAIL — /);
});

test('check: a secret on the line of an unpinned launch — both causes are decided, and --strict fails', () => {
  // One-line JSON: the secret's line is the server's line, so verify and
  // secrets speak about one subject. Its decision rests on both.
  const dir = project(JSON.stringify({ mcpServers: { browser: { command: 'npx', args: ['-y', '@playwright/mcp@latest'], env: { GITHUB_TOKEN: TOKEN } } } }));
  const { status, doc } = json([], dir);
  assert.equal(status, 1);
  const d = decisionOf(doc, '.mcp.json:1');
  assert.ok(d, doc.decisions.map((x) => x.subject.id).join(' '));
  assert.equal(doc.facts['.mcp.json:1'].mode, 'gate');
  assert.equal(d.effect, 'deny');
  assert.equal(d.decided_by, 'secrets/github-token');
  assert.ok(outcomes(d).includes('config/unpinned-launch:warn'), outcomes(d).join(' '));
  assert.ok(outcomes(d).includes('secrets/github-token:deny'), outcomes(d).join(' '));
  const text = check([], dir).stdout;
  assert.match(text, /✗ GitHub token in plain text .* \[secrets\/github-token: deny, fails\]/);
  assert.match(text, /this config launches @playwright\/mcp@latest, a tag rather than a version.* \[config\/unpinned-launch: warn; so pin\/missing: unknown\]/);
  const strict = check(['--strict'], dir);
  assert.equal(strict.status, 1);
  assert.match(strict.stdout, /\[config\/unpinned-launch: warn; so pin\/missing: unknown, fails\]/);
});

test('check: a partly broken config — the valid entries are checked, the broken one is unanswered on its line', () => {
  const dir = project({ mcpServers: {
    broken: 'npx -y something',
    'playwright-mcp': { command: 'npx', args: ['-y', '@playwright/mcp@0.0.75'] },
  } });
  const clean = json([], dir);
  // Nothing fails, and a question is open: 2.
  assert.equal(clean.status, 2, JSON.stringify(clean.doc.decisions.map((x) => [x.subject.id, x.effect])));
  const open = decisionOf(clean.doc, '.mcp.json:3');
  assert.equal(open.decided_by, 'scope/unanswered');
  assert.equal(open.subject.server, 'broken');
  assert.equal(decisionOf(clean.doc, '.mcp.json:4').effect, 'allow', 'the valid sibling was not checked');
  assert.ok(!decisionOf(clean.doc, '.mcp.json'), 'the file as a whole is not "unreadable"');
  assert.match(check([], dir).stdout, /\? \.mcp\.json:3: server entry "broken" is not an object — it was not checked/);
  // A valid sibling's secret is found, and a finding outranks the open question.
  const withSecret = project({ mcpServers: {
    broken: 42,
    browser: { command: 'npx', args: ['-y', '@playwright/mcp@0.0.75'], env: { GITHUB_TOKEN: TOKEN } },
  } });
  const s = json([], withSecret);
  assert.equal(s.status, 1);
  assert.ok(s.doc.findings.some((f) => f.rule === 'secrets/github-token'));
  assert.ok(s.doc.findings.some((f) => f.rule === 'scope/unanswered' && f.subject.server === 'broken'));
});

test('check: a launch from an overridden source is unknown, with the reason', () => {
  const dir = project({ mcpServers: { tool: { command: 'npx', args: ['-y', '--registry', 'https://registry.example', 'some-pkg@1.0.0'] } } });
  const { status, doc } = json([], dir);
  assert.equal(status, 0);
  const d = decisionOf(doc, '.mcp.json:3');
  assert.equal(d.effect, 'unknown');
  assert.ok(outcomes(d).includes('config/launch-source-override:unknown'), outcomes(d).join(' '));
  assert.equal(check(['--fail-on', 'unknown'], dir).status, 1);
});

test('check: a lookalike name is decided by lookalike/* — a warning for a configured name, as verify --config and audit do', () => {
  // The row (lib/policy_rules.cjs) refuses a lookalike somebody asks for by
  // name (install, explain) and warns about one a config launches; check
  // decides the configured one exactly as verify --config does, so --strict
  // fails it and --allow-lookalike vouches for it.
  const dir = project({ mcpServers: { memory: { command: 'npx', args: ['-y', 'mcp-server-memmory@1.0.0'] } } });
  const { status, doc } = json([], dir);
  const name = doc.decisions.find((d) => d.subject.type === 'name');
  assert.ok(name, 'no name subject');
  assert.equal(name.decided_by, 'lookalike/doubled-letter');
  assert.equal(name.effect, 'warn');
  assert.equal(status, 0);
  assert.equal(check(['--strict'], dir).status, 1);
  const vouched = json(['--strict', '--allow-lookalike', 'memory'], dir).doc.decisions.find((d) => d.subject.type === 'name');
  assert.equal(vouched.effect, 'allow');
  // Rendered on the config line that launches it.
  assert.match(check([], dir).stdout, /^ {2}:3 memory\n(.*\n)* {4}! npm package mcp-server-memmory is not in the vault but looks like mcp-server-memory/m);
});

// ── one decision per line, the same as the command that owns it ────────────

test('consistency: each line of a config is decided by check as verify --config, secrets and lookalike decide it', () => {
  const fixtures = [
    ...fs.readdirSync(SHAPES).map((f) => path.join(SHAPES, f)),
    path.join(ACTION, 'clean', '.mcp.json'), path.join(ACTION, 'clean', '.vscode', 'mcp.json'), path.join(ACTION, 'bad', '.mcp.json'),
  ];
  const extra = [
    { mcpServers: { memory: { command: 'npx', args: ['-y', 'mcp-server-memmory@1.0.0'] } } },
    { mcpServers: { tool: { command: 'npx', args: ['-y', '--registry', 'https://registry.example', 'some-pkg@1.0.0'] } } },
    { mcpServers: { gh: { command: 'npx', args: ['-y', '@playwright/mcp@latest'], env: { GITHUB_TOKEN: TOKEN } } } },
  ];
  const dirs = [...fixtures.map((f) => project(fs.readFileSync(f, 'utf8'))), ...extra.map(project)];
  let compared = 0;
  for (const dir of dirs) {
    for (const flags of [[], ['--strict'], ['--fail-on', 'unknown']]) {
      const label = `${dir} ${flags.join(' ')}`;
      const c = json(flags, dir);
      assert.deepEqual(recompute(c.doc), c.doc.decisions, `${label}: check printed decisions that are not decide()'s`);
      assert.equal(c.status, F.exitCode(c.doc.decisions), `${label}: the exit code is not the decisions'`);

      const v = run(VERIFY, ['--offline', '--json', '--as-of', AS_OF, ...flags, '--config', '.mcp.json'], dir);
      const vdoc = JSON.parse(v.stdout).findings;
      const sdoc = JSON.parse(run(SECRETS, ['--json', '--as-of', AS_OF], dir).stdout).findings;
      for (const d of c.doc.decisions) {
        const owner = [vdoc, sdoc].filter(Boolean).map((x) => decisionOf(x, d.subject.id)).find(Boolean);
        // A subject only check has: what the config's servers do together.
        if (!owner) { assert.ok(['setup', 'tool'].includes(d.subject.type), `${label}: ${d.subject.id} has no owner`); continue; }
        // A secret on a server's own line is decided over both sources: the
        // worse wins. Everything else is one source's subject.
        const both = vdoc && sdoc && decisionOf(vdoc, d.subject.id) && decisionOf(sdoc, d.subject.id);
        if (both) continue;
        assert.deepEqual([d.effect, d.decided_by, d.fails], [owner.effect, owner.decided_by, owner.fails], `${label}: ${d.subject.id}`);
        compared++;
      }
      // And nothing verify or secrets decided is missing from check.
      for (const x of [vdoc, sdoc].filter(Boolean)) {
        for (const d of x.decisions) {
          if (d.subject.type === 'host-config' && !d.subject.line && sdoc === x) continue;   // a clean file, as a whole
          assert.ok(decisionOf(c.doc, d.subject.id), `${label}: ${d.subject.id} is missing from check`);
        }
      }
    }
  }
  assert.ok(compared > 100, `only ${compared} lines compared`);
});

// ── scope, errors, output ──────────────────────────────────────────────────

test('check: without paths it reads the project configs here, and nothing from $HOME', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-vault-check-ownhome-'));
  fs.writeFileSync(path.join(home, '.claude.json'), JSON.stringify({ mcpServers: { x: { command: 'npx', args: ['-y', 'x@latest'], env: { GITHUB_TOKEN: TOKEN } } } }));
  const r = spawnSync(process.execPath, [CHECK, '--json'], { cwd: path.join(ACTION, 'clean'), encoding: 'utf8', env: { ...ENV, HOME: home } });
  assert.equal(r.status, 0, r.stderr);
  const paths = new Set(JSON.parse(r.stdout).decisions.map((d) => (d.subject.type === 'host-config' ? d.subject.path : d.subject.id.replace(/#session$/, ''))));
  assert.deepEqual([...paths].sort(), ['.mcp.json', '.vscode/mcp.json']);
});

test('check: no config is a pass with a note; a named file that is missing or broken is 2', () => {
  const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-vault-check-empty-'));
  const none = check([], empty);
  assert.equal(none.status, 0);
  assert.match(none.stdout, /No MCP config found \(looked for \.mcp\.json, \.cursor\/mcp\.json, \.vscode\/mcp\.json\)/);
  assert.equal(JSON.parse(check(['--json'], empty).stdout).schema, 'mcp-vault/findings@1');

  const missing = json(['nope.json'], empty);
  assert.equal(missing.status, 2);
  assert.equal(missing.doc.decisions[0].decided_by, 'scope/unanswered');

  const broken = project(`{ "mcpServers": { "x": { "env": { "TOKEN": "${TOKEN}" } `);
  const b = check([], broken);
  assert.equal(b.status, 2, b.stdout);
  assert.ok(!(b.stdout + b.stderr).includes(TOKEN.slice(4, 16)), 'a parse error quoted the secret');
  assert.match(b.stdout, /\? \.mcp\.json: not valid JSON/);
  // A finding outranks an incomplete scope.
  assert.equal(check(['nope.json', path.join(ACTION, 'bad', '.mcp.json'), '--strict'], empty).status, 1);
});

test('check: arguments — usage errors are 2', () => {
  const cwd = path.join(ACTION, 'clean');
  for (const args of [['--json', '--sarif'], ['--fail-on', 'maybe'], ['--frobnicate'], ['--policy'], ['--online', '--as-of', '2026-09-30']]) {
    const r = run(CHECK, args, cwd);
    assert.equal(r.status, 2, args.join(' '));
  }
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-vault-check-policy-'));
  assert.equal(check(['--policy', path.join(tmp, 'nope.json')], cwd).status, 2);
  fs.writeFileSync(path.join(tmp, 'p.json'), JSON.stringify({ unverified: 'fail' }));
  // A policy raises the bar: the unpinned fixture's unknown now fails.
  assert.equal(check(['--policy', path.join(tmp, 'p.json')], path.join(ACTION, 'bad')).status, 1);
  assert.equal(check([], path.join(ACTION, 'bad')).status, 0);
});

test('check: plain text when piped — no colour, no feedback line; --json and --sarif are documents', () => {
  const r = check([], path.join(ACTION, 'bad'));
  assert.doesNotMatch(r.stdout, /\x1b\[/);
  assert.doesNotMatch(r.stdout, /issues\/new/);
  const sarif = JSON.parse(check(['--sarif'], path.join(ACTION, 'bad')).stdout);
  assert.equal(sarif.version, '2.1.0');
  assert.ok(sarif.runs[0].results.some((x) => x.ruleId === 'config/unpinned-launch'
    && x.locations[0].physicalLocation.artifactLocation.uri === '.mcp.json' && x.locations[0].physicalLocation.region.startLine === 3));
});

test('check: the feedback line is status\'s — a person at a terminal, not CI', () => {
  const { feedbackLine } = require('../mcp-ecosystem-intelligence/scripts/lib/feedback.cjs');
  const status = require('../mcp-ecosystem-intelligence/scripts/status.cjs');
  assert.equal(status.feedbackLine, feedbackLine);
  // main() with a TTY-like stdout prints it last; with CI set it does not.
  const { main } = require('../mcp-ecosystem-intelligence/scripts/check_configs.cjs');
  const capture = (env) => {
    let out = '';
    const stdout = { isTTY: true, write: (s) => { out += s; return true; } };
    main(['--as-of', AS_OF, '--no-color'], { cwd: path.join(ACTION, 'clean'), stdout, stderr: { write() {} }, env });
    return out;
  };
  assert.match(capture({}).trim().split('\n').pop(), /issues\/new$/);
  assert.doesNotMatch(capture({ CI: 'true' }), /issues\/new/);
  assert.doesNotMatch(capture({}), /\x1b\[/, '--no-color');
});

test('mcp-vault check: reachable through the CLI, listed in --help', () => {
  const r = spawnSync(process.execPath, [BIN, 'check', '--json', '--as-of', AS_OF], { cwd: path.join(ACTION, 'clean'), encoding: 'utf8', env: ENV });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(JSON.parse(r.stdout).schema, 'mcp-vault/findings@1');
  const help = spawnSync(process.execPath, [BIN, '--help'], { encoding: 'utf8' }).stdout;
  assert.match(help, /^ {2}check \[paths…\]/m);
});
