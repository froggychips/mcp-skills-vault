'use strict';
/**
 * The GitHub Action (action.yml), the pre-commit hook, and the `verify
 * --config` / `--policy` flags they are built on.
 *
 * The action's shell steps are pulled out of action.yml and run here with
 * bash, against the fixtures the self-test workflow uses. That workflow only
 * runs in trusted contexts (a PR's action.yml is PR code, and `uses: ./` cannot
 * be jailed), so this is where a pull request finds out it broke the action.
 * Where bash is missing — the jailed PR container is node:alpine — those cases
 * skip rather than pass.
 */

const { test } = require('node:test');
const assert   = require('node:assert/strict');
const fs       = require('node:fs');
const os       = require('node:os');
const path     = require('node:path');
const { spawnSync } = require('node:child_process');

const REPO     = path.resolve(__dirname, '..');
const ACTION   = fs.readFileSync(path.join(REPO, 'action.yml'), 'utf8');
const FIXTURES = path.join(REPO, 'tests', 'fixtures', 'action');
const VERIFY   = path.join(REPO, 'mcp-ecosystem-intelligence', 'scripts', 'verify_integrity.cjs');

const HAS_BASH = spawnSync('bash', ['-c', 'exit 0']).status === 0;

/**
 * The `run: |` block of the step with this id (or name). action.yml is ours
 * and regular; this reads exactly that shape rather than YAML in general.
 */
function runBlock(src, key) {
  const lines = src.split('\n');
  const start = lines.findIndex((l) => l.trim() === `id: ${key}` || l.trim() === `- name: ${key}`);
  assert.ok(start !== -1, `no step ${key} in action.yml`);
  const runIdx = lines.findIndex((l, i) => i > start && /^\s+run: \|\s*$/.test(l));
  const indent = lines[runIdx].match(/^(\s*)/)[1].length;
  const body = [];
  for (let i = runIdx + 1; i < lines.length; i++) {
    const l = lines[i];
    if (l.trim() && l.match(/^(\s*)/)[1].length <= indent) break;
    body.push(l.slice(indent + 2));
  }
  return body.join('\n');
}

const INPUT_DEFAULTS = {
  VAULT_PATHS: '.mcp.json\n.vscode/mcp.json\n.cursor/mcp.json\n',
  VAULT_POLICY: '',
  VAULT_FAIL_ON: 'unverified',
  VAULT_SARIF: 'false',
  VAULT_OFFLINE: 'true',
  VAULT_MODE: 'checkout',
  VAULT_ACTION_REF: '',
  // The test runner's own environment must not decide the signature cases.
  MCP_VAULT_ALLOW_UNSIGNED_DB: '',
  MCP_VAULT_REQUIRE_SIGNED_DB: '',
};

function readOutputs(file) {
  const out = {};
  for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
    const m = line.match(/^([\w-]+)=(.*)$/);
    if (m) out[m[1]] = m[2];
  }
  return out;
}

/** Run one action step in `cwd` with GitHub's file-based step interface. */
function runStep(key, { cwd, env = {} }) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-vault-action-'));
  const outputs = path.join(tmp, 'output');
  const summary = path.join(tmp, 'summary');
  fs.writeFileSync(outputs, '');
  fs.writeFileSync(summary, '');
  // Exactly how GitHub runs a composite step with `shell: bash`:
  // `bash --noprofile --norc -eo pipefail {0}`. Without -e here a step that
  // dies on the CLI's exit 1 looked fine in the test and broke in CI.
  const r = spawnSync('bash', ['--noprofile', '--norc', '-eo', 'pipefail', '-c', runBlock(ACTION, key)], {
    cwd,
    encoding: 'utf8',
    env: {
      ...process.env,
      GITHUB_ACTION_PATH: REPO,
      GITHUB_OUTPUT: outputs,
      GITHUB_STEP_SUMMARY: summary,
      RUNNER_TEMP: tmp,
      VAULT_CLI: path.join(REPO, 'bin', 'mcp-vault.cjs'),
      ...INPUT_DEFAULTS,
      ...env,
    },
  });
  return { ...r, outputs: readOutputs(outputs), summary: fs.readFileSync(summary, 'utf8'), tmp };
}

// ── action.yml as a manifest ───────────────────────────────────────────────

test('action.yml: every action it uses is pinned to a full commit SHA', () => {
  const refs = [...ACTION.matchAll(/^\s*(?:-\s+)?uses:\s*(\S+)/gm)].map((m) => m[1]);
  assert.ok(refs.length >= 2, 'expected setup-node and upload-sarif');
  for (const ref of refs) {
    assert.match(ref, /@[0-9a-f]{40}$/, `mutable ref in action.yml: ${ref}`);
  }
});

test('action.yml: no expression is pasted into a script body', () => {
  // `${{ inputs.x }}` inside run: is substituted into the script text before
  // bash parses it — an input would be code. Inputs go through env.
  for (const key of ['cli', 'verify', 'Enforce']) {
    assert.doesNotMatch(runBlock(ACTION, key), /\$\{\{/, `step ${key} interpolates an expression into its script`);
  }
});

test('action.yml: the CLI is never installed or run through npx', () => {
  const scripts = ['cli', 'verify', 'Enforce'].map((k) => runBlock(ACTION, k)).join('\n');
  assert.doesNotMatch(scripts, /\bnpx\b/);
  assert.doesNotMatch(scripts, /npm (install|i|ci|exec)\b/);
  assert.match(scripts, /npm pack [^\n]*--ignore-scripts/);
  // Default: the action's own checkout, i.e. exactly the commit `uses:` names.
  // Line by line: the `default:` of the `version:` input, before the next input.
  const lines = ACTION.split('\n');
  const at = lines.findIndex((l) => l === '  version:');
  assert.ok(at !== -1, 'no version input');
  const next = lines.findIndex((l, i) => i > at && /^  \S/.test(l));
  assert.ok(lines.slice(at + 1, next).some((l) => l.trim() === "default: ''"), 'version input must default to empty');
});

test('action.yml: the default paths are the project-scoped configs of every host', () => {
  const { HOSTS } = require('../mcp-ecosystem-intelligence/scripts/lib/hosts.cjs');
  const cwd = '/repo';
  for (const host of HOSTS) {
    if (!host.scopes.project) continue;
    const rel = path.relative(cwd, host.scopes.project({ cwd })).split(path.sep).join('/');
    assert.ok(INPUT_DEFAULTS.VAULT_PATHS.split('\n').includes(rel), `${host.id}: ${rel} missing from the test defaults`);
    const escaped = rel.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    assert.match(ACTION, new RegExp(`^\\s+${escaped}$`, 'm'), `${host.id}: ${rel} missing from action.yml paths default`);
  }
});

test('fixtures: the clean config pins the versions the DB has hashes for', () => {
  // If the DB moves a pin, the self-test's "clean" fixture turns unverified;
  // better to be told here, by name, than by a red workflow after merge.
  const db = require('../mcp-ecosystem-intelligence/assets/tools_database.json');
  const byName = new Map(db.tools.map((t) => [t.name, t]));
  const { readInstalledServers, explicitConfigPaths } = require('../mcp-ecosystem-intelligence/scripts/lib/installed.cjs');
  const cwd = path.join(FIXTURES, 'clean');
  const servers = readInstalledServers({ paths: explicitConfigPaths(['.mcp.json', '.vscode/mcp.json'], { cwd }) });
  assert.equal(servers.length, 2);
  for (const s of servers) {
    const entry = byName.get(s.name);
    assert.ok(entry && entry.pkg_integrity, `${s.name}: not a hashed DB entry`);
    assert.equal(s.install_cmd, entry.install_cmd, `${s.name}: fixture pin differs from the DB — update tests/fixtures/action/clean`);
  }
});

// ── the action's shell, run ────────────────────────────────────────────────

test('action: a clean config passes and says so in the job summary', { skip: !HAS_BASH && 'no bash' }, () => {
  const r = runStep('verify', { cwd: path.join(FIXTURES, 'clean') });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.outputs['exit-code'], '0', r.stdout + r.stderr);
  assert.match(r.summary, /\*\*OK\*\* — 2 servers checked, 0 failing, 0 unverified \(fail on: unknown,/);
  assert.match(r.summary, /\| playwright-mcp \| allow \| finding\/none \| \.mcp\.json:3 \| — \|/);
  assert.match(r.summary, /\| mongodb-mcp-server \| allow \| finding\/none \| \.vscode\/mcp\.json:3 \| — \|/);
  const report = JSON.parse(fs.readFileSync(r.outputs.report, 'utf8'));
  assert.equal(report.subject, 'installed');
  assert.equal(report.mode, 'offline');
});

test('action: an unpinned server fails at the default fail-on, passes at fail-on: error', { skip: !HAS_BASH && 'no bash' }, () => {
  const cwd = path.join(FIXTURES, 'bad');
  const strict = runStep('verify', { cwd });
  assert.equal(strict.outputs['exit-code'], '1', strict.stdout + strict.stderr);
  assert.match(strict.summary, /\*\*FAIL\*\*/);
  assert.match(strict.summary, /\| playwright-mcp \| unknown \(fails\) \| finding\/incomplete \| \.mcp\.json:3 \|/);
  const lenient = runStep('verify', { cwd, env: { VAULT_FAIL_ON: 'error' } });
  assert.equal(lenient.outputs['exit-code'], '0');
  assert.match(lenient.summary, /\*\*UNVERIFIED\*\*/);
  // fail-on is the decision's fail_on, whichever spelling the input used.
  for (const [input, failOn] of [['error', 'deny'], ['deny', 'deny'], ['unverified', 'unknown'], ['unknown', 'unknown'], ['warning', 'warn'], ['warn', 'warn']]) {
    const run = runStep('verify', { cwd, env: { VAULT_FAIL_ON: input } });
    const doc = JSON.parse(fs.readFileSync(run.outputs.report, 'utf8')).findings;
    assert.equal(doc.decisions[0].fail_on, failOn, `fail-on: ${input}`);
    assert.equal(run.outputs['exit-code'], failOn === 'deny' ? '0' : '1', `fail-on: ${input}`);
  }
});

test('action: no config in the repo is a pass with a note, not a crash', { skip: !HAS_BASH && 'no bash' }, () => {
  const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-vault-empty-'));
  const r = runStep('verify', { cwd: empty });
  assert.equal(r.outputs['exit-code'], '0');
  assert.match(r.summary, /No MCP config found/);
  // No report was written, so no `report` output points at one.
  assert.equal(r.outputs.report, undefined);
});

test('action: globs are expanded and duplicates collapse', { skip: !HAS_BASH && 'no bash' }, () => {
  const r = runStep('verify', { cwd: path.join(FIXTURES, 'clean'), env: { VAULT_PATHS: '.mcp.json **/mcp.json .mcp.json' } });
  assert.equal(r.outputs['exit-code'], '0', r.stdout + r.stderr);
  const report = JSON.parse(fs.readFileSync(r.outputs.report, 'utf8'));
  assert.equal(report.checked, 2);
});

test('action: an invalid input is exit 2, and Enforce fails the job on it', { skip: !HAS_BASH && 'no bash' }, () => {
  const r = runStep('verify', { cwd: path.join(FIXTURES, 'clean'), env: { VAULT_FAIL_ON: 'nope' } });
  assert.equal(r.outputs['exit-code'], '2');
  for (const [code, status] of [['0', 0], ['1', 1], ['2', 2], ['', 2]]) {
    const e = runStep('Enforce', { cwd: REPO, env: { VAULT_EXIT: code } });
    assert.equal(e.status, status, `exit-code "${code}"`);
  }
});

test('action: sarif puts the finding on the config line that launches the server', { skip: !HAS_BASH && 'no bash' }, () => {
  const r = runStep('verify', { cwd: path.join(FIXTURES, 'bad'), env: { VAULT_SARIF: 'true' } });
  const sarif = JSON.parse(fs.readFileSync(r.outputs['sarif-file'], 'utf8'));
  const results = sarif.runs[0].results;
  for (const result of results) {
    assert.equal(result.locations[0].physicalLocation.artifactLocation.uri, '.mcp.json');
    assert.equal(result.locations[0].physicalLocation.region.startLine, 3);
    assert.equal(result.properties.subject, '.mcp.json:3');
  }
  // The findings model's SARIF: rule ids are finding rules, subjects host-config.
  // `@latest` is the config's own problem (config/unpinned-launch), and the
  // gate's "nothing to compare" (pin/missing) is reported beside it.
  assert.deepEqual(results.map((r) => r.ruleId).sort(), ['config/unpinned-launch', 'pin/missing']);
  assert.match(results.find((r) => r.ruleId === 'config/unpinned-launch').message.text, /@playwright\/mcp@latest, a tag rather than a version/);
});

test('action: a version that is not exact is refused before anything is fetched', { skip: !HAS_BASH && 'no bash' }, () => {
  for (const v of ['latest', '^0.15.0', '0.15', 'next']) {
    const r = runStep('cli', { cwd: REPO, env: { VAULT_VERSION: v, VAULT_INTEGRITY: '' } });
    assert.equal(r.status, 2, `${v}: ${r.stdout}`);
    assert.match(r.stdout, /must be an exact version/);
  }
  const own = runStep('cli', { cwd: REPO, env: { VAULT_VERSION: '', VAULT_INTEGRITY: '' } });
  assert.equal(own.status, 0);
  assert.equal(own.outputs.cli, path.join(REPO, 'bin', 'mcp-vault.cjs'));
});

/**
 * The action as GitHub unpacks `uses: owner/repo@<sha>`: the commit's files,
 * no .git, and no DB signature (that is made at release and is not in git).
 */
function unpackedAction() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-vault-uses-'));
  for (const p of ['action.yml', 'package.json', 'bin', 'mcp-ecosystem-intelligence']) {
    fs.cpSync(path.join(REPO, p), path.join(dir, p), { recursive: true, filter: (src) => !src.endsWith('.sig') });
  }
  return dir;
}

test('action: its own checkout without .git (uses: @sha) runs, integrity pinned by the SHA', { skip: !HAS_BASH && 'no bash' }, () => {
  const dir = unpackedAction();
  const sha = 'a'.repeat(40);
  const r = runStep('verify', {
    cwd: path.join(FIXTURES, 'clean'),
    env: { GITHUB_ACTION_PATH: dir, VAULT_CLI: path.join(dir, 'bin', 'mcp-vault.cjs'), VAULT_MODE: 'checkout', VAULT_ACTION_REF: sha },
  });
  assert.equal(r.outputs['exit-code'], '0', r.stdout + r.stderr);
  assert.match(r.summary, /\*\*OK\*\*/);
  assert.ok(r.summary.includes(`DB integrity: pinned by action SHA ${sha}`), r.summary);
  // The allowance is this step's alone, and only for a missing signature: a
  // .sig that is present still has to verify.
  fs.writeFileSync(path.join(dir, 'mcp-ecosystem-intelligence', 'assets', 'tools_database.json.sig'), '{"not":"a signature"}');
  const tampered = runStep('verify', {
    cwd: path.join(FIXTURES, 'clean'),
    env: { GITHUB_ACTION_PATH: dir, VAULT_CLI: path.join(dir, 'bin', 'mcp-vault.cjs'), VAULT_MODE: 'checkout', VAULT_ACTION_REF: sha },
  });
  assert.equal(tampered.outputs['exit-code'], '1', tampered.stdout + tampered.stderr);
  assert.match(tampered.stderr, /refusing to use the DB/);
});

test('action: the npm package (version:) without a .sig is refused — the tarball must carry one', { skip: !HAS_BASH && 'no bash' }, () => {
  const pkg = unpackedAction();
  const r = runStep('verify', {
    cwd: path.join(FIXTURES, 'clean'),
    // An allowance in the caller's env does not reach the package mode.
    env: { VAULT_CLI: path.join(pkg, 'bin', 'mcp-vault.cjs'), VAULT_MODE: 'package', MCP_VAULT_ALLOW_UNSIGNED_DB: '1' },
  });
  assert.equal(r.outputs['exit-code'], '1', r.stdout + r.stderr);
  assert.match(r.stderr, /refusing to use the DB/);
  assert.match(r.summary, /DB integrity: Ed25519 signature, checked by the CLI/);
});

test('action: the resolve step says which mode it picked', { skip: !HAS_BASH && 'no bash' }, () => {
  const own = runStep('cli', { cwd: REPO, env: { VAULT_VERSION: '', VAULT_INTEGRITY: '' } });
  assert.equal(own.outputs.mode, 'checkout');
});

// ── pre-commit hook ────────────────────────────────────────────────────────

test('.pre-commit-hooks.yaml: hook mcp-vault ends in --config and matches every host config', () => {
  const src = fs.readFileSync(path.join(REPO, '.pre-commit-hooks.yaml'), 'utf8');
  assert.match(src, /^- id: mcp-vault$/m);
  // pre-commit appends the staged file names; --config takes them all.
  assert.match(src, /^\s+entry: mcp-vault verify [^\n]*--config$/m);
  // YAML single quotes keep backslashes literal, so the text is the regex.
  const files = new RegExp(src.match(/^\s+files: '(.*)'$/m)[1]);
  for (const p of ['.mcp.json', '.vscode/mcp.json', '.cursor/mcp.json', 'pkg/a/.mcp.json']) {
    assert.match(p, files, `${p} not matched`);
  }
  for (const p of ['mcp.json', 'package.json', '.mcp.json.bak', '.mcp-vault.policy.json']) {
    assert.doesNotMatch(p, files, `${p} should not match`);
  }
});

// ── verify --config / --policy ─────────────────────────────────────────────

const runVerify = (args, cwd = REPO) => spawnSync(process.execPath, [VERIFY, ...args], { cwd, encoding: 'utf8' });

test('verify --config: checks exactly the named files, and reads nothing else', () => {
  const r = runVerify(['--offline', '--json', '--config', '.mcp.json', '.vscode/mcp.json'], path.join(FIXTURES, 'clean'));
  assert.equal(r.status, 0, r.stderr);
  const doc = JSON.parse(r.stdout).findings;
  assert.equal(doc.schema, 'mcp-vault/findings@1');
  assert.deepEqual(doc.decisions.map((d) => [d.subject.type, d.subject.id, d.subject.server, d.subject.host, d.effect]), [
    ['host-config', '.mcp.json:3', 'playwright-mcp', 'claude-code', 'allow'],
    ['host-config', '.vscode/mcp.json:3', 'mongodb-mcp-server', 'vscode', 'allow'],
  ]);
});

test('verify --config: file names after later flags still count (pre-commit appends args, then files)', () => {
  const r = runVerify(['--offline', '--json', '--config', '--cwd', path.join(FIXTURES, 'clean'), '--fail-unverified', '.mcp.json', '.vscode/mcp.json']);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(JSON.parse(r.stdout).checked, 2);
  assert.equal(JSON.parse(r.stdout).fail_unverified, true);
});

test('verify --config: a named file that does not exist is exit 2, not a clean run', () => {
  const r = runVerify(['--offline', '--json', '--config', 'no-such.json'], path.join(FIXTURES, 'clean'));
  assert.equal(r.status, 2);
  const report = JSON.parse(r.stdout);
  assert.match(report.installed_config_problems[0].error, /file not found/);
});

test('verify --config with no path is a usage error, not a DB run', () => {
  const r = runVerify(['--offline', '--config']);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /--config needs at least one path/);
});

test('verify --policy: a named policy is enforced, a missing one is refused', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-vault-policy-'));
  const policy = path.join(tmp, 'p.json');
  fs.writeFileSync(policy, JSON.stringify({ unverified: 'fail' }));
  const bad = path.join(FIXTURES, 'bad');
  assert.equal(runVerify(['--offline', '--config', '.mcp.json'], bad).status, 0);
  assert.equal(runVerify(['--offline', '--config', '.mcp.json', '--policy', policy], bad).status, 1);
  const missing = runVerify(['--offline', '--config', '.mcp.json', '--policy', path.join(tmp, 'nope.json')], bad);
  assert.equal(missing.status, 2);
  assert.match(missing.stderr, /policy error/);
  assert.equal(runVerify(['--offline', '--policy', policy, '--no-policy']).status, 2);
});

test('verify --fail-on: the decision\'s threshold, the same as the flag it names', () => {
  const bad = path.join(FIXTURES, 'bad');
  const doc = (args) => JSON.parse(runVerify(['--offline', '--json', ...args, '--config', '.mcp.json'], bad).stdout).findings;
  const strip = (d) => d.decisions.map(({ as_of, ...rest }) => rest);
  assert.deepEqual(strip(doc(['--fail-on', 'warn'])), strip(doc(['--strict'])));
  assert.deepEqual(strip(doc(['--fail-on', 'unknown'])), strip(doc(['--fail-unverified'])));
  assert.deepEqual(strip(doc(['--fail-on', 'deny'])), strip(doc([])));
  // A flag raises the bar and never lowers it: a policy that fails unverified
  // keeps doing so under --fail-on deny.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-vault-failon-'));
  fs.writeFileSync(path.join(tmp, 'p.json'), JSON.stringify({ unverified: 'fail' }));
  assert.equal(runVerify(['--offline', '--fail-on', 'deny', '--policy', path.join(tmp, 'p.json'), '--config', '.mcp.json'], bad).status, 1);
  const nope = runVerify(['--offline', '--fail-on', 'maybe', '--config', '.mcp.json'], bad);
  assert.equal(nope.status, 2);
  assert.match(nope.stderr, /--fail-on must be deny, unknown or warn/);
});

test('verify --config --sarif: a policy outcome with no finding is annotated at the config line', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-vault-lic-'));
  fs.writeFileSync(path.join(tmp, 'p.json'), JSON.stringify({ licenses: { allow: ['NO-SUCH-LICENSE'] } }));
  const clean = path.join(FIXTURES, 'clean');
  const r = runVerify(['--offline', '--sarif', '--policy', path.join(tmp, 'p.json'), '--config', '.mcp.json'], clean);
  assert.equal(r.status, 1, r.stderr);
  const [res] = JSON.parse(r.stdout).runs[0].results.filter((x) => x.ruleId === 'policy/license');
  assert.ok(res, 'no policy/license result');
  assert.equal(res.level, 'error');
  assert.equal(res.properties.effect, 'deny');
  assert.deepEqual([res.locations[0].physicalLocation.artifactLocation.uri, res.locations[0].physicalLocation.region.startLine], ['.mcp.json', 3]);
});

// ── libraries ──────────────────────────────────────────────────────────────

test('explicitConfigPaths: labels the host from the file name', () => {
  const { explicitConfigPaths } = require('../mcp-ecosystem-intelligence/scripts/lib/installed.cjs');
  const got = explicitConfigPaths(['.mcp.json', '.vscode/mcp.json', '.cursor/mcp.json', 'x/config.toml', 'other.json'], { cwd: '/r' })
    .map((l) => [l.host, l.path, l.explicit]);
  assert.deepEqual(got, [
    ['claude-code', path.resolve('/r/.mcp.json'), true],
    ['vscode', path.resolve('/r/.vscode/mcp.json'), true],
    ['cursor', path.resolve('/r/.cursor/mcp.json'), true],
    ['codex', path.resolve('/r/x/config.toml'), true],
    ['custom', path.resolve('/r/other.json'), true],
  ]);
});

test('serverLine: the line that names a server, in JSON and Codex TOML', () => {
  const { serverLine } = require('../mcp-ecosystem-intelligence/scripts/lib/installed.cjs');
  assert.equal(serverLine('{\n  "mcpServers": {\n    "a": {}\n  }\n}', 'a'), 3);
  assert.equal(serverLine('x = 1\n[mcp_servers.b]\ncommand = "npx"', 'b'), 2);
  assert.equal(serverLine('{}', 'a'), null);
});

test('job summary: renders the Decisions — verdict, config line, escaped cells', () => {
  const F = require('../mcp-ecosystem-intelligence/scripts/lib/finding.cjs');
  const { toMarkdown } = require('../mcp-ecosystem-intelligence/scripts/lib/job_summary.cjs');
  const s = F.subject.hostConfig({ path: '.vscode/mcp.json', line: 4, host: 'vscode', server: 'a|b' });
  const f = F.finding({ rule: 'verify/check-failed', subject: s, severity: 'high', message: 'integrity\nmismatch \\| x' });
  const d = F.decision({ subject: s, effect: 'deny', decided_by: 'finding/severity', as_of: 0, findings: [f.id],
    rules: [{ rule: 'finding/severity', effect: 'deny', detail: f.message, findings: [f.id] }] });
  const md = toMarkdown({ mode: 'offline', findings: { as_of: '1970-01-01T00:00:00.000Z', decisions: [d] } });
  assert.match(md, /\*\*FAIL\*\* — 1 server checked, 1 failing, 0 unverified \(fail on: deny, mode: offline/);
  assert.ok(md.includes('| a\\|b | deny (fails) | finding/severity | .vscode/mcp.json:4 | finding/severity: integrity mismatch \\\\\\| x |'), md);
  assert.match(toMarkdown({}), /no `mcp-vault\/findings@1` document/);
});
