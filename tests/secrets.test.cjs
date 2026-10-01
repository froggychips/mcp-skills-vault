'use strict';
/**
 * Plain-text secrets in host configs.
 *
 * The property that matters most is the one a quick implementation gets wrong:
 * the value must never come back out — not in the text report, not in --json,
 * not in SARIF, not in the suggested edit, not through `audit` or `status`.
 * A scanner that prints the token it found has made a second copy of it in a
 * CI log. Those tests spawn the real CLIs and grep their whole output.
 *
 * Every fixture token is assembled at runtime from a seeded generator, so no
 * string in this file looks like a real credential to a push-protection scan.
 */

const test   = require('node:test');
const assert = require('node:assert/strict');
const fs     = require('fs');
const os     = require('os');
const path   = require('path');
const { spawnSync } = require('child_process');

const S = require('../mcp-ecosystem-intelligence/scripts/lib/secrets.cjs');
const SCRIPTS = path.resolve(__dirname, '../mcp-ecosystem-intelligence/scripts');

// Deterministic "random" characters: fixtures are reproducible, never real.
function gen(n, alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789', seed = 7) {
  let x = seed; let out = '';
  for (let i = 0; i < n; i++) { x = (x * 1103515245 + 12345) & 0x7fffffff; out += alphabet[x % alphabet.length]; }
  return out;
}
const UP = 'ABCDEFGHJKLMNPQRSTUVWXYZ234567';

const T = {
  github:    ['gh', 'p_'].join('') + gen(36, undefined, 1),
  githubPat: ['github', '_pat_'].join('') + gen(60, undefined, 2),
  gitlab:    ['gl', 'pat-'].join('') + gen(20, undefined, 3),
  aws:       ['AK', 'IA'].join('') + gen(16, UP, 4),
  slack:     ['xo', 'xb-'].join('') + gen(12, '0123456789', 5) + '-' + gen(24, undefined, 5),
  openai:    ['sk', '-proj-'].join('') + gen(40, undefined, 6),
  anthropic: ['sk', '-ant-'].join('') + 'api03-' + gen(40, undefined, 8),
  stripe:    ['sk', '_live_'].join('') + gen(24, undefined, 9),
  google:    ['AI', 'za'].join('') + gen(35, undefined, 10),
  jwt:       ['ey', 'J'].join('') + gen(20, undefined, 11) + '.eyJ' + gen(20, undefined, 12) + '.' + gen(30, undefined, 13),
  pem:       ['-----BEGIN ', 'PRIVATE KEY-----'].join('') + '\n' + gen(64, undefined, 14) + '\n-----END PRIVATE KEY-----',
  dbPass:    gen(18, undefined, 15),
  bearer:    gen(32, undefined, 16),
  query:     gen(24, undefined, 17),
  heuristic: gen(28, undefined, 18),
  headerKey: gen(24, undefined, 19),
  codex:     ['gl', 'pat-'].join('') + gen(22, undefined, 20),
  codexHdr:  gen(26, undefined, 21),
  local:     ['gh', 'p_'].join('') + gen(36, undefined, 22),
};

function rulesOf(value, name) { return S.scanString(value, { name }).map((h) => h.rule); }

// ── detection ──────────────────────────────────────────────────────────────

test('every known format is detected by its own rule', () => {
  assert.deepEqual(rulesOf(T.github), ['github-token']);
  assert.deepEqual(rulesOf(T.githubPat), ['github-pat']);
  assert.deepEqual(rulesOf(T.gitlab), ['gitlab-token']);
  assert.deepEqual(rulesOf(T.aws), ['aws-access-key']);
  assert.deepEqual(rulesOf(T.slack), ['slack-token']);
  assert.deepEqual(rulesOf(T.openai), ['openai-key']);
  assert.deepEqual(rulesOf(T.anthropic), ['anthropic-key'], 'sk-ant- must not also be reported as a generic sk- key');
  assert.deepEqual(rulesOf(T.stripe), ['stripe-live-key']);
  assert.deepEqual(rulesOf(T.google), ['google-api-key']);
  assert.deepEqual(rulesOf(T.jwt), ['jwt']);
  assert.deepEqual(rulesOf(T.pem), ['private-key']);
  assert.deepEqual(rulesOf(`postgres://admin:${T.dbPass}@db:5432/app`), ['connection-string']);
  assert.deepEqual(rulesOf(`mongodb+srv://u:${T.dbPass}@c.example.net/x`), ['connection-string']);
  assert.deepEqual(rulesOf(`https://u:${T.dbPass}@example.com/`), ['url-credentials']);
  assert.deepEqual(rulesOf(`https://x.example/mcp?api_key=${T.query}`), ['url-query-token']);
  assert.deepEqual(rulesOf(`Authorization: Bearer ${T.bearer}`), ['bearer-token']);
});

test('the heuristic needs a credential-shaped name and a literal high-entropy value', () => {
  assert.deepEqual(rulesOf(T.heuristic, 'MY_SERVICE_API_KEY'), ['named-secret']);
  assert.deepEqual(rulesOf(`AWS_SECRET_ACCESS_KEY=${T.heuristic}`, 'args'), ['named-secret'], 'docker -e NAME=value names itself');
  assert.deepEqual(rulesOf(`--api-key=${T.heuristic}`), ['named-secret']);
  assert.deepEqual(rulesOf(T.heuristic, 'LOG_LEVEL'), [], 'not a credential name');
  assert.deepEqual(rulesOf('3600', 'TOKEN_TTL'), []);
  assert.deepEqual(rulesOf('aaaaaaaaaaaaaaaaaaaaaaaa', 'API_KEY'), [], 'low entropy');
  assert.deepEqual(rulesOf('/Users/me/keys/service.json', 'GOOGLE_APPLICATION_CREDENTIALS'), [], 'a path to a key');
  assert.deepEqual(rulesOf(T.heuristic, 'API_KEY_PATH'), [], 'a name about a key');
  assert.deepEqual(rulesOf('your-api-key-here', 'API_KEY'), []);
  assert.deepEqual(rulesOf('<YOUR_TOKEN>', 'GITHUB_TOKEN'), []);
});

test('a reference in any host syntax is not a secret', () => {
  for (const ref of ['${GITHUB_TOKEN}', '${GITHUB_TOKEN:-}', '${env:GITHUB_TOKEN}', '${input:github-token}', '$GITHUB_TOKEN',
    'Bearer ${API_TOKEN}', 'postgres://admin:${DB_PASSWORD}@db/app', 'https://x.example/mcp?api_key=${KEY}']) {
    assert.deepEqual(rulesOf(ref, 'GITHUB_TOKEN'), [], ref);
  }
});

test('Codex TOML: inline env, env sub-table, headers and multi-line args are read; env var names are not secrets', () => {
  const doc = S.parseCodexTomlServers([
    'model = "o4"',
    '[mcp_servers.gl]',
    'command = "npx"',
    'args = [',
    '  "-y",',
    `  "--token=${T.heuristic}",`,
    ']',
    `env = { GITLAB_TOKEN = "${T.codex}", OTHER = "x" }`,
    'env_vars = ["GITHUB_TOKEN_FORWARDED"]',
    '[mcp_servers.gl.http_headers]',
    `"X-Api-Token" = "${T.codexHdr}"`,
    '[mcp_servers.gh.env]',
    `GITHUB_TOKEN = '${T.github}'`,
    '[profiles.x]',
    `api_key = "${T.openai}"`,
  ].join('\n'));
  const found = S.scanDocument(doc, { host: 'codex', scope: 'user', path: 'config.toml' });
  const paths = found.map((f) => f.path).sort();
  assert.deepEqual(paths, [
    'mcp_servers.gh.env.GITHUB_TOKEN',
    'mcp_servers.gl.args[1]',
    'mcp_servers.gl.env.GITLAB_TOKEN',
    'mcp_servers.gl.http_headers.X-Api-Token',
  ], 'everything outside mcp_servers (the profiles table) is not read');
});

test('~/.claude.json: per-project server maps are scanned, Claude Code’s own auth state is not', () => {
  const doc = {
    oauthAccount: { accessToken: T.anthropic },
    primaryApiKey: T.anthropic,
    mcpServers: {},
    projects: { '/work/app': { mcpServers: { gh: { command: 'npx', env: { GITHUB_TOKEN: T.local } } } } },
  };
  const found = S.scanDocument(doc, { host: 'claude-code', scope: 'user', path: '.claude.json' });
  assert.equal(found.length, 1);
  assert.equal(found[0].path, 'projects["/work/app"].mcpServers.gh.env.GITHUB_TOKEN');
  assert.equal(found[0].scope, 'local');
});

test('the mask shows at most four characters, and none for a heuristic match', () => {
  const [gh] = S.scanDocument({ mcpServers: { a: { env: { GITHUB_TOKEN: T.github } } } }, { host: 'claude-code', scope: 'project' });
  assert.equal(gh.masked, 'ghp_…');
  assert.equal(gh.length, T.github.length);
  const [h] = S.scanDocument({ mcpServers: { a: { env: { MY_API_KEY: T.heuristic } } } }, { host: 'claude-code', scope: 'project' });
  assert.equal(h.masked, '…');
  assert.equal(h.confidence, 'heuristic');
  for (const f of [gh, h]) assert.equal(Object.getOwnPropertySymbols(f).length, 0, 'no hidden copy of the value');
});

// ── the value never comes back out ─────────────────────────────────────────

function fixture() {
  const cwd  = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-secrets-'));
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-secrets-home-'));
  fs.mkdirSync(path.join(cwd, '.cursor'));
  fs.mkdirSync(path.join(cwd, '.vscode'));
  fs.mkdirSync(path.join(home, '.codex'));
  fs.writeFileSync(path.join(cwd, '.mcp.json'), JSON.stringify({ mcpServers: {
    github: { command: 'npx', args: ['-y', 'x@1.0.0'], env: {
      GITHUB_TOKEN: T.github, PAT: T.githubPat, GITLAB: T.gitlab, AWS_ACCESS_KEY_ID: T.aws, SLACK: T.slack,
      OPENAI: T.openai, ANTHROPIC: T.anthropic, STRIPE: T.stripe, GOOGLE: T.google, JWT: T.jwt, PEM: T.pem,
      MY_SERVICE_API_KEY: T.heuristic, SAFE: '${SAFE_TOKEN}',
    } },
    remote: { command: 'npx', args: ['mcp-remote', `https://x.example/mcp?api_key=${T.query}`, '--header', `Authorization: Bearer ${T.bearer}`] },
    db: { command: 'uvx', args: ['pg-mcp', `postgres://admin:${T.dbPass}@db:5432/app`] },
  } }, null, 2));
  fs.writeFileSync(path.join(cwd, '.cursor', 'mcp.json'), JSON.stringify({ mcpServers: { s: { url: 'https://api.example', headers: { 'X-Api-Key': T.headerKey } } } }));
  fs.writeFileSync(path.join(cwd, '.vscode', 'mcp.json'), JSON.stringify({ servers: { v: { command: 'docker', args: ['run', '-e', `AWS_SECRET_ACCESS_KEY=${T.heuristic}`, 'img'] } } }));
  fs.writeFileSync(path.join(home, '.codex', 'config.toml'),
    `[mcp_servers.gl]\ncommand = "npx"\nenv = { GITLAB_TOKEN = "${T.codex}" }\n[mcp_servers.gl.http_headers]\n"X-Token" = "${T.codexHdr}"\n`);
  fs.writeFileSync(path.join(home, '.claude.json'), JSON.stringify({
    projects: { [cwd]: { mcpServers: { local: { command: 'npx', env: { GITHUB_TOKEN: T.local } } } } },
  }));
  return { cwd, home };
}

function run(script, args, { cwd, home }) {
  return spawnSync(process.execPath, [path.join(SCRIPTS, script), '--cwd', cwd, ...args], {
    encoding: 'utf8', env: { ...process.env, HOME: home, NO_COLOR: '1' },
  });
}

/** The secret part of each fixture: what follows the format's public prefix. */
function secretBodies() {
  return Object.values(T).map((v) => v.replace(/^(ghp_|github_pat_|glpat-|AKIA|xoxb-|sk-proj-|sk-ant-|sk_live_|AIza|eyJ|-----BEGIN PRIVATE KEY-----\n)/, ''));
}

function assertNoLeak(output, where) {
  for (const body of secretBodies()) {
    // Any eight consecutive characters of the secret is a leak, not just the
    // whole value: a "truncated" preview is still the credential's entropy.
    for (let i = 0; i + 8 <= body.length; i += 4) {
      const window = body.slice(i, i + 8);
      if (/\n/.test(window)) continue;
      assert.ok(!output.includes(window), `${where} printed part of a secret value (${window.length} chars at offset ${i})`);
    }
  }
}

test('secrets: text, --json (findings@1 included), --sarif, --fix-suggest and --explain never contain a secret value', () => {
  const fx = fixture();
  for (const args of [[], ['--json'], ['--sarif'], ['--fix-suggest'], ['--json', '--fix-suggest'], ['--sarif', '--fix-suggest'],
    ['--explain'], ['--explain', '--fix-suggest']]) {
    const r = run('check_secrets.cjs', ['--no-git', ...args], fx);
    assert.equal(r.status, 1, `secrets ${args.join(' ')} exited ${r.status}: ${r.stderr}`);
    assertNoLeak(r.stdout + r.stderr, `secrets ${args.join(' ') || '(text)'}`);
  }
});

test('secrets --json: every fixture is found, with type, file, path, length and a short mask', () => {
  const fx = fixture();
  const r = run('check_secrets.cjs', ['--json', '--no-git'], fx);
  const doc = JSON.parse(r.stdout);
  assert.equal(doc.schema, 'mcp-vault/secrets@1');
  assert.equal(doc.findings.schema, 'mcp-vault/findings@1');
  const found = doc.findings.findings;
  const rules = new Set(found.map((f) => f.rule));
  for (const rule of ['github-token', 'github-pat', 'gitlab-token', 'aws-access-key', 'slack-token', 'openai-key',
    'anthropic-key', 'stripe-live-key', 'google-api-key', 'jwt', 'private-key', 'connection-string',
    'url-query-token', 'bearer-token', 'named-secret']) {
    assert.ok(rules.has(`secrets/${rule}`), `no secrets/${rule} finding`);
  }
  for (const f of found) {
    assert.equal(f.subject.type, 'host-config');
    assert.equal(f.subject.id, `${f.subject.path}${f.subject.line ? `:${f.subject.line}` : ''}`);
    assert.equal(f.state, 'observed');
    assert.equal(f.confidence, f.rule === 'secrets/named-secret' ? 'medium' : 'high');
  }
  assert.equal(doc.secrets.length, found.length, 'one detail per finding');
  for (const d of doc.secrets) {
    assert.ok(found.some((f) => f.id === d.finding), `${d.path}: detail names no finding`);
    for (const k of ['type', 'path', 'length', 'masked', 'recommendation']) assert.ok(d[k] !== undefined && d[k] !== null, `${d.path}: no ${k}`);
    assert.ok(d.masked.replace(/…$/, '').length <= 4, `${d.path}: mask ${d.masked} shows more than 4 characters`);
    assert.equal(d.tracked, null, '--no-git: not established, not false');
  }
  assert.ok(!doc.secrets.some((d) => /SAFE/.test(d.path)), 'a ${VAR} reference was reported');
  const hosts = new Set(found.map((f) => f.subject.host));
  assert.deepEqual([...hosts].sort(), ['claude-code', 'codex', 'cursor', 'vscode']);
  // An untracked secret is medium — and still refused: the secrets/* row
  // decides, not the severity ladder.
  const denied = doc.findings.decisions.filter((d) => d.effect === 'deny');
  assert.ok(denied.length && denied.every((d) => d.decided_by.startsWith('secrets/') && d.fails));
  assert.equal(r.status, 1);
});

test('decide(): a secrets/* finding is denied by its row at any severity; the trace carries no value', () => {
  const F = require('../mcp-ecosystem-intelligence/scripts/lib/finding.cjs');
  const PR = require('../mcp-ecosystem-intelligence/scripts/lib/policy_rules.cjs');
  const scan = { files: [{ host: 'cursor', scope: 'project', path: '/p/.cursor/mcp.json' }, { host: 'vscode', scope: 'project', path: '/p/.vscode/mcp.json' }],
    unreadable: [], findings: S.scanDocument({ mcpServers: { a: { env: { GITHUB_TOKEN: T.github } } } }, { host: 'cursor', scope: 'project', path: '/p/.cursor/mcp.json' })
      .map((f) => ({ ...f, line: 3, tracked: false, severity: 'medium', recommendation: 'x' })) };
  const { findings, subjects } = S.toFindings(scan, { cwd: '/p' });
  assert.equal(findings[0].subject.id, '.cursor/mcp.json:3');
  assert.deepEqual(subjects.map((x) => x.id), ['.vscode/mcp.json'], 'a clean config is a subject, not an absence');
  const policy = PR.effectivePolicy(null, {}, { policyRules: false });
  const ds = F.decide(findings, policy, Date.parse('2026-09-30T00:00:00Z'), { subjects });
  const by = Object.fromEntries(ds.map((d) => [d.subject.id, d]));
  assert.equal(by['.cursor/mcp.json:3'].effect, 'deny');
  assert.equal(by['.cursor/mcp.json:3'].decided_by, 'secrets/github-token');
  assert.equal(by['.vscode/mcp.json'].effect, 'allow');
  const doc = F.toJson(F.findingsDocument({ asOf: Date.parse('2026-09-30T00:00:00Z'), findings, decisions: ds, policy }));
  assertNoLeak(JSON.stringify(doc) + F.renderTrace(F.explainTrace(doc)).join('\n') + JSON.stringify(F.toSarif(doc.findings)), 'findings@1 / trace / SARIF');
});

test('secrets --fix-suggest uses each host’s documented syntax', () => {
  const fx = fixture();
  const doc = JSON.parse(run('check_secrets.cjs', ['--json', '--fix-suggest', '--no-git'], fx).stdout);
  const by = (p) => doc.secrets.find((d) => d.path === p).fix_suggestion;
  assert.match(by('mcpServers.github.env.GITHUB_TOKEN').lines.join('\n'), /"\$\{GITHUB_TOKEN\}"/);
  assert.match(by('mcpServers.s.headers.X-Api-Key').lines.join('\n'), /\$\{env:X_API_KEY\}/);
  assert.match(by('servers.v.args[2]').lines.join('\n'), /\$\{input:aws-secret-access-key\}[\s\S]*"password":true/);
  assert.match(by('mcp_servers.gl.env.GITLAB_TOKEN').lines.join('\n'), /env_vars = \["GITLAB_TOKEN"\]/);
  assert.match(by('mcp_servers.gl.http_headers.X-Token').lines.join('\n'), /env_http_headers/);
  // ~/.claude.json: Claude Code documents expansion for .mcp.json only, so no
  // edit is invented for it.
  const localId = doc.findings.findings.find((f) => f.subject.scope === 'local').id;
  const local = doc.secrets.find((d) => d.finding === localId);
  assert.ok(local.fix_suggestion.manual && !local.fix_suggestion.lines);
});

test('audit --json and status --json carry the findings and never the values', () => {
  const fx = fixture();
  const audit = run('audit_setup.cjs', ['--json', '--global-config', path.join(fx.home, '.claude.json')], fx);
  assertNoLeak(audit.stdout + audit.stderr, 'audit --json');
  const out = JSON.parse(audit.stdout);
  const secrets = out.findings.findings.filter((f) => f.rule.startsWith('secrets/')).map((f) => out.details[f.id]);
  assert.ok(secrets.length >= 15, `audit reported ${secrets.length} secret findings`);
  assert.ok(secrets.every((d) => d && d.category === 'secret'));
  assert.ok(secrets.some((f) => f.path.startsWith('projects[')), 'local-scope servers in ~/.claude.json are scanned');

  const text = run('audit_setup.cjs', ['--global-config', path.join(fx.home, '.claude.json')], fx);
  assertNoLeak(text.stdout, 'audit (text)');

  const status = run('status.cjs', ['--json'], fx);
  assertNoLeak(status.stdout + status.stderr, 'status --json');
  const s = JSON.parse(status.stdout);
  assert.ok(s.secrets.count >= 15);
  assert.ok(s.findings.findings.filter((f) => f.rule.startsWith('secrets/')).length >= 15);
  assert.match(s.verdict.blocking[0], /secrets? in plain text in host configs/);
  assertNoLeak(run('status.cjs', [], fx).stdout, 'status (text)');
});

test('redact: a value passed as the argument after a credential-named flag is masked (status `launches`)', () => {
  const cmd = `npx -y some-mcp --api-key ${T.heuristic} --verbose`;
  const out = S.redact(cmd);
  assert.ok(!out.includes(T.heuristic.slice(0, 8)), out);
  assert.match(out, /--api-key … --verbose$/);
  assert.equal(S.redact('npx -y some-mcp --port 8080'), 'npx -y some-mcp --port 8080');
});

test('Codex TOML: root-level dotted `mcp_servers.…` keys and a bare [mcp_servers] table are read', () => {
  const doc = S.parseCodexTomlServers([
    'model = "o4"',
    `mcp_servers.gh.env.GITHUB_TOKEN = "${T.github}"`,
    `mcp_servers.gl = { command = "npx", env = { GITLAB_TOKEN = "${T.gitlab}" } }`,
    'other.api_key = "x"',
    '[mcp_servers]',
    `aws.env.AWS_ACCESS_KEY_ID = "${T.aws}"`,
  ].join('\n'));
  const paths = S.scanDocument(doc, { host: 'codex', scope: 'user', path: 'config.toml' }).map((f) => f.path).sort();
  assert.deepEqual(paths, ['mcp_servers.aws.env.AWS_ACCESS_KEY_ID', 'mcp_servers.gh.env.GITHUB_TOKEN', 'mcp_servers.gl.env.GITLAB_TOKEN']);
});

test('a config that does not parse is unreadable (exit 2) — and the parse error never quotes the file', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-secrets-home-'));
  fs.mkdirSync(path.join(home, '.codex'));
  fs.writeFileSync(path.join(home, '.codex', 'config.toml'), `[mcp_servers.gl]\nenv = { GITLAB_TOKEN = "${T.codex}"\n`);
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-secrets-'));
  // Broken JSON with a token right at the fault: V8 would quote it.
  fs.writeFileSync(path.join(cwd, '.mcp.json'), `{ "mcpServers": { "a": { "env": { "GITHUB_TOKEN": "${T.github}" oops`);
  for (const args of [['--no-git'], ['--no-git', '--json'], ['--no-git', '--sarif'], ['--no-git', '--explain']]) {
    const r = run('check_secrets.cjs', args, { cwd, home });
    assert.equal(r.status, 2, `${args.join(' ')}: ${r.stdout}${r.stderr}`);
    assertNoLeak(r.stdout + r.stderr, `unreadable ${args.join(' ')}`);
  }
  const doc = JSON.parse(run('check_secrets.cjs', ['--no-git', '--json'], { cwd, home }).stdout).findings;
  const unreadable = doc.findings.filter((f) => f.rule === 'scope/unreadable');
  assert.equal(unreadable.length, 2);
  assert.ok(unreadable.every((f) => f.state === 'no-data'));
  assert.ok(doc.decisions.every((d) => d.effect === 'unknown' && d.unanswered && !d.fails), 'no data is unknown, never allow');
});

// ── exit codes ─────────────────────────────────────────────────────────────

test('exit codes: 0 clean, 1 found, 2 unreadable, and a finding outranks an unreadable config', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-secrets-home-'));
  const clean = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-secrets-'));
  fs.writeFileSync(path.join(clean, '.mcp.json'), JSON.stringify({ mcpServers: { a: { command: 'npx', env: { GITHUB_TOKEN: '${GITHUB_TOKEN}' } } } }));
  assert.equal(run('check_secrets.cjs', ['--no-git'], { cwd: clean, home }).status, 0);

  const broken = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-secrets-'));
  fs.writeFileSync(path.join(broken, '.mcp.json'), '{ "mcpServers": { oops');
  assert.equal(run('check_secrets.cjs', ['--no-git'], { cwd: broken, home }).status, 2);

  fs.mkdirSync(path.join(broken, '.cursor'));
  fs.writeFileSync(path.join(broken, '.cursor', 'mcp.json'), JSON.stringify({ mcpServers: { a: { env: { GITHUB_TOKEN: T.github } } } }));
  assert.equal(run('check_secrets.cjs', ['--no-git'], { cwd: broken, home }).status, 1);
});

test('audit and status decide a plain-text secret as `secrets` does: it refuses, by default', () => {
  // One subject, one answer (docs/adr/0001): the host-config line holding the
  // credential is denied by the secrets/* row in every command that reads it.
  // Pre-1.0 change: audit and status used to fail on it only under --strict.
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-secrets-home-'));
  const cwd  = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-secrets-'));
  fs.writeFileSync(path.join(cwd, '.mcp.json'), JSON.stringify({ mcpServers: {
    'mcp-server-fetch': { command: 'uvx', args: ['mcp-server-fetch'], env: { MY_API_KEY: T.heuristic } },
  } }));
  const g = ['--global-config', path.join(home, '.claude.json')];
  const secretDecision = (doc) => doc.decisions.find((d) => d.rules.some((o) => o.rule.startsWith('secrets/')));
  const au = run('audit_setup.cjs', [...g, '--json'], { cwd, home });
  assert.equal(au.status, 1);
  const sc = run('check_secrets.cjs', ['--json'], { cwd, home });
  assert.equal(sc.status, 1);
  const st = run('status.cjs', ['--json'], { cwd, home });
  assert.equal(st.status, 1);
  const [a, x, t] = [JSON.parse(au.stdout).findings, JSON.parse(sc.stdout).findings, JSON.parse(st.stdout).findings].map(secretDecision);
  for (const d of [a, t]) {
    assert.deepEqual([d.subject.id, d.effect, d.decided_by, d.fails], [x.subject.id, x.effect, x.decided_by, x.fails]);
  }
  assert.match(JSON.parse(st.stdout).verdict.blocking[0], /1 secret in plain text/);
});

// ── git ────────────────────────────────────────────────────────────────────

const HAS_GIT = spawnSync('git', ['--version']).status === 0;

test('a secret in a git-tracked .mcp.json is severity high; untracked is medium', { skip: !HAS_GIT && 'git not installed' }, () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-secrets-home-'));
  const cwd  = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-secrets-repo-'));
  const git = (...a) => spawnSync('git', a, { cwd, encoding: 'utf8' });
  assert.equal(git('init', '-q').status, 0);
  fs.writeFileSync(path.join(cwd, '.mcp.json'), JSON.stringify({ mcpServers: { a: { env: { GITHUB_TOKEN: T.github } } } }));

  let doc = JSON.parse(run('check_secrets.cjs', ['--json'], { cwd, home }).stdout);
  assert.equal(doc.secrets[0].tracked, false);
  assert.equal(doc.findings.findings[0].severity, 'medium');

  assert.equal(git('add', '.mcp.json').status, 0);
  doc = JSON.parse(run('check_secrets.cjs', ['--json'], { cwd, home }).stdout);
  assert.equal(doc.secrets[0].tracked, true);
  assert.equal(doc.findings.findings[0].severity, 'high');
  assert.match(doc.secrets[0].recommendation, /rotate/);

  const sarif = JSON.parse(run('check_secrets.cjs', ['--sarif'], { cwd, home }).stdout);
  assert.equal(sarif.runs[0].results[0].level, 'error');
  assert.equal(sarif.runs[0].results[0].ruleId, 'secrets/github-token');
  assert.equal(sarif.runs[0].results[0].partialFingerprints.findingId, doc.findings.findings[0].id);
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, '.mcp.json');
  assertNoLeak(JSON.stringify(sarif), 'sarif (tracked)');
});
