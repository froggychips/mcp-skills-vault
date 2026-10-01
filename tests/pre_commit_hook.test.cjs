'use strict';
/**
 * The pre-commit hook, run the way pre-commit runs it: `pre-commit try-repo`
 * clones this repository at a commit, `npm pack`s it and installs it into its
 * own node_env — no .git and no DB signature — and runs the hook's entry on a
 * staged config. Before bin/mcp-vault-pre-commit.cjs the CLI took that install
 * for an unsigned npm package and refused: "refusing to use the DB — no
 * signature file", on every config.
 *
 * Skipped when pre-commit is not installed (it is a Python tool; CI that wants
 * this runs `pip install pre-commit` first).
 */

const { test } = require('node:test');
const assert   = require('node:assert/strict');
const fs       = require('node:fs');
const os       = require('node:os');
const path     = require('node:path');
const { spawnSync } = require('node:child_process');

const REPO = path.resolve(__dirname, '..');
const haveTool = (cmd) => spawnSync(cmd, ['--version'], { encoding: 'utf8' }).status === 0;
const SKIP = !haveTool('pre-commit') ? 'pre-commit is not installed'
  : !haveTool('git') ? 'git is not installed' : false;

// Not the developer's own overrides: the hook has to stand on its own.
const ENV = { ...process.env, MCP_VAULT_ALLOW_UNSIGNED_DB: '', MCP_VAULT_REQUIRE_SIGNED_DB: '', MCP_VAULT_PRE_COMMIT_HOOK: '', NO_COLOR: '1' };
// Built at runtime so no credential-shaped string is committed to the repo.
const TOKEN = ['ghp', 'Zq7Xw2Lp9Rt4Vb8Nc3Md6Fk1Hs5Jy0Ug7Ae2Qx'].join('_');

/**
 * The hook repository pre-commit clones: this package's files, committed, with
 * a staged DB (tests/lib/fixture_skill.cjs) — so the answer does not depend on
 * what the shipped DB says today. The hook cannot take --as-of; the staged
 * record holds no found problem for the server below, and its age is context
 * only, so the outcome is the same on any day.
 */
let hookRepo = null;
function makeHookRepo() {
  if (hookRepo) return hookRepo;
  const { fixtureSkill } = require('./lib/fixture_skill.cjs');
  const f = fixtureSkill();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-vault-hook-repo-'));
  for (const p of ['bin', 'package.json', '.pre-commit-hooks.yaml', 'LICENSE', 'README.md']) {
    fs.cpSync(path.join(REPO, p), path.join(dir, p), { recursive: true });
  }
  fs.cpSync(path.join(f.root, 'mcp-ecosystem-intelligence'), path.join(dir, 'mcp-ecosystem-intelligence'), { recursive: true });
  f.cleanup();
  fs.rmSync(path.join(dir, 'mcp-ecosystem-intelligence', 'assets', 'tools_database.json.sig'), { force: true });
  const vcs = (...a) => spawnSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'commit.gpgsign=false', ...a], { cwd: dir, encoding: 'utf8', env: ENV });
  assert.equal(vcs('init', '-q').status, 0);
  assert.equal(vcs('add', '-A').status, 0);
  const c = vcs('commit', '-q', '-m', 'hook repo');
  assert.equal(c.status, 0, c.stderr);
  hookRepo = dir;
  process.on('exit', () => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function tryRepo(servers) {
  const repo = makeHookRepo();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-vault-pre-commit-'));
  try {
    const git = (...a) => spawnSync('git', a, { cwd: dir, encoding: 'utf8', env: ENV });
    assert.equal(git('init', '-q').status, 0);
    fs.writeFileSync(path.join(dir, '.mcp.json'), JSON.stringify({ mcpServers: servers }, null, 2));
    assert.equal(git('add', '.mcp.json').status, 0);
    const r = spawnSync('pre-commit', ['try-repo', repo, 'mcp-vault', '--files', '.mcp.json', '--verbose'], {
      cwd: dir, encoding: 'utf8', env: ENV, timeout: 300000,
    });
    return { status: r.status, out: `${r.stdout}${r.stderr}` };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test('pre-commit try-repo: a clean config passes, on the DB the pinned rev carries', { skip: SKIP, timeout: 600000 }, () => {
  // Keyed "pw", not the vault's name: the hook knows the server by what it launches.
  const r = tryRepo({ pw: { command: 'npx', args: ['-y', '@playwright/mcp@0.0.75'] } });
  assert.doesNotMatch(r.out, /refusing to use the DB/);
  assert.match(r.out, /DB integrity: pinned by pre-commit rev/);
  assert.doesNotMatch(r.out, /not in the vault/);
  assert.equal(r.status, 0, r.out);
});

test('pre-commit try-repo: a plain-text secret fails the commit', { skip: SKIP, timeout: 600000 }, () => {
  const r = tryRepo({ pw: { command: 'npx', args: ['-y', '@playwright/mcp@0.0.75'], env: { GITHUB_TOKEN: TOKEN } } });
  assert.match(r.out, /DB integrity: pinned by pre-commit rev/);
  assert.match(r.out, /secrets\/github-token: deny, fails/);
  assert.doesNotMatch(r.out, new RegExp(TOKEN));
  assert.equal(r.status, 1, r.out);
});
