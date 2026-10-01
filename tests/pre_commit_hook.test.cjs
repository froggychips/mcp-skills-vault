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

function tryRepo(servers) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-vault-pre-commit-'));
  try {
    const git = (...a) => spawnSync('git', a, { cwd: dir, encoding: 'utf8', env: ENV });
    assert.equal(git('init', '-q').status, 0);
    fs.writeFileSync(path.join(dir, '.mcp.json'), JSON.stringify({ mcpServers: servers }, null, 2));
    assert.equal(git('add', '.mcp.json').status, 0);
    const r = spawnSync('pre-commit', ['try-repo', REPO, 'mcp-vault', '--files', '.mcp.json', '--verbose'], {
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
