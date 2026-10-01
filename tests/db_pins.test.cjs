'use strict';
/**
 * Every DB entry launches exactly the artifact it vouches for.
 *
 * `version` + `pkg_integrity` are what verify compared; `install_cmd` is what a
 * host config copies and what actually runs. 73 entries carried
 * `npx -y <pkg>` with no version while `version` named the one that was
 * verified — so every start resolved whatever was latest, and the hash the
 * vault checked described some other release. Nothing compared the two.
 *
 * The launch is read with the same parser the gate uses (lib/install_cmd.cjs
 * parseLaunch), so "pinned" here means what it means to `verify` and `check`.
 */

const { test } = require('node:test');
const assert   = require('node:assert/strict');
const fs       = require('node:fs');
const path     = require('node:path');

const { launchPinProblem } = require('../mcp-ecosystem-intelligence/scripts/lib/install_cmd.cjs');
const { applyRefresh } = require('../mcp-ecosystem-intelligence/scripts/verify_integrity.cjs');

const DB = JSON.parse(fs.readFileSync(
  path.join(__dirname, '../mcp-ecosystem-intelligence/assets/tools_database.json'), 'utf8'));

// Entries that cannot be pinned by construction, each with the reason. Empty
// today; an addition needs a reason a reviewer can check, not "later".
const ALLOW_UNPINNED = {
  // 'entry-name': 'why this launch cannot name an exact version',
};

// The rule itself lives with the parser (lib/install_cmd.cjs launchPinProblem).
const pinProblem = launchPinProblem;

test('every registry entry launches the exact version it verified; docker by digest', () => {
  const problems = [];
  for (const tool of DB.tools) {
    if (Object.prototype.hasOwnProperty.call(ALLOW_UNPINNED, tool.name)) continue;
    const why = pinProblem(tool);
    if (why) problems.push(`${tool.name}: ${why} (install_cmd: ${tool.install_cmd})`);
  }
  assert.deepEqual(problems, [], `unpinned DB entries:\n${problems.join('\n')}`);
});

test('the allowlist names real entries that really are unpinned, each with a reason', () => {
  for (const [name, reason] of Object.entries(ALLOW_UNPINNED)) {
    const tool = DB.tools.find((t) => t.name === name);
    assert.ok(tool, `ALLOW_UNPINNED names ${name}, which is not in the DB`);
    assert.ok(typeof reason === 'string' && reason.trim().length > 10, `${name}: give a reason`);
    assert.ok(pinProblem(tool), `${name} is pinned now — drop it from ALLOW_UNPINNED`);
  }
});

test('pinProblem reads launches the way the gate does', () => {
  const t = (install_cmd, version) => pinProblem({ install_cmd, version });
  assert.equal(t('npx -y @scope/pkg@1.2.3', '1.2.3'), null);
  assert.equal(t('npx -y -p @scope/pkg@1.2.3 bin', '1.2.3'), null);
  assert.equal(t('uvx pkg==1.2.3', '1.2.3'), null);
  assert.equal(t('uvx --from pkg==1.2.3 bin', '1.2.3'), null);
  assert.match(t('npx -y @scope/pkg', '1.2.3'), /no version/);
  assert.match(t('npx -y @scope/pkg@latest', '1.2.3'), /tag or range/);
  assert.match(t('npx -y @scope/pkg@^1.2.0', '1.2.3'), /tag or range/);
  assert.match(t('npx -y @scope/pkg@1.2.2', '1.2.3'), /verified version is 1\.2\.3/);
  assert.match(t('uvx pkg', '1.2.3'), /no version/);
  assert.match(t('docker run -i --rm ghcr.io/o/i:latest', null), /digest/);
  assert.equal(t(`docker run -i --rm ghcr.io/o/i@sha256:${'a'.repeat(64)}`, null), null);
  assert.match(t('node server.js', null), /not a registry launch/);
});

test('--update keeps the invariant: a refreshed version is re-pinned in install_cmd (npm @, PyPI ==)', () => {
  const npm = applyRefresh({ install_cmd: 'npx -y @scope/pkg@1.0.0 --flag', version: '1.0.0' }, { version: '1.1.0', integrity: 'sha512-x' });
  assert.equal(npm.install_cmd, 'npx -y @scope/pkg@1.1.0 --flag');
  assert.equal(npm.pkg_integrity, 'sha512-x');
  const bare = applyRefresh({ install_cmd: 'npx -y pkg', version: null }, { version: '2.0.0', integrity: 'sha512-y' });
  assert.equal(bare.install_cmd, 'npx -y pkg@2.0.0');
  const py = applyRefresh({ install_cmd: 'uvx --from pkg==0.1 pkg-bin', version: '0.1' }, { version: '0.2', integrity: 'sha256-z' });
  assert.equal(py.install_cmd, 'uvx --from pkg==0.2 pkg-bin');
  for (const t of [npm, bare, py]) assert.equal(pinProblem(t), null, t.install_cmd);

  // Every registry entry in the DB, refreshed to a new version, still passes.
  const broken = [];
  for (const tool of DB.tools) {
    if (/^docker\s/.test(tool.install_cmd)) continue;
    const copy = applyRefresh({ ...tool }, { version: '99.0.1', integrity: 'x' });
    const why = pinProblem(copy);
    if (why) broken.push(`${tool.name}: ${why}`);
  }
  assert.deepEqual(broken, []);
});
