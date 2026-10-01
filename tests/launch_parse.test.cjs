'use strict';
// Launch commands as real host configs write them (public .mcp.json /
// .vscode/mcp.json / .cursor/mcp.json files, 2026-10). Each shape here was
// "unknown install method", "cannot parse npm pkg name" or "local command"
// before: the server was configured and nobody checked it.
const { test } = require('node:test');
const assert   = require('node:assert/strict');

const ic   = require('../mcp-ecosystem-intelligence/scripts/lib/install_cmd.cjs');
const inst = require('../mcp-ecosystem-intelligence/scripts/lib/installed.cjs');

const launch = (command, ...args) => ic.parseLaunch({ command, args });
const pick = (l) => l && { ecosystem: l.ecosystem, package: l.package, version: l.version, bin: l.bin, exact: l.exact, error: l.error };

// ── 1. npx options, read as npm reads them ─────────────────────────────────

test('npx: --yes, --yes=true, -y, -q and no flag at all name the same package', () => {
  for (const args of [
    ['--yes', '@modelcontextprotocol/server-github'],
    ['--yes=true', '@modelcontextprotocol/server-github'],
    ['-y', '@modelcontextprotocol/server-github'],
    ['-q', '-y', '@modelcontextprotocol/server-github'],
    ['-y', '--quiet', '@modelcontextprotocol/server-github'],
    ['--prefer-offline', '--yes', '@modelcontextprotocol/server-github'],
    ['@modelcontextprotocol/server-github'],
    ['--yes', '--', '@modelcontextprotocol/server-github'],
  ]) {
    const l = launch('npx', ...args);
    assert.equal(l.package, '@modelcontextprotocol/server-github', args.join(' '));
    assert.equal(l.version, null);
    assert.equal(l.exact, false);
  }
});

test('npx: a value-taking option is skipped with its value, never read as the package', () => {
  assert.equal(launch('npx', '-y', '--cache', '/tmp/x', 'pkg@1.2.3').package, 'pkg');
  assert.equal(launch('npx', '--loglevel', 'silent', '-y', 'pkg@1.2.3').package, 'pkg');
  assert.equal(launch('npx', '--cache=/tmp/x', 'pkg@1.2.3').version, '1.2.3');
});

test('npx: arguments after the package belong to the server, flags included', () => {
  const l = launch('npx', '-y', 'chrome-devtools-mcp@latest', '--no-usage-statistics', '-p', 'x');
  assert.deepEqual(pick(l), { ecosystem: 'npm', package: 'chrome-devtools-mcp', version: 'latest', bin: null, exact: false, error: null });
  assert.deepEqual(l.args, ['--no-usage-statistics', '-p', 'x']);
});

test('npx: an unknown option or a registry override is a reason, not a guess', () => {
  assert.match(launch('npx', '-y', '--frobnicate', 'v', 'pkg').error, /unknown npx option --frobnicate/);
  assert.match(launch('npx', '-y', '--registry=https://evil.example', 'pkg').error, /another registry/);
  assert.match(launch('npx', '-c', 'echo hi').error, /shell string/);
  assert.match(launch('npx', '-y', 'github:o/r').error, /not a registry package/);
  assert.match(launch('npx', '-y', './local-dir').error, /not a registry package/);
});

test('npmPkgName (DB strings): option order no longer matters, a version is still a version', () => {
  assert.equal(ic.npmPkgName('npx --yes pkg@1.0.0'), 'pkg');
  assert.equal(ic.npmPkgName('npx -q -y @scope/pkg@1.0.0 extra'), '@scope/pkg');
  assert.equal(ic.npmPkgName('npx -y --registry=https://evil.example pkg'), null);
  assert.equal(ic.npmPkgName('uvx pkg'), null);
});

// ── 2. -p / --package: the package is the value, the binary is separate ────

test('npx -p pkg bin: package from -p, bin kept apart, version from the -p spec', () => {
  for (const args of [
    ['-y', '-p', '@example/tool-mcp@^14.0.0', 'tool-mcp-start'],
    ['-y', '--package', '@example/tool-mcp@^14.0.0', 'tool-mcp-start'],
    ['--package=@example/tool-mcp@^14.0.0', '-y', 'tool-mcp-start'],
    ['-p', '@example/tool-mcp@^14.0.0', '--yes', 'tool-mcp-start'],
  ]) {
    assert.deepEqual(pick(launch('npx', ...args)),
      { ecosystem: 'npm', package: '@example/tool-mcp', version: '^14.0.0', bin: 'tool-mcp-start', exact: false, error: null }, args.join(' '));
  }
});

test('npx with several -p: the server is the package the binary belongs to; all are listed', () => {
  const l = launch('npx', '-y', '-p', 'typescript@5.6.3', '-p', '@acme/tool-mcp@1.2.3', 'tool-mcp', '--stdio');
  assert.equal(l.package, '@acme/tool-mcp');
  assert.equal(l.version, '1.2.3');
  assert.equal(l.exact, true);
  assert.deepEqual(l.packages.map((p) => p.name), ['typescript', '@acme/tool-mcp']);
  assert.deepEqual(l.args, ['--stdio']);
  // No binary match: the first -p.
  assert.equal(launch('npx', '-p', 'a@1.0.0', '-p', 'b@2.0.0', 'run-it').package, 'a');
});

test('toInstallCmd: -p launches keep -p in the canonical command, and the gate reads it', () => {
  const cmd = inst.toInstallCmd({ command: 'npx', args: ['-y', '-p', '@example/tool-mcp@^14.0.0', 'tool-mcp-start'] });
  assert.equal(cmd, 'npx -y -p @example/tool-mcp@^14.0.0 tool-mcp-start');
  assert.equal(ic.npmPkgName(cmd), '@example/tool-mcp');
});

// ── 3. the other registry runners are registry launches, not local commands ─

test('pnpx / pnpm dlx / bunx / bun x / yarn dlx / npm exec are npm-registry launches', () => {
  for (const [command, args] of [
    ['pnpx', ['chrome-devtools-mcp@latest', '--browserUrl', 'http://127.0.0.1:9222']],
    ['pnpm', ['dlx', 'chrome-devtools-mcp@latest']],
    ['pnpm', ['dlx', '--silent', 'chrome-devtools-mcp@latest']],
    ['bunx', ['chrome-devtools-mcp@latest']],
    ['bunx', ['--bun', 'chrome-devtools-mcp@latest']],
    ['bun', ['x', 'chrome-devtools-mcp@latest']],
    ['yarn', ['dlx', 'chrome-devtools-mcp@latest']],
    ['yarn', ['dlx', '-q', 'chrome-devtools-mcp@latest']],
    ['npm', ['exec', '--yes', '--', 'chrome-devtools-mcp@latest']],
    ['/opt/homebrew/bin/pnpx', ['chrome-devtools-mcp@latest']],
  ]) {
    const l = launch(command, ...args);
    assert.equal(l.ecosystem, 'npm', `${command} ${args.join(' ')}`);
    assert.equal(l.package, 'chrome-devtools-mcp');
    assert.equal(l.version, 'latest');
    assert.match(inst.toInstallCmd({ command, args }), /^npx -y chrome-devtools-mcp@latest/);
  }
  // with their own --package spelling
  assert.equal(launch('pnpm', 'dlx', '--package', '@example/tool-mcp@14.0.0', 'tool-mcp-start').package, '@example/tool-mcp');
  assert.equal(launch('yarn', 'dlx', '-p', '@example/tool-mcp@14.0.0', 'tool-mcp-start').bin, 'tool-mcp-start');
});

test('yarn / pnpm / npm without a dlx-style subcommand stay local commands', () => {
  assert.equal(launch('yarn', 'node', './mcps/server.js'), null);
  assert.equal(launch('pnpm', 'run', 'mcp'), null);
  assert.equal(launch('npm', 'run', 'mcp'), null);
  assert.equal(inst.toInstallCmd({ command: 'yarn', args: ['node', './mcps/server.js'] }), null);
});

test('PyPI: uvx --from, uv tool run, pipx run are PyPI launches; git sources are not', () => {
  assert.deepEqual(pick(launch('uvx', '--from', 'mcp-server-fetch==2025.4.7', 'mcp-server-fetch')),
    { ecosystem: 'pypi', package: 'mcp-server-fetch', version: '2025.4.7', bin: 'mcp-server-fetch', exact: true, error: null });
  assert.deepEqual(pick(launch('uv', 'tool', 'run', 'mcp-server-fetch')),
    { ecosystem: 'pypi', package: 'mcp-server-fetch', version: null, bin: null, exact: false, error: null });
  assert.deepEqual(pick(launch('pipx', 'run', 'mcp-server-fetch==1.0.0')),
    { ecosystem: 'pypi', package: 'mcp-server-fetch', version: '1.0.0', bin: null, exact: true, error: null });
  assert.deepEqual(pick(launch('pipx', 'run', '--spec', 'awslabs.core-mcp-server', 'core-mcp')),
    { ecosystem: 'pypi', package: 'awslabs.core-mcp-server', version: null, bin: 'core-mcp', exact: false, error: null });
  assert.equal(launch('uvx', 'mcp-server-fetch@latest').version, 'latest');
  assert.equal(launch('uvx', '--python', '3.12', 'mcp-server-fetch').package, 'mcp-server-fetch');

  const git = launch('uvx', '--from', 'git+https://git.example.com/acme/example-mcp', 'example-mcp', 'start');
  assert.equal(git.ecosystem, 'git');
  assert.match(git.error, /source install/);
  assert.match(launch('uvx', '--with', 'x', 'pkg').error, /--with/);

  assert.equal(inst.toInstallCmd({ command: 'uvx', args: ['--from', 'mcp-server-fetch==2025.4.7', 'mcp-server-fetch'] }), 'uvx --from mcp-server-fetch==2025.4.7 mcp-server-fetch');
  assert.equal(ic.pypiPkgName('uvx --from mcp-server-fetch==2025.4.7 mcp-server-fetch'), 'mcp-server-fetch');
  assert.equal(inst.toInstallCmd({ command: 'pipx', args: ['run', 'mcp-server-fetch==1.0.0'] }), 'uvx mcp-server-fetch==1.0.0');
  assert.equal(inst.toInstallCmd({ command: 'uv', args: ['tool', 'run', 'mcp-server-fetch'] }), 'uvx mcp-server-fetch');
  // A git source stays a uvx command the gate reports as a source install.
  assert.equal(ic.pypiPkgName(inst.toInstallCmd({ command: 'uvx', args: ['--from', 'git+https://x/y', 'z'] })), null);
});

test('exact means exact: a tag, a range and nothing at all are not pins', () => {
  assert.equal(launch('npx', '-y', 'pkg@1.2.3').exact, true);
  for (const v of ['latest', '^1.2.3', '~0.25.0', '1', '1.x']) assert.equal(launch('npx', '-y', `pkg@${v}`).exact, false, v);
  assert.equal(launch('npx', '-y', 'pkg').exact, false);
  assert.equal(launch('uvx', 'pkg>=1.0').exact, false);
  assert.equal(launch('uvx', 'pkg==1.0').exact, true);
});

test('not a registry launch: docker, node, a binary on PATH', () => {
  assert.equal(launch('docker', 'run', '-i', 'img'), null);
  assert.equal(launch('node', './server.js'), null);
  assert.equal(launch('/opt/bin/my-mcp'), null);
});
