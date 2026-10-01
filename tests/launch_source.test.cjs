'use strict';
// When the parser is not sure what runs, the answer is "unknown, with the
// reason" — never a quiet guess, never a public-registry check standing in for
// another source. Review of #138: source overrides (npm, uv, pipx), every
// `-p` package checked, PyPI ranges kept as ranges.
const { test }      = require('node:test');
const assert        = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs            = require('node:fs');
const os            = require('node:os');
const path          = require('node:path');

const ic   = require('../mcp-ecosystem-intelligence/scripts/lib/install_cmd.cjs');
const inst = require('../mcp-ecosystem-intelligence/scripts/lib/installed.cjs');

const REPO = path.resolve(__dirname, '..');
const AS_OF = '2026-10-01T00:00:00Z';
const launch = (command, ...args) => ic.parseLaunch({ command, args });

// ── 1. npm options that move the source ────────────────────────────────────

test('npm: --registry, --userconfig, --globalconfig, --cache, --prefix, --@scope:registry are source overrides', () => {
  for (const args of [
    ['-y', '--registry', 'https://registry.example', 'pkg@1.0.0'],
    ['-y', '--registry=https://registry.example', 'pkg@1.0.0'],
    ['-y', '--userconfig', '/tmp/x/.npmrc', 'pkg@1.0.0'],
    ['-y', '--globalconfig=/tmp/x/npmrc', 'pkg@1.0.0'],
    ['-y', '--cache', '/tmp/c', 'pkg@1.0.0'],
    ['-y', '--prefix', '/tmp/p', 'pkg@1.0.0'],
    ['-y', '--@acme:registry=https://registry.example', 'pkg@1.0.0'],
  ]) {
    const l = launch('npx', ...args);
    assert.equal(l.package, 'pkg', args.join(' '));      // read…
    assert.ok(l.override, args.join(' '));               // …but marked
    assert.match(l.error, /^launch source overridden: /);
    assert.equal(ic.npmPkgName(['npx', ...args].join(' ')), null, 'never routed as a public-registry package');
    assert.equal(ic.canonicalInstallCmd(l), null);
  }
  assert.ok(launch('pnpm', 'dlx', '--registry', 'https://r.example', 'pkg').override);
  assert.ok(launch('bunx', '--cwd', '/tmp/x', 'pkg').override);
});

test('npm: an environment variable that moves the source is an override too, and install_cmd fails closed', () => {
  const srv = { name: 's', command: 'npx', args: ['-y', 'pkg@1.0.0'], env_keys: ['npm_config_registry'] };
  assert.match(inst.launchSourceOverride(srv), /npm_config_registry/);
  const cmd = inst.toInstallCmd(srv);
  assert.equal(ic.npmPkgName(cmd), null, cmd);
  assert.equal(inst.launchSourceOverride({ ...srv, env_keys: ['API_TOKEN'] }), null);
});

// ── 2. uv options that move the source ─────────────────────────────────────

test('uv: --project, --directory, --config-file, index and find-links options are source overrides', () => {
  for (const args of [
    ['--project', './proj', 'pkg'], ['--directory', './d', 'pkg'], ['--config-file', './uv.toml', 'pkg'],
    ['--index-url', 'https://i.example/simple', 'pkg'], ['--extra-index-url=https://i.example/simple', 'pkg'],
    ['--index', 'https://i.example/simple', 'pkg'], ['--default-index', 'https://i.example', 'pkg'],
    ['--find-links', './wheels', 'pkg'], ['-f', './wheels', 'pkg'],
  ]) {
    const l = launch('uvx', ...args);
    assert.equal(l.package, 'pkg', args.join(' '));
    assert.ok(l.override, args.join(' '));
    assert.equal(ic.pypiPkgName(['uvx', ...args].join(' ')), null);
  }
  const srv = { name: 's', command: 'uvx', args: ['pkg==1.0'], env_keys: ['UV_INDEX_URL'] };
  assert.match(inst.launchSourceOverride(srv), /UV_INDEX_URL/);
  assert.equal(ic.pypiPkgName(inst.toInstallCmd(srv)), null);
});

// ── 3. pipx: a local or non-registry source is not a PyPI package ──────────

test('pipx run --path / --spec <path|URL> are not PyPI packages', () => {
  const p = launch('pipx', 'run', '--path', 'localserver');
  assert.ok(p.override);
  assert.match(p.override, /local path/);
  assert.equal(ic.pypiPkgName(inst.toInstallCmd({ command: 'pipx', args: ['run', '--path', 'localserver'] })), null);
  for (const spec of ['./server', '/abs/server', 'https://example.com/x-1.0-py3-none-any.whl', 'git+https://git.example.com/x']) {
    const l = launch('pipx', 'run', '--spec', spec, 'bin');
    assert.notEqual(l.ecosystem, 'pypi', spec);
    assert.ok(l.error, spec);
  }
  assert.ok(launch('pipx', 'run', '--index-url', 'https://i.example', 'pkg').override);
  assert.ok(launch('pipx', 'run', '--pip-args=--index-url=https://i.example', 'pkg').override);
});

// ── 5. PyPI ranges are ranges ──────────────────────────────────────────────

test('PyPI: ==X and ===X are pins; >=, ~=, <, !=, ==X.* and combinations are ranges, kept as written', () => {
  assert.deepEqual([launch('uvx', 'pkg==1.2').version, launch('uvx', 'pkg==1.2').exact], ['1.2', true]);
  assert.deepEqual([launch('uvx', 'pkg===1.2').version, launch('uvx', 'pkg===1.2').exact], ['1.2', true]);
  for (const [spec, range] of [['pkg>=1.2', '>=1.2'], ['pkg~=1.2', '~=1.2'], ['pkg<2', '<2'], ['pkg!=1.3', '!=1.3'], ['pkg>=1,<2', '>=1,<2'], ['pkg==1.*', '==1.*']]) {
    const l = launch('uvx', spec);
    assert.equal(l.version, range, spec);
    assert.equal(l.exact, false, spec);
    assert.equal(l.range, true, spec);
    // Not dropped from the canonical command (a dropped range reads as "no
    // version" and gets checked as the latest release).
    assert.equal(ic.canonicalInstallCmd(l), `uvx ${spec}`);
  }
  const u = inst.unpinnedLaunch({ name: 's', command: 'uvx', args: ['pkg>=1.2'] });
  assert.match(u.message, /pkg >=1\.2, a range rather than a version/);
});

// ── end to end ─────────────────────────────────────────────────────────────

function verify(servers, ...flags) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'launch-source-'));
  fs.writeFileSync(path.join(dir, '.mcp.json'), JSON.stringify({ mcpServers: servers }, null, 2));
  const r = spawnSync(process.execPath, [path.join(REPO, 'mcp-ecosystem-intelligence/scripts/verify_integrity.cjs'),
    '--installed', '--offline', '--json', '--no-policy', '--cwd', dir, '--as-of', AS_OF, ...flags], {
    cwd: dir, encoding: 'utf8', env: { ...process.env, HOME: dir, APPDATA: dir },
  });
  fs.rmSync(dir, { recursive: true, force: true });
  assert.doesNotMatch(r.stderr, /internal:/);
  return { status: r.status, doc: JSON.parse(r.stdout) };
}
const text = (e) => [e.message || '', ...(e.findings || []).map((f) => `${f.tag} ${f.message}`)].join('\n');
// Every message about one server: its report lines and the gate's own line
// (the findings document keeps the unroutable reason).
const all = (doc, name) => [text(doc.entries.find((x) => x.name === name)),
  ...doc.findings.findings.filter((f) => f.subject.server === name).map((f) => `${f.rule} ${f.message}`)].join('\n');

test('CLI: a source override is a config/launch-source-override finding, unknown, never checked as the registry package', () => {
  const { status, doc } = verify({
    npmrc: { command: 'npx', args: ['-y', '--userconfig', './.npmrc', '@playwright/mcp@0.0.75'] },
    envreg: { command: 'npx', args: ['-y', '@playwright/mcp@0.0.75'], env: { npm_config_registry: 'https://r.example' } },
    uvproj: { command: 'uvx', args: ['--project', './p', 'mcp-server-fetch==2025.4.7'] },
    local: { command: 'pipx', args: ['run', '--path', 'localserver'] },
  });
  assert.equal(status, 0, 'unknown fails only under --fail-unverified / --strict');
  for (const name of ['npmrc', 'envreg', 'uvproj', 'local']) {
    const e = doc.entries.find((x) => x.name === name);
    assert.equal(e.status, 'UNVERIFIED', `${name}: ${text(e)}`);
    assert.match(all(doc, name), /source is overridden/, name);
    assert.ok(e.findings.some((x) => x.tag === 'OVERRIDE'), `${name}: ${text(e)}`);
    // Not checked as if it were the public registry's package.
    assert.doesNotMatch(text(e), /offline pin present|in DB|UNPINNED/, name);
  }
  const fs_ = doc.findings.findings.filter((f) => f.rule === 'config/launch-source-override');
  assert.equal(fs_.length, 4);
  for (const f of fs_) {
    assert.equal(f.subject.type, 'host-config');
    const d = doc.findings.decisions.find((x) => x.subject.id === f.subject.id);
    assert.ok(d.rules.some((o) => o.rule === 'config/launch-source-override' && o.effect === 'unknown'));
  }
  assert.equal(verify({ npmrc: { command: 'npx', args: ['-y', '--registry=https://r.example', 'pkg@1.0.0'] } }, '--fail-unverified').status, 1);
});

test('CLI: every -p package is a subject of its own checks, on the same config line', () => {
  const { doc } = verify({
    multi: { command: 'npx', args: ['-y', '-p', '@playwright/mcp@0.0.75', '-p', 'mcp-server-memmory', 'mcp-server-playwright'] },
  });
  const extra = doc.entries.find((x) => x.name === 'multi (-p mcp-server-memmory)');
  assert.ok(extra, JSON.stringify(doc.entries.map((x) => x.name)));
  // lookalike and unpinned on the extra package, not only on the bin's owner
  assert.ok(extra.findings.some((x) => x.tag === 'LOOKALIKE'), text(extra));
  assert.match(text(extra), /UNPINNED this config launches mcp-server-memmory without a version/);
  const main = doc.entries.find((x) => x.name === 'multi');
  assert.ok(!main.findings.some((x) => x.tag === 'UNPINNED'), text(main));
  // One config line, one subject.
  const subj = new Set(doc.findings.findings.filter((f) => f.subject.type === 'host-config').map((f) => f.subject.id));
  assert.equal(subj.size, 1);
});

test('CLI: a PyPI or npm range is unverified with the range named, and an UNPINNED finding — never "version X"', () => {
  const { doc } = verify({
    py: { command: 'uvx', args: ['mcp-server-fetch>=2025.1'] },
    js: { command: 'npx', args: ['-y', '@playwright/mcp@^0.0.70'] },
  });
  const py = doc.entries.find((x) => x.name === 'py');
  assert.equal(py.status, 'UNVERIFIED');
  assert.match(all(doc, 'py'), /asks for a range \(>=2025\.1\)/);
  assert.equal(py.version, null, 'a range is not reported as a version');
  assert.match(text(py), /mcp-server-fetch >=2025\.1, a range rather than a version/);
  assert.doesNotMatch(text(py), /@2025|==2025\.1\b/);
  const js = doc.entries.find((x) => x.name === 'js');
  assert.match(all(doc, 'js'), /asks for a range \(\^0\.0\.70\)/);
});
