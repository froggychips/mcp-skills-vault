'use strict';
const { test } = require('node:test');
const assert   = require('node:assert/strict');
const m = require('../mcp-ecosystem-intelligence/scripts/lib/entry_model.cjs');

test('toTypedEntry: npm entry splits into artifact and launch', () => {
  const typed = m.toTypedEntry({
    name: '@scope/pkg', install_cmd: 'npx -y @scope/pkg@1.2.3 --flag',
    version: '1.2.3', pkg_integrity: 'sha512-abc',
  });
  assert.deepEqual(typed.artifact, {
    ecosystem: 'npm', package: '@scope/pkg', version: '1.2.3', integrity: 'sha512-abc',
  });
  assert.deepEqual(typed.launch, { command: 'npx', args: ['-y', '@scope/pkg@1.2.3', '--flag'] });
  assert.deepEqual(typed.warnings, []);
});

test('toTypedEntry: PyPI entry', () => {
  const typed = m.toTypedEntry({ install_cmd: 'uvx mcp-server-git==2026.1.14', version: '2026.1.14', pkg_integrity: 'sha256-def' });
  assert.equal(typed.artifact.ecosystem, 'pypi');
  assert.equal(typed.artifact.package, 'mcp-server-git');
  assert.equal(typed.artifact.version, '2026.1.14');
});

test('toTypedEntry: OCI entry keeps image and digest apart', () => {
  const digest = 'a'.repeat(64);
  const typed = m.toTypedEntry({
    install_cmd: `docker run -i --rm ghcr.io/o/r@sha256:${digest}`,
    pkg_integrity: `sha256-${digest}`,
  });
  assert.equal(typed.artifact.ecosystem, 'oci');
  assert.equal(typed.artifact.image, 'ghcr.io/o/r');
  assert.equal(typed.artifact.digest, `sha256:${digest}`);
  assert.equal(typed.artifact.tag, null);
  assert.deepEqual(typed.warnings, []);
});

test('toTypedEntry: a tag-only image is recorded as such, with a warning', () => {
  const typed = m.toTypedEntry({ install_cmd: 'docker run -i ghcr.io/o/r:latest' });
  assert.equal(typed.artifact.digest, null);
  assert.equal(typed.artifact.tag, 'latest');
  assert.match(typed.warnings.join(' '), /referenced by tag/);
});

test('toTypedEntry: a git source install has no verifiable artifact', () => {
  const typed = m.toTypedEntry({ install_cmd: 'uvx --from git+https://github.com/o/r mcp-redis' });
  assert.equal(typed.artifact.ecosystem, 'git');
  assert.equal(typed.artifact.source, 'git+https://github.com/o/r');
  assert.match(typed.warnings.join(' '), /no released artifact/);
});

test('toTypedEntry: a command version disagreeing with the verified one is a warning', () => {
  const typed = m.toTypedEntry({ install_cmd: 'npx -y pkg@1.0.0', version: '2.0.0' });
  assert.match(typed.warnings.join(' '), /asks for 1\.0\.0 but the verified version is 2\.0\.0/);
});

test('toTypedEntry: no version anywhere is called out', () => {
  const typed = m.toTypedEntry({ install_cmd: 'npx -y pkg' });
  assert.equal(typed.artifact.version, null);
  assert.match(typed.warnings.join(' '), /no version anywhere/);
});

test('renderInstallCommand: round-trips the launch spec', () => {
  const typed = m.toTypedEntry({ install_cmd: 'npx -y pkg@1.2.3 --toolsets repos', version: '1.2.3' });
  assert.equal(m.renderInstallCommand(typed), 'npx -y pkg@1.2.3 --toolsets repos');
  assert.equal(m.renderInstallCommand(null), null);
  assert.equal(m.renderInstallCommand({}), null);
});

test('artifactId: identity includes the version, because evidence does not transfer', () => {
  assert.equal(m.artifactId({ ecosystem: 'npm', package: '@s/p', version: '1.2.3' }), 'npm:@s/p@1.2.3');
  assert.equal(m.artifactId({ ecosystem: 'pypi', package: 'p', version: '1.0' }), 'pypi:p@1.0');
  assert.equal(m.artifactId({ ecosystem: 'oci', image: 'ghcr.io/o/r', digest: 'sha256:abc' }), 'oci:ghcr.io/o/r@sha256:abc');
  assert.equal(m.artifactId({ ecosystem: 'oci', image: 'ghcr.io/o/r', tag: 'latest' }), 'oci:ghcr.io/o/r:latest');
  assert.equal(m.artifactId({ ecosystem: 'git', source: 'git+https://x/y' }), 'git:git+https://x/y');
  assert.equal(m.artifactId({ ecosystem: 'npm' }), null);
  assert.equal(m.artifactId(null), null);
});

test('validateEntry: catches a typed form that does not reproduce the command', () => {
  const ok = m.validateEntry({ install_cmd: 'npx -y pkg@1.2.3', version: '1.2.3', pkg_integrity: 'sha512-x' });
  assert.equal(ok.ok, true, ok.errors.join('; '));

  const badIntegrity = m.validateEntry({ install_cmd: 'npx -y pkg@1.2.3', version: '1.2.3', pkg_integrity: 'abc' });
  assert.equal(badIntegrity.ok, false);
  assert.match(badIntegrity.errors.join(' '), /no recognised algorithm prefix/);

  assert.equal(m.validateEntry({}).ok, false);
});

test('every shipped DB entry satisfies the render invariant', () => {
  // This is what makes moving to the typed form a migration rather than a
  // rewrite: the typed record must reproduce the string the DB ships today,
  // for all 114 entries, before anything starts reading the typed form.
  const db = require('../mcp-ecosystem-intelligence/assets/tools_database.json');
  const failures = [];
  for (const tool of db.tools) {
    const r = m.validateEntry(tool);
    if (!r.ok) failures.push(`${tool.name}: ${r.errors.join('; ')}`);
  }
  assert.deepEqual(failures, [], failures.join('\n'));
});

test('the DB derives exactly the ecosystems the tooling knows how to check', () => {
  const db = require('../mcp-ecosystem-intelligence/assets/tools_database.json');
  const counts = {};
  for (const tool of db.tools) {
    const eco = m.toTypedEntry(tool).artifact.ecosystem;
    counts[eco] = (counts[eco] || 0) + 1;
  }
  // 'unknown' would mean an entry nothing can verify and nothing flags.
  assert.equal(counts.unknown, undefined, `unknown-ecosystem entries: ${counts.unknown}`);
  assert.ok(counts.npm > 0 && counts.oci > 0);
});
