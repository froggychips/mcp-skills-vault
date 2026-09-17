'use strict';
/**
 * Capability detection, and the asymmetry that makes it honest.
 *
 * The rule under test, stated in lib/capabilities.cjs and enforced here:
 * **`found` is a fact, `absent` is never recorded.** A pattern scan over a
 * minified bundle can show presence and cannot show absence, so the output
 * carries evidence for what it found and a coverage block describing what it
 * read — and never a claim that a package *cannot* do something.
 *
 * The delta follows from that: additions are findings (a pattern fired on real
 * text), and a capability that stopped matching is not reported as an
 * improvement, because a new bundler produces the same observation.
 */

const test   = require('node:test');
const assert = require('node:assert/strict');

const c = require('../mcp-ecosystem-intelligence/scripts/lib/capabilities.cjs');

const file = (path, text) => ({ path, text });

test('each capability is found with a file and a line to go and look at', () => {
  const found = c.detect([
    file('package/index.js', [
      "const { exec } = require('child_process');",
      "const https = require('https');",
      'const token = process.env.API_KEY;',
      "fs.writeFileSync('/tmp/x', token);",
      "fs.readFileSync('/etc/hosts');",
      'eval(userInput);',
    ].join('\n')),
  ]).found;

  for (const cap of ['shell', 'network', 'env_access', 'fs_write', 'fs_read', 'dynamic_code']) {
    assert.ok(found[cap], `${cap} not detected`);
    assert.equal(found[cap][0].file, 'package/index.js');
    assert.ok(found[cap][0].line >= 1, 'evidence carries a line number');
    assert.ok(found[cap][0].match.length > 0);
  }
});

test('nothing is ever recorded as absent', () => {
  const result = c.detect([file('package/index.js', 'export const x = 1;\n')]);
  // An empty `found` is the absence of evidence, and the shape says so: there
  // is no `absent` list to mistake for a finding.
  assert.deepEqual(Object.keys(result.found), []);
  assert.equal(result.absent, undefined);
  assert.match(result.coverage.caveat, /presence, never absence/);
});

test('coverage describes what was read, and flags a bundle', () => {
  const readable = c.detect([file('package/index.js', 'const a = 1;\nconst b = 2;\n')]);
  assert.equal(readable.coverage.minified, false);

  const bundle = c.detect([file('package/dist/bundle.js', `const x=1;${'a'.repeat(9000)}`)]);
  assert.equal(bundle.coverage.minified, true);
  assert.match(bundle.coverage.caveat, /written for a machine/);
  assert.ok(bundle.coverage.longest_line > 5000);
});

test('a base64 payload is counted, because it is why a scan can see nothing', () => {
  const result = c.detect([file('package/index.js', `const blob = "${'QUJD'.repeat(200)}";\n`)]);
  assert.ok(result.coverage.base64_bytes > 512);
});

test('install scripts come from the manifest, so that one is not a guess', () => {
  const withHook = c.detect([file('package/index.js', 'x')], { scripts: { postinstall: 'node scripts/build.js' } });
  assert.ok(withHook.found.install_script);
  assert.match(withHook.found.install_script[0].match, /postinstall/);
  assert.equal(withHook.found.install_script[0].file, 'package.json');

  const without = c.detect([file('package/index.js', 'x')], { scripts: { test: 'node --test' } });
  assert.equal(without.found.install_script, undefined, 'a test script is not an install hook');
});

test('non-code files are not scanned but are counted', () => {
  const result = c.detect([
    file('package/README.md', 'Run `exec()` to do the thing, and set process.env.KEY'),
    file('package/index.js', 'const x = 1;'),
  ]);
  assert.deepEqual(Object.keys(result.found), [], 'documentation is not behaviour');
  assert.equal(result.coverage.code_files, 1);
  assert.equal(result.coverage.other_files, 1);
});

test('credential paths are their own capability, because they are rarely legitimate', () => {
  const found = c.detect([file('package/auth.js', "const p = home + '/.aws/credentials';")]).found;
  assert.ok(found.credential_paths);
  assert.ok(c.HIGH_RISK.has('credential_paths'));
});

test('a require of a literal is not a dynamic require', () => {
  const literal = c.detect([file('package/a.js', "require('fs'); require(\"path\");")]).found;
  assert.equal(literal.dynamic_require, undefined);

  const dynamic = c.detect([file('package/b.js', 'require(moduleName);')]).found;
  assert.ok(dynamic.dynamic_require);
});

test('the delta reports additions with evidence and marks the risky ones', () => {
  const before = c.detect([file('package/index.js', "const https = require('https');")]);
  const after  = c.detect([file('package/index.js', "const https = require('https');\nconst { exec } = require('child_process');")]);

  const diff = c.diffCapabilities(before, after);
  assert.deepEqual(diff.added.map((a) => a.capability), ['shell']);
  assert.equal(diff.added[0].high_risk, true);
  assert.ok(diff.added[0].why, 'a finding says why it matters');
  assert.equal(diff.added[0].evidence.length, 1);
  assert.deepEqual(diff.removed, []);
});

test('a capability that stopped matching is not reported as an improvement', () => {
  const before = c.detect([file('package/index.js', "const { exec } = require('child_process');")]);
  const after  = c.detect([file('package/index.js', 'const x = 1;')]);
  const diff = c.diffCapabilities(before, after);
  assert.deepEqual(diff.added, []);
  assert.equal(diff.removed.length, 1);
  assert.equal(diff.removed[0].capability, 'shell');
  // The wording is the point: a new bundler produces exactly this observation.
  assert.match(diff.removed[0].note, /harder to read/);
});

test('a change in what could be read weakens the comparison, and says so', () => {
  const readable = c.detect([file('package/index.js', 'const a = 1;\n')]);
  const bundled  = c.detect([file('package/dist/bundle.js', `const a=1;${'x'.repeat(9000)}`)]);
  const diff = c.diffCapabilities(readable, bundled);
  assert.equal(diff.coverage_changed, true);
  assert.match(diff.coverage_note, /readable → minified/);
});

test('HIGH_RISK is the set whose appearance is worth stopping a build', () => {
  // Network and file access are what MCP servers are *for*; these are not.
  assert.deepEqual([...c.HIGH_RISK].sort(), ['credential_paths', 'dynamic_code', 'install_script', 'shell']);
  assert.ok(!c.HIGH_RISK.has('network'));
  assert.ok(!c.HIGH_RISK.has('fs_read'));
});

test('every detector explains why it matters', () => {
  for (const [name, spec] of Object.entries(c.CAPABILITIES)) {
    assert.ok(spec.why && spec.why.length > 20, `${name} has no explanation`);
    assert.ok(Array.isArray(spec.patterns), `${name} has no pattern list`);
  }
});
