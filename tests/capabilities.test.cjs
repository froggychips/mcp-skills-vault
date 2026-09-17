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

test('one unreadable file is not made readable by a readable neighbour', () => {
  // A package-wide average meant adding a file with a hundred newlines flipped
  // `minified` to false. No executable code became any more readable, and the
  // caveat printed next to "nothing found" got weaker for no reason.
  const alone = c.detect([file('package/dist/bundle.js', 'x'.repeat(9000))]);
  const beside = c.detect([
    file('package/dist/bundle.js', 'x'.repeat(9000)),
    file('package/readable.js', '\n'.repeat(200)),
  ]);
  assert.equal(alone.coverage.minified, true);
  assert.equal(beside.coverage.minified, true);
  assert.deepEqual(beside.coverage.minified_files, ['package/dist/bundle.js']);
});

test('a method call on a regex or a string is not shell execution', () => {
  // `/re/.exec(s)` produced a high-risk, build-stopping finding on ordinary
  // code. A real child_process call is reached through an import that matches
  // in the same file anyway.
  assert.deepEqual(Object.keys(c.detect([file('a.js', 'if (/foo/.exec(s)) return;')]).found), []);
  assert.deepEqual(Object.keys(c.detect([file('a.js', 'const m = str.match(re).exec(x);')]).found), []);
  assert.ok(c.detect([file('a.js', 'const { exec } = require("child_process"); exec("ls");')]).found.shell);
  assert.ok(c.detect([file('a.js', 'spawn("ls", []);')]).found.shell);
});

test('a literal require stays literal however it is spaced', () => {
  // The lookahead used to sit after `\s*`, which backtracks: for
  // `require( "fs")` the engine matched zero spaces, saw a space instead of
  // the quote, and called a statically known module name dynamic.
  for (const src of ['require("fs")', "require( 'fs')", 'require(\n  "fs")', 'require(  `fs`)']) {
    assert.equal(c.detect([file('a.js', src)]).found.dynamic_require, undefined, src);
  }
  assert.ok(c.detect([file('a.js', 'require(name)')]).found.dynamic_require);
  assert.ok(c.detect([file('a.js', 'require(`${dir}/x`)')]).found.dynamic_require);
});

test('a documentation link is not credential access', () => {
  const comment = c.detect([file('a.js', '// See https://example.org/docs/.aws/credentials for setup')]);
  assert.equal(comment.found.credential_paths, undefined);
  const real = c.detect([file('a.js', 'const p = home + "/.aws/credentials";')]);
  assert.ok(real.found.credential_paths);
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

test('coverage that one side never recorded is not a change, it is unknown', () => {
  // A stored record without `coverage` produced an invented transition —
  // "readable → readable, 0 → 38 bytes" — stated as fact. Same failure as a
  // surface comparison treating a missing identity as a change: a missing
  // input silently became a value.
  const after = c.detect([file('a.js', 'const { exec } = require("child_process");')]);
  const legacy = { found: { network: [{ file: 'a.js', line: 1, match: 'https' }] } };
  const d = c.diffCapabilities(legacy, after);
  assert.equal(d.coverage_changed, null);
  assert.match(d.coverage_note, /cannot be compared/);
  // The capability addition is still reported: that part *is* comparable.
  assert.deepEqual(d.added.map((a) => a.capability), ['shell']);
});

test('coverage comparisons still work when both sides have one', () => {
  const readable = c.detect([file('a.js', 'const x = 1;')]);
  const bundle   = c.detect([file('d.js', 'x'.repeat(9000))]);
  assert.equal(c.diffCapabilities(readable, readable).coverage_changed, false);
  assert.equal(c.diffCapabilities(readable, bundle).coverage_changed, true);
  assert.match(c.diffCapabilities(readable, bundle).coverage_note, /readable → minified/);
});

test('each half of the coverage comparison carries its own unknown', () => {
  // Making the *block* tri-state was not enough: a record with `minified` and
  // no `bytes` answered "coverage unchanged" while the byte comparison had
  // never happened. Same bug, one level down.
  const after = c.detect([file('a.js', 'const y = 2;')]);
  const minifiedOnly = { found: {}, coverage: { minified: false } };
  const d = c.diffCapabilities(minifiedOnly, after);
  assert.equal(d.coverage_changed, null);
  assert.deepEqual(d.coverage_detail, { minified_changed: false, bytes_changed: null });
  assert.match(d.coverage_note, /how much code there is/);

  // Both sides complete: a real answer, per component.
  const before = c.detect([file('a.js', 'const x = 1;')]);
  const full = c.diffCapabilities(before, before);
  assert.equal(full.coverage_changed, false);
  assert.deepEqual(full.coverage_detail, { minified_changed: false, bytes_changed: false });
});
