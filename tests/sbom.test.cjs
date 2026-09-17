'use strict';
/**
 * The SBOM: valid CycloneDX, and honest about what it does not know.
 *
 * The document was validated against the official CycloneDX 1.6 JSON schema
 * while it was being written (ajv, with spdx.schema.json and jsf-0.82 as
 * referenced schemas) — that is not repeated here, because it would mean either
 * a dependency or a network fetch in the test suite. What these tests hold is
 * the part that broke during that validation and the parts a schema cannot
 * check:
 *
 *   - `license.id` must come from the SPDX enum. Emitting `NOASSERTION`, which
 *     this DB contains, made the whole document invalid.
 *   - a hash must decode to the length its algorithm declares, or not be
 *     emitted at all. A truncated hash in an SBOM reads as tampering.
 *   - the serial number must be derived from content, or every export looks
 *     like a change.
 */

const test   = require('node:test');
const assert = require('node:assert/strict');

const s = require('../mcp-ecosystem-intelligence/scripts/sbom.cjs');

test('toHash: base64 and hex both arrive as hex of the right length', () => {
  const sha512 = `sha512-${Buffer.alloc(64, 7).toString('base64')}`;
  const h = s.toHash(sha512);
  assert.equal(h.alg, 'SHA-512');
  assert.equal(h.content.length, 128);

  const hex = 'a'.repeat(64);
  assert.deepEqual(s.toHash(`sha256-${hex}`), { alg: 'SHA-256', content: hex });
});

test('toHash: a value that does not match its declared algorithm is dropped', () => {
  // A hash of the wrong length in an SBOM does not read as "we are unsure", it
  // reads as "these bytes are wrong".
  assert.equal(s.toHash('sha512-tooshort'), null);
  assert.equal(s.toHash(`sha256-${Buffer.alloc(64).toString('base64')}`), null, 'sha512-length body under a sha256 label');
  assert.equal(s.toHash('md5-abc'), null);
  assert.equal(s.toHash(''), null);
  assert.equal(s.toHash(null), null);
});

test('licences: an SPDX id becomes an id, everything else becomes a name', () => {
  assert.deepEqual(s.licencesFor('MIT'), [{ license: { id: 'MIT' } }]);
  assert.deepEqual(s.licencesFor('BUSL-1.1'), [{ license: { id: 'BUSL-1.1' } }]);
  // The two values that made the document fail validation:
  assert.deepEqual(s.licencesFor('NOASSERTION'), [{ license: { name: 'NOASSERTION' } }]);
  assert.deepEqual(s.licencesFor('Unknown'), [{ license: { name: 'Unknown' } }]);
  // An invented id must never be emitted as an id.
  assert.deepEqual(s.licencesFor('Totally-Made-Up-1.0'), [{ license: { name: 'Totally-Made-Up-1.0' } }]);
  assert.deepEqual(s.licencesFor('MIT OR Apache-2.0'), [{ expression: 'MIT OR Apache-2.0' }]);
  assert.equal(s.licencesFor(null), undefined);
});

test('every licence the DB currently holds produces a valid component', () => {
  const db = require('../mcp-ecosystem-intelligence/assets/tools_database.json').tools;
  for (const tool of db) {
    const licences = s.licencesFor(tool.license);
    if (!licences) continue;
    const entry = licences[0];
    if (entry.license && entry.license.id) {
      assert.ok(s.SPDX_IDS.has(entry.license.id),
        `${tool.name}: "${entry.license.id}" is emitted as an SPDX id but is not on the checked list`);
    } else {
      assert.ok(entry.expression || (entry.license && entry.license.name),
        `${tool.name}: licence "${tool.license}" produced neither an id, a name nor an expression`);
    }
  }
});

test('components carry the artifact identity, not just a label', () => {
  const c = s.componentFor({
    name: 'playwright-mcp',
    install_cmd: 'npx -y @playwright/mcp@0.0.75',
    version: '0.0.75',
    pkg_integrity: `sha512-${Buffer.alloc(64, 3).toString('base64')}`,
    license: 'Apache-2.0',
    source_url: 'https://github.com/microsoft/playwright-mcp',
    trust: 'verified',
  }, null);
  assert.equal(c.type, 'application');
  assert.equal(c.name, '@playwright/mcp');
  assert.equal(c.version, '0.0.75');
  assert.equal(c.purl, 'pkg:npm/%40playwright/mcp@0.0.75', 'the scope is percent-encoded, as purl requires');
  assert.equal(c['bom-ref'], 'server:npm:@playwright/mcp@0.0.75');
  assert.deepEqual(c.externalReferences, [{ type: 'vcs', url: 'https://github.com/microsoft/playwright-mcp' }]);
  assert.equal(c.hashes.length, 1);
});

test('behavioural status and evidence dates travel with the component', () => {
  const props = s.propertiesFor(
    {
      name: 'x', install_cmd: 'npx -y pkg@1.0.0', trust: 'verified',
      trust_evidence: { artifact_id: 'npm:pkg@1.0.0', dimensions: {
        artifact:   { status: 'verified', checked_at: '2026-09-17', verified_at: '2026-09-17' },
        advisories: { status: 'clean', checked_at: '2020-01-01', verified_at: '2020-01-01' },
      } },
    },
    { status: 'fail', failure_class: 'NEEDS_ENV', tool_count: null },
  );
  const byName = Object.fromEntries(props.map((p) => [p.name, p.value]));
  assert.equal(byName['mcp-vault:behaviour'], 'needs-credentials');
  assert.match(byName['mcp-vault:evidence.artifact'], /^verified \(2026-09-17\)$/);
  // The date is the point: "clean" from 2020 is not a current claim, and the
  // SBOM says so rather than leaving a reader to assume it is fresh.
  assert.match(byName['mcp-vault:evidence.advisories'], /2020-01-01/);
  assert.match(byName['mcp-vault:evidence.stale'], /advisories/);
});

test('a transitive package that runs install scripts says so', () => {
  const c = s.depComponent({ name: 'esbuild', version: '0.21.0', integrity: `sha512-${Buffer.alloc(64, 1).toString('base64')}`, hasInstallScript: true });
  assert.equal(c.type, 'library');
  assert.deepEqual(c.properties, [{ name: 'mcp-vault:install-script', value: 'true' }]);
  assert.equal(c.purl, 'pkg:npm/esbuild@0.21.0');

  const plain = s.depComponent({ name: 'ms', version: '2.1.3', integrity: null, hasInstallScript: false });
  assert.equal(plain.properties, undefined);
  assert.equal(plain.hashes, undefined, 'no integrity means no hash, not an empty one');
});

test('the serial number is derived from content, so an unchanged export is unchanged', () => {
  const a = s.contentUuid({ x: 1 });
  const b = s.contentUuid({ x: 1 });
  const c = s.contentUuid({ x: 2 });
  assert.equal(a, b, 'a random UUID per run would make every export look like a change');
  assert.notEqual(a, c);
  assert.match(a, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-8[0-9a-f]{3}-[0-9a-f]{12}$/);
});

test('--spec only accepts versions we produce', () => {
  assert.equal(s.parseArgs(['--spec', '1.6']).error, undefined);
  assert.equal(s.parseArgs(['--spec', '1.5']).error, undefined);
  assert.match(s.parseArgs(['--spec', '1.4']).error, /must be one of/);
  assert.match(s.parseArgs(['--nope']).error, /unknown flag/);
});
