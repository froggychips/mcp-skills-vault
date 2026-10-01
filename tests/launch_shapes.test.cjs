'use strict';
// The gate over the launch shapes found in host configs in the wild
// (tests/fixtures/launch-shapes). The fixtures are synthetic: server keys,
// paths, URLs and values are made up; only the shape of each launch command
// and the public package names it runs are kept. Every assertion here was
// wrong before: `npx --yes` was "unknown install method", `npx -y -p pkg bin`
// "cannot parse npm pkg name", `pnpx` a local command, Microsoft's
// `playwright` an impersonation of `@playwright/mcp`, and an unpinned launch
// read as a gap in the vault's DB.
const { test }      = require('node:test');
const assert        = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs            = require('node:fs');
const os            = require('node:os');
const path          = require('node:path');

const REPO = path.resolve(__dirname, '..');
const FIX  = path.join(__dirname, 'fixtures', 'launch-shapes');
const AS_OF = '2026-10-01T00:00:00Z';

function verify(name, ...flags) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shapes-'));
  const file = path.join(dir, '.mcp.json');
  fs.copyFileSync(path.join(FIX, name), file);
  const r = spawnSync(process.execPath, [path.join(REPO, 'mcp-ecosystem-intelligence/scripts/verify_integrity.cjs'),
    '--installed', '--offline', '--json', '--no-policy', '--config', file, '--as-of', AS_OF, ...flags], {
    cwd: dir, encoding: 'utf8', env: { ...process.env, HOME: dir, APPDATA: dir },
  });
  fs.rmSync(dir, { recursive: true, force: true });
  assert.doesNotMatch(r.stderr, /internal:/, `${name}: the decision and the gate's counters disagree`);
  return { status: r.status, doc: JSON.parse(r.stdout) };
}

const text = (e) => [e.message || '', ...(e.findings || []).map((f) => `${f.tag} ${f.message}`)].join('\n');
const FILES = fs.readdirSync(FIX).filter((f) => f.endsWith('.json')).sort();

test('every shape: no "unknown install method", no unparsable npm name, no lookalike', () => {
  assert.ok(FILES.length >= 15, `${FILES.length} fixtures`);
  let servers = 0, unpinned = 0;
  for (const f of FILES) {
    const { doc } = verify(f);
    for (const e of doc.entries) {
      servers++;
      assert.doesNotMatch(text(e), /unknown install method|cannot parse npm pkg name/, `${f} ${e.name}`);
      assert.ok(!e.findings.some((x) => x.tag === 'LOOKALIKE'), `${f} ${e.name}: ${text(e)}`);
      if (e.findings.some((x) => x.tag === 'UNPINNED')) unpinned++;
    }
  }
  assert.ok(servers >= 45 && unpinned >= 35, `${unpinned}/${servers} unpinned`);
});

test('`npx --yes <pkg>` is read and checked', () => {
  const { doc } = verify('npx-yes-flags.json');
  for (const name of ['db', 'gh', 'fs', 'browser']) {
    const e = doc.entries.find((x) => x.name === name);
    assert.ok(e.findings.some((x) => x.tag === 'UNPINNED'), `${name}: ${text(e)}`);
  }
  assert.match(text(doc.entries.find((x) => x.name === 'gh')), /@modelcontextprotocol\/server-github without a version/);
});

test('`npx -y -p pkg@^14 bin` is that package, a range; `yarn node ./x.js` stays local', () => {
  const { doc } = verify('ranges-and-package-flag.json');
  assert.match(text(doc.entries.find((x) => x.name === 'tool')), /@example\/tool-mcp@\^14\.0\.0, a range rather than a version/);
  assert.match(text(doc.entries.find((x) => x.name === 'nx')), /nx-mcp@~0\.25\.0, a range/);
  assert.match(text(doc.entries.find((x) => x.name === 'tool-local')), /launched from a local command \(yarn\)/);
});

test('`pnpx pkg@latest` is an npm launch, not a local command', () => {
  const { doc } = verify('pnpx-launch.json');
  const e = doc.entries.find((x) => x.name === 'devtools');
  assert.doesNotMatch(text(e), /local command/);
  assert.match(text(e), /chrome-devtools-mcp@latest, a tag rather than a version/);
});

test('`npx -y playwright run-test-mcp-server` is not an impersonation of @playwright/mcp', () => {
  const { doc } = verify('publisher-unscoped-playwright.json', '--strict');
  const e = doc.entries.find((x) => x.name === 'playwright');
  assert.ok(!e.findings.some((x) => x.tag === 'LOOKALIKE'), text(e));
  assert.ok(!doc.findings.findings.some((x) => x.rule.startsWith('lookalike/')));
  assert.match(text(e), /launches playwright without a version/);
});

test('an unpinned launch the vault knows gets the config\'s own line pinned to the verified version', () => {
  const { doc } = verify('vault-known-latest.json');
  const e = doc.entries.find((x) => x.name === 'browser');
  assert.match(text(e), /Pin it to the version the vault verified \(playwright-mcp\): "args": \[.*"@playwright\/mcp@\d+\.\d+\.\d+"\]/);
  assert.ok(!/no pinned version in DB/.test(text(e)), 'the config\'s gap is not phrased as the DB\'s');
});

test('a git source is a source install, not a parse failure', () => {
  const { doc } = verify('git-source-and-remote.json');
  assert.match(text(doc.entries.find((x) => x.name === 'source')), /is a source install/);
});

test('under --strict the exit code is the decisions\'', () => {
  for (const f of ['two-latest.json', 'no-version-three.json']) {
    const { status, doc } = verify(f, '--strict');
    assert.equal(status, 1, f);
    assert.ok(doc.findings.decisions.some((d) => d.fails && d.rules.some((o) => o.rule === 'config/unpinned-launch')), f);
  }
});
