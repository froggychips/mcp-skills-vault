'use strict';
/**
 * The numbers in the documentation, checked against the data they describe.
 *
 * Every count in the documentation (docs/DATABASE.md, the README, SKILL.md) was written by hand at some point and
 * then left alone while the DB moved underneath it. By the time anyone looked,
 * the tier distribution read "20 Core / 76 Recommended / 18 Experimental" for a
 * database holding 20 / 71 / 23 — three wrong numbers in a document whose whole
 * claim is that this repository counts things carefully.
 *
 * So each documented figure is declared here with the regex that finds it and
 * the expression that computes it. Two ways to fail, both useful:
 *
 *   - the number in the document disagrees with the data → fix the document
 *     (or the data, if the document was right)
 *   - the regex no longer matches → the prose was rewritten, and this table
 *     needs to follow it. Silence would mean the claim stopped being checked
 *     without anyone deciding that.
 *
 * What is deliberately *not* here: figures that are observations rather than
 * properties of the committed data — "100 of the DB's 102 npm entries verify
 * today" depends on what npm serves today, and asserting it in an offline test
 * would make the suite fail on a bad afternoon at npm. Those read as dated
 * observations in the docs. The 102 is checkable, and is checked.
 */

const test   = require('node:test');
const assert = require('node:assert/strict');
const fs     = require('fs');
const path   = require('path');

const ROOT = path.resolve(__dirname, '..');
// The DB's figures live on one page, so the README can stay short and still
// say nothing the data contradicts. The README's own count is checked below.
const DB_DOC = 'docs/DATABASE.md';
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

const db    = JSON.parse(read('mcp-ecosystem-intelligence/assets/tools_database.json')).tools;
const evals = JSON.parse(read('mcp-ecosystem-intelligence/assets/eval_results.json')).results;
const capabilities = JSON.parse(read('mcp-ecosystem-intelligence/assets/capabilities.json'));

/** How many scanned packages have each capability. */
function capabilityCounts() {
  const out = {};
  for (const pkg of Object.values(capabilities.packages || {})) {
    for (const cap of Object.keys(pkg.found || {})) out[cap] = (out[cap] || 0) + 1;
  }
  return out;
}

const count   = (fn) => db.filter(fn).length;
// The tier is derived, not stored — lib/tiers.cjs explains why. Deriving it
// here too keeps the documented distribution honest without the DB carrying a
// copy that goes stale.
const { classifyEntry, evalIndex } = require('../mcp-ecosystem-intelligence/scripts/lib/tiers.cjs');
const evalByName = evalIndex(evals);
// Staleness makes the tier a function of time, so "the distribution" only
// means something with a date on it. Time is an explicit input here: the
// page names the date its figures are as of, and that date has to be the
// date of the newest `checked_at` in the DB — the snapshot the numbers
// describe. Classified against the wall clock instead, this test went red on
// its own a week after every evidence refresh (availability and advisories
// expire in 7 days) with no commit touching anything. Classified against the
// snapshot without the page saying so, it would keep accepting a historical
// distribution presented as current. With the date in the prose, the test is
// deterministic, and refreshing the evidence without refreshing the page
// fails below until someone rewrites the figures for the new date.
const SNAPSHOT_NOW = Math.max(0, ...db.flatMap((t) =>
  Object.values(t.trust_evidence?.dimensions || {})
    .map((d) => Date.parse(d.checked_at))
    .filter(Number.isFinite)));
const SNAPSHOT_DATE = new Date(SNAPSHOT_NOW).toISOString().slice(0, 10);
/** A dated claim's date must be the snapshot's, or its numbers describe other data. */
const dated = (date) => assert.equal(date, SNAPSHOT_DATE,
  `${DB_DOC} dates this figure "as of ${date}", but the newest evidence in the DB is from ${SNAPSHOT_DATE}.\n`
  + `The evidence was refreshed and ${DB_DOC} was not: recompute the figures and update the date.`);
const tierOf  = (t) => classifyEntry(t, evalByName.get(t.name) || null, { now: SNAPSHOT_NOW }).classification;
const tier    = (name) => count((t) => tierOf(t) === name);
const withTools = db.filter((t) => Number.isFinite(t.est_tools_count));
const heaviest  = withTools.reduce((m, t) => (t.est_tools_count > m.est_tools_count ? t : m), withTools[0]);

/**
 * Each claim: where it lives, the pattern that captures the number(s), and what
 * they should be. `expected` is an array so one sentence can carry several.
 */
const CLAIMS = [
  {
    what:  'DB entry count (README)',
    file:  'README.md',
    re:    /curated DB of (\d+) known servers/,
    expected: () => [db.length],
  },
  {
    what:  'DB entry count (scan output example)',
    file:  DB_DOC,
    re:    /^(\d+) entries checked — \d+ failure\(s\)(?:, \d+ unverified)?$/m,
    expected: () => [db.length],
  },
  {
    what:  'DB entry count (Vault DB section)',
    file:  DB_DOC,
    re:    /\*\*(\d+) entries\*\* across ~(\d+) categories/,
    expected: () => [db.length, new Set(db.map((t) => t.category)).size],
  },
  {
    what:  'tier distribution',
    file:  DB_DOC,
    re:    /Distribution as of (\d{4}-\d{2}-\d{2}) \(the date of the newest evidence in the DB\): \*\*(\d+) Core \/ (\d+) Recommended \/ (\d+) Experimental \/ (\d+) Deprecated\*\*/,
    expected: (captured) => (dated(captured[0]),
      [SNAPSHOT_DATE, tier('Core'), tier('Recommended'), tier('Experimental'), tier('Deprecated')]),
  },
  {
    what:  'npm entry count',
    file:  DB_DOC,
    re:    /of the DB's (\d+) npm entries/,
    expected: () => [count((t) => /^npx\s/.test(t.install_cmd || ''))],
  },
  {
    what:  'server count and the tool-surface spread',
    file:  DB_DOC,
    re:    /With (\d+) servers in the DB the spread is wide: `([\w-]+)` = (\d+) tool vs\. `([\w-]+)` = (\d+) tools/,
    // The two named entries are *examples*, and several entries have one tool —
    // so the names are echoed back and checked by `nameCheck` against what they
    // claim to be, rather than compared to one arbitrarily chosen entry. The
    // first version of this test picked its own example and then failed because
    // the docs had named an equally correct one.
    expected: (captured) => [db.length, captured[1], 1, captured[3], heaviest.est_tools_count],
    nameCheck: (captured) => {
      const light = db.find((t) => t.name === captured[1]);
      assert.ok(light, `${DB_DOC} names \`${captured[1]}\` as a one-tool server; there is no such entry`);
      assert.equal(light.est_tools_count, 1, `${captured[1]} no longer has 1 tool`);
      const heavy = db.find((t) => t.name === captured[3]);
      assert.ok(heavy, `${DB_DOC} names \`${captured[3]}\` as the heaviest server; there is no such entry`);
      assert.equal(heavy.est_tools_count, heaviest.est_tools_count,
        `${captured[3]} is no longer the heaviest entry — ${heaviest.name} has ${heaviest.est_tools_count}`);
    },
  },
  {
    what:  'behavioural eval headline',
    file:  DB_DOC,
    re:    /(\d+) of the (\d+) entries with a runnable launch command complete a handshake/,
    expected: () => [evals.filter((r) => r.status === 'pass').length, evals.length],
  },
  {
    what:  'tools observed and their token cost',
    file:  DB_DOC,
    re:    /listing ([\d,]+) tools between them, ≈([\d,]+)k tokens/,
    expected: () => {
      const tools  = evals.reduce((n, r) => n + (r.tool_count || 0), 0);
      const tokens = Math.round(evals.reduce((n, r) => n + (r.tools_payload_bytes || 0), 0) / 4 / 1000);
      return [tools.toLocaleString('en-US'), String(tokens)];
    },
  },
  {
    what:  'derived trust distribution',
    file:  DB_DOC,
    re:    /\*\*(\d+) verified \/ (\d+) candidate \/ (\d+) unverified\*\* as of (\d{4}-\d{2}-\d{2})/,
    expected: (captured) => {
      dated(captured[3]);
      const by = (word) => count((t) => t.trust === word);
      return [by('verified'), by('candidate'), by('unverified'), SNAPSHOT_DATE];
    },
  },
  {
    what:  'capability counts across the scanned packages',
    file:  DB_DOC,
    re:    /env_access\s+(\d+)\s+shell\s+(\d+)/,
    expected: () => {
      const caps = capabilityCounts();
      return [caps.env_access, caps.shell];
    },
  },
  {
    what:  'how many packages can both shell out and reach the network',
    file:  DB_DOC,
    re:    /(\d+) of those packages can both run other programs and reach the network/,
    expected: () => {
      const pkgs = Object.values(capabilities.packages || {});
      return [pkgs.filter((p) => p.found && p.found.shell && p.found.network).length];
    },
  },
  {
    what:  'how many packages were scanned, and how many are minified',
    file:  DB_DOC,
    re:    /(\d+) of\s+(\d+) ship at least one minified file/,
    expected: () => {
      const pkgs = Object.values(capabilities.packages || {});
      return [pkgs.filter((p) => p.coverage && p.coverage.minified).length, pkgs.length];
    },
  },
  {
    what:  'provenance dimension counts',
    file:  DB_DOC,
    re:    /provenance\s+bound (\d+), absent (\d+)/,
    expected: () => {
      const by = (status) => count((t) => t.trust_evidence?.dimensions?.provenance?.status === status);
      return [by('bound'), by('absent')];
    },
  },
  {
    what:  'entries listed in the official registry',
    file:  DB_DOC,
    re:    /(\d+) entries are listed as of (\d{4}-\d{2}-\d{2}) and all of them agree/,
    expected: (captured) => (dated(captured[1]),
      [count((t) => t.trust_evidence?.dimensions?.registry?.status === 'listed'), SNAPSHOT_DATE]),
  },
  {
    what:  'DB entry count (SKILL.md)',
    file:  'mcp-ecosystem-intelligence/SKILL.md',
    // Anchored on the sentence, not on "entries": a bare `(\d+) entries`
    // matched "~30–300 entries" from a paragraph about registry pagination and
    // cheerfully reported that the DB should hold 300.
    re:    /canonical example, (\d+) entries across ~(\d+) categories/,
    expected: () => [db.length, new Set(db.map((x) => x.category)).size],
  },
];

for (const claim of CLAIMS) {
  test(`${claim.file}: ${claim.what}`, () => {
    const text = read(claim.file);
    const m = text.match(claim.re);
    assert.ok(m, `the sentence carrying this figure was rewritten — ${claim.re} no longer matches ${claim.file}.\n`
      + 'Update the pattern in tests/docs_numbers.test.cjs so the claim keeps being checked.');

    const captured = m.slice(1);
    const expected = claim.expected(captured).map(String);
    assert.deepEqual(captured, expected,
      `${claim.file} says ${JSON.stringify(captured)}, the data says ${JSON.stringify(expected)}`);

    if (claim.nameCheck) claim.nameCheck(captured);
  });
}

test('the eval snapshot distinguishes a handshake from a usable tool list', () => {
  // "40 complete a handshake" and "39 list at least one tool" are different
  // facts, and the docs say both because one server (mcp-atlassian)
  // answered tools/list with an empty array. Collapsing them would be the
  // same class of overstatement this whole file exists to prevent.
  const handshake = evals.filter((r) => r.status === 'pass').length;
  const withTools = evals.filter((r) => r.status === 'pass' && r.tool_count > 0).length;
  const readme = read(DB_DOC);
  if (handshake !== withTools) {
    assert.match(readme, new RegExp(`${withTools} of (them|those)`),
      `${handshake} entries pass but only ${withTools} list a tool; ${DB_DOC} should say both`);
  }
});

test('no entry claims a tool count the eval contradicted without the DB being updated', () => {
  // Not a documentation check, but it belongs next to one: the numbers the
  // docs quotes come from these fields, and drift here is what makes the
  // documented figures quietly wrong.
  const drifted = evals.filter((r) => r.tool_count_drift && r.status === 'pass' && r.tool_count > 0);
  const listed = drifted.map((r) => `${r.name} (DB ${r.tool_count_db} → observed ${r.tool_count})`);
  // This is a report, not a failure: the DB is the reviewed value and the eval
  // is an observation, so a human decides which is right. It fails only if
  // nothing in the repo acknowledges the drift.
  if (listed.length) {
    const readme = read(DB_DOC);
    assert.match(readme, /drift/i,
      `${listed.length} entries drift from their observed tool count and ${DB_DOC} does not mention drift at all:\n  ${listed.join('\n  ')}`);
  }
});
