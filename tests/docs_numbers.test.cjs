'use strict';
/**
 * The numbers in the documentation, checked against the data they describe.
 *
 * Every count in README.md and SKILL.md was written by hand at some point and
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
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

const db    = JSON.parse(read('mcp-ecosystem-intelligence/assets/tools_database.json')).tools;
const evals = JSON.parse(read('mcp-ecosystem-intelligence/assets/eval_results.json')).results;

const count   = (fn) => db.filter(fn).length;
const tier    = (name) => count((t) => t.classification === name);
const withTools = db.filter((t) => Number.isFinite(t.est_tools_count));
const heaviest  = withTools.reduce((m, t) => (t.est_tools_count > m.est_tools_count ? t : m), withTools[0]);

/**
 * Each claim: where it lives, the pattern that captures the number(s), and what
 * they should be. `expected` is an array so one sentence can carry several.
 */
const CLAIMS = [
  {
    what:  'DB entry count (scan output example)',
    file:  'README.md',
    re:    /^(\d+) entries checked — \d+ failure\(s\)$/m,
    expected: () => [db.length],
  },
  {
    what:  'DB entry count (Vault DB section)',
    file:  'README.md',
    re:    /\*\*(\d+) entries\*\* across ~(\d+) categories/,
    expected: () => [db.length, new Set(db.map((t) => t.category)).size],
  },
  {
    what:  'tier distribution',
    file:  'README.md',
    re:    /Distribution: \*\*(\d+) Core \/ (\d+) Recommended \/ (\d+) Experimental\*\*/,
    expected: () => [tier('Core'), tier('Recommended'), tier('Experimental')],
  },
  {
    what:  'npm entry count',
    file:  'README.md',
    re:    /of the DB's (\d+) npm entries/,
    expected: () => [count((t) => /^npx\s/.test(t.install_cmd || ''))],
  },
  {
    what:  'server count and the tool-surface spread',
    file:  'README.md',
    re:    /With (\d+) servers in the DB the spread is wide: `([\w-]+)` = (\d+) tool vs\. `([\w-]+)` = (\d+) tools/,
    // The two named entries are *examples*, and several entries have one tool —
    // so the names are echoed back and checked by `nameCheck` against what they
    // claim to be, rather than compared to one arbitrarily chosen entry. The
    // first version of this test picked its own example and then failed because
    // the README had named an equally correct one.
    expected: (captured) => [db.length, captured[1], 1, captured[3], heaviest.est_tools_count],
    nameCheck: (captured) => {
      const light = db.find((t) => t.name === captured[1]);
      assert.ok(light, `README names \`${captured[1]}\` as a one-tool server; there is no such entry`);
      assert.equal(light.est_tools_count, 1, `${captured[1]} no longer has 1 tool`);
      const heavy = db.find((t) => t.name === captured[3]);
      assert.ok(heavy, `README names \`${captured[3]}\` as the heaviest server; there is no such entry`);
      assert.equal(heavy.est_tools_count, heaviest.est_tools_count,
        `${captured[3]} is no longer the heaviest entry — ${heaviest.name} has ${heaviest.est_tools_count}`);
    },
  },
  {
    what:  'behavioural eval headline',
    file:  'README.md',
    re:    /(\d+) of the (\d+) entries with a runnable launch command complete a handshake/,
    expected: () => [evals.filter((r) => r.status === 'pass').length, evals.length],
  },
  {
    what:  'tools observed and their token cost',
    file:  'README.md',
    re:    /listing ([\d,]+) tools between them, ≈([\d,]+)k tokens/,
    expected: () => {
      const tools  = evals.reduce((n, r) => n + (r.tool_count || 0), 0);
      const tokens = Math.round(evals.reduce((n, r) => n + (r.tools_payload_bytes || 0), 0) / 4 / 1000);
      return [tools.toLocaleString('en-US'), String(tokens)];
    },
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
  // facts, and the README says both because one server (mcp-atlassian)
  // answered tools/list with an empty array. Collapsing them would be the
  // same class of overstatement this whole file exists to prevent.
  const handshake = evals.filter((r) => r.status === 'pass').length;
  const withTools = evals.filter((r) => r.status === 'pass' && r.tool_count > 0).length;
  const readme = read('README.md');
  if (handshake !== withTools) {
    assert.match(readme, new RegExp(`${withTools} of (them|those)`),
      `${handshake} entries pass but only ${withTools} list a tool; README should say both`);
  }
});

test('no entry claims a tool count the eval contradicted without the DB being updated', () => {
  // Not a documentation check, but it belongs next to one: the numbers the
  // README quotes come from these fields, and drift here is what makes the
  // documented figures quietly wrong.
  const drifted = evals.filter((r) => r.tool_count_drift && r.status === 'pass' && r.tool_count > 0);
  const listed = drifted.map((r) => `${r.name} (DB ${r.tool_count_db} → observed ${r.tool_count})`);
  // This is a report, not a failure: the DB is the reviewed value and the eval
  // is an observation, so a human decides which is right. It fails only if
  // nothing in the repo acknowledges the drift.
  if (listed.length) {
    const readme = read('README.md');
    assert.match(readme, /drift/i,
      `${listed.length} entries drift from their observed tool count and the README does not mention drift at all:\n  ${listed.join('\n  ')}`);
  }
});
