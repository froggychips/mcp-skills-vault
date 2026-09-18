'use strict';
/**
 * What a tier is allowed to be a function of.
 *
 * The tier used to be a threshold on `health_score`, and `health_score`
 * contained `+30 if in_registry` — a hand-set boolean that disagreed with the
 * live registry for 26 of 114 entries and outweighed every measured term put
 * together. The first thing a reader saw about an entry was mostly a field
 * nobody had checked.
 *
 * These tests pin the three properties that replace it: the tier comes from
 * measured evidence, a stored label cannot forge it, and a sandbox that could
 * not run something never counts against that thing.
 */

const test   = require('node:test');
const assert = require('node:assert/strict');

const { classifyEntry, evalIndex, TIER_ORDER } = require('../mcp-ecosystem-intelligence/scripts/lib/tiers.cjs');

const DAY = '2026-09-17';
const dim = (status) => ({ status, checked_at: DAY, verified_at: DAY });
const NOW = new Date(`${DAY}T00:00:00Z`).getTime();
const at  = { now: NOW };

const CMD = 'npx -y pkg@1.0.0';
const AID = 'npm:pkg@1.0.0';

/** Evidence that is enough to call an npm artifact verified, tied to AID. */
const verified = (over = {}) => ({
  artifact_id: AID,
  dimensions: {
    availability:   dim('present'),
    artifact:       dim('verified'),
    signature:      dim('verified'),
    source_binding: dim('verified'),
    advisories:     dim('clean'),
    ...over,
  },
});

const entry = (evidence, over = {}) => ({ name: 'x', install_cmd: CMD, trust_evidence: evidence, ...over });
// A passing eval that recorded *which artifact* it launched. Without that
// field a pass cannot be attributed to this entry at all.
const pass  = { name: 'x', status: 'pass', tool_count: 7, identity: { artifact_id: AID } };
const crash = { name: 'x', status: 'fail', failure_class: 'CRASH', error_code: 'exit 1', identity: { artifact_id: AID } };

test('Core needs both halves: verified bytes and an observed handshake', () => {
  assert.equal(classifyEntry(entry(verified()), pass, at).classification, 'Core');
  assert.equal(classifyEntry(entry(verified()), null, at).classification, 'Recommended');
});

test('behaviour promotes, never demotes', () => {
  // 59 verified entries did not complete a handshake, and the sandbox runs
  // with an empty environment: @azure/mcp and its kind exit 1 because no API
  // key was present and say so in prose the classifier does not recognise.
  // Demoting them would record our sandbox's limits as a fact about them.
  const crashed = classifyEntry(entry(verified()), crash, at);
  assert.equal(crashed.classification, 'Recommended');
  assert.match(crashed.why, /did not complete a handshake/);

  for (const cls of ['NEEDS_ENV', 'NEEDS_NET', 'NEEDS_ARGS', 'SANDBOX_UNAVAILABLE']) {
    assert.equal(
      classifyEntry(entry(verified()), { name: 'x', status: 'fail', failure_class: cls }, at).classification,
      'Recommended',
      cls,
    );
  }
});

test('Deprecated means "do not install", and each way of getting there is named', () => {
  for (const status of ['gone', 'version-gone', 'yanked']) {
    const r = classifyEntry(entry(verified({ availability: dim(status) })), pass, at);
    assert.equal(r.classification, 'Deprecated', status);
    assert.match(r.why, new RegExp(`availability: ${status}`));
  }
  // A CVE that applies to the pinned version, and bytes that are not the
  // bytes we verified — both block, and both outrank a clean handshake.
  const vulnerable = classifyEntry(entry(verified({ advisories: dim('vulnerable') })), pass, at);
  assert.equal(vulnerable.classification, 'Deprecated');
  assert.match(vulnerable.why, /advisories: vulnerable/);

  const mismatch = classifyEntry(entry(verified({ artifact: dim('mismatch') })), pass, at);
  assert.equal(mismatch.classification, 'Deprecated');
  assert.match(mismatch.why, /artifact: mismatch/);
});

test('an omitted check cannot make an entry look stronger', () => {
  // The first version of this file asked `trustScore().gate === 'ok'`, which
  // is "artifact verified plus 55 points". `artifact: verified` (40) with
  // `signature: verified` (20) and *no advisory check at all* cleared that bar
  // and reached Core — a missing input paying for a stronger verdict. The tier
  // now asks deriveTrust with requiredFor(ecosystem), which demands the
  // dimensions that matter for the ecosystem.
  const noAdvisories = entry({
    artifact_id: AID,
    dimensions: { artifact: dim('verified'), signature: dim('verified') },
  });
  const r = classifyEntry(noAdvisories, pass, at);
  assert.equal(r.classification, 'Experimental');
  assert.match(r.why, /never checked for this entry: advisories/);

  // And enough positive points must not outweigh a contradiction.
  const contradicted = entry(verified({ source_binding: dim('mismatch') }));
  const c = classifyEntry(contradicted, pass, at);
  assert.equal(c.classification, 'Deprecated');
  assert.match(c.why, /source_binding: mismatch/);

  assert.equal(classifyEntry(entry(null), pass, at).classification, 'Experimental');
  assert.equal(classifyEntry({ name: 'x' }, pass, at).classification, 'Experimental');
});

test('evidence about other bytes is not evidence about these', () => {
  // Change an entry from pkg@1.0.0 to pkg@2.0.0 and every stored claim under
  // it is a statement about bytes that are no longer installed. mergeEvidence
  // already refuses to inherit across artifact ids; so does the tier.
  const moved = entry(verified(), { install_cmd: 'npx -y pkg@2.0.0' });
  const r = classifyEntry(moved, pass, at);
  assert.equal(r.classification, 'Experimental');
  assert.match(r.why, /recorded evidence is about npm:pkg@1\.0\.0/);
  assert.match(r.why, /now installs npm:pkg@2\.0\.0/);
  assert.equal(r.bound.evidence.state, 'no');
});

test('a handshake against another artifact does not reach Core either', () => {
  const old = { name: 'x', status: 'pass', tool_count: 7, identity: { artifact_id: 'npm:pkg@0.9.0' } };
  const r = classifyEntry(entry(verified()), old, at);
  assert.equal(r.classification, 'Recommended');
  assert.match(r.why, /against npm:pkg@0\.9\.0 rather than npm:pkg@1\.0\.0/);

  // And a pass that recorded no identity at all — which is every row in the
  // shipped snapshot today — says so rather than counting.
  const anonymous = { name: 'x', status: 'pass', tool_count: 7 };
  const a = classifyEntry(entry(verified()), anonymous, at);
  assert.equal(a.classification, 'Recommended');
  assert.match(a.why, /did not record which artifact it launched/);
  assert.equal(a.bound.behaviour.state, 'unknown');
});

test('a stored label cannot forge a tier', () => {
  // The whole point of deriving it: an entry arriving through a pull request
  // carries fields a contributor typed. None of them are read here.
  const forged = { name: 'x', install_cmd: CMD, classification: 'Core', trust: 'verified', in_registry: true, health_score: 110 };
  assert.equal(classifyEntry(forged, pass, at).classification, 'Experimental');
});

test('a claim past its shelf life stops counting', () => {
  // Why the tier is computed rather than stored: it is a function of the
  // evidence *and of today*. A stored copy would go quietly wrong while the
  // file sat unchanged — exactly what `in_registry` and `last_checked` did.
  const fresh = classifyEntry(entry(verified()), pass, at);
  assert.equal(fresh.classification, 'Core');

  const muchLater = { now: NOW + 400 * 86400 * 1000 };
  const aged = classifyEntry(entry(verified()), pass, muchLater);
  assert.equal(aged.classification, 'Experimental');
  assert.match(aged.why, /shelf life/);
});

test('evalIndex tolerates a missing or malformed snapshot', () => {
  assert.equal(evalIndex(undefined).size, 0);
  assert.equal(evalIndex(null).size, 0);
  assert.equal(evalIndex([{ name: 'a' }, { name: 'b' }]).get('b').name, 'b');
});

test('the shipped eval snapshot cannot promote anything to Core yet', () => {
  // Not a defect in the tier — a gap in the data, and the tier saying so
  // instead of guessing. No row in eval_results.json records the artifact it
  // launched, so no pass can be attributed to the entry it sits next to.
  // mcp_eval writes `identity` on every row now, so the next weekly run fills
  // this in and Core comes back on its own.
  const db = require('../mcp-ecosystem-intelligence/assets/tools_database.json').tools;
  const results = require('../mcp-ecosystem-intelligence/assets/eval_results.json').results;
  const ix = evalIndex(results);
  const withIdentity = results.filter((r) => r.identity && r.identity.artifact_id);
  const core = db.filter((t) => classifyEntry(t, ix.get(t.name) || null).classification === 'Core');
  assert.equal(core.length, withIdentity.length === 0 ? 0 : core.length,
    'a Core tier appeared from a snapshot that records no artifact identity');
});

test('the shipped DB stores no tier, no in_registry and no last_checked', () => {
  // These three were the reason for the change: a tier over a score that put
  // 91 of 114 entries in one bucket, a registry flag wrong for 26 entries,
  // and a "last checked" date reading 2026-07-31 across every row while the
  // evidence beneath it was a day old. If one comes back, so does the bug.
  const db = require('../mcp-ecosystem-intelligence/assets/tools_database.json').tools;
  for (const field of ['classification', 'in_registry', 'last_checked']) {
    const carriers = db.filter((t) => field in t).map((t) => t.name);
    assert.deepEqual(carriers, [], `${carriers.length} entries still carry ${field}`);
  }
  // And every entry can still be placed, without any of them.
  const ix = evalIndex(require('../mcp-ecosystem-intelligence/assets/eval_results.json').results);
  for (const t of db) {
    const r = classifyEntry(t, ix.get(t.name) || null);
    assert.ok(r.classification in TIER_ORDER, `${t.name}: ${r.classification}`);
    assert.ok(r.why && r.why.length > 0, `${t.name} has a tier with no reason`);
  }
});
