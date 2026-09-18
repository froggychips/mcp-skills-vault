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

test('what blocks is the trust gate\'s list, not a wider one', () => {
  // The first version asked `deriveTrust(...) === 'unverified'`, which also
  // catches `smoke: fail` — turning "our sandbox could not start it" into
  // "must not run", flatly against the rule that behaviour never demotes.
  const smokeFailed = classifyEntry(entry(verified({ smoke: dim('fail') })), pass, at);
  assert.equal(smokeFailed.classification, 'Experimental');
  assert.match(smokeFailed.why, /smoke: fail/);
});

test('an unpublished *name* survives a version change; a yanked version does not', () => {
  // `gone` means nothing is published under that name at all — worse than
  // unpublished, because a free name can be claimed by somebody else — and it
  // is true whatever version the entry moves to. `yanked` is a statement about
  // one version, so evidence for 0.9.0 is not a finding about 1.0.0.
  const staleGone = { ...verified({ availability: dim('gone') }), artifact_id: 'npm:pkg@0.9.0' };
  assert.equal(classifyEntry(entry(staleGone), pass, at).classification, 'Deprecated');

  const staleYank = { ...verified({ availability: dim('yanked') }), artifact_id: 'npm:pkg@0.9.0' };
  const r = classifyEntry(entry(staleYank), pass, at);
  assert.equal(r.classification, 'Experimental');
  assert.match(r.why, /recorded evidence is about npm:pkg@0\.9\.0/);
});

test('complete evidence with no recorded identity cannot reach Core', () => {
  // The binding used to be checked only when the trust verdict was already
  // weak, so evidence that looked complete and named no artifact sailed past
  // it — with a bound passing eval, straight to Core.
  const anonymous = { dimensions: verified().dimensions };   // no artifact_id
  const r = classifyEntry(entry(anonymous), pass, at);
  assert.equal(r.classification, 'Experimental');
  assert.equal(r.bound.evidence.state, 'unknown');
  assert.match(r.why, /not tied to a named artifact/);
});

test('an entry whose own version fields disagree names no artifact', () => {
  // `toTypedEntry` prefers the DB's `version` over the one in the launch
  // command and records a warning when they differ. Reading the winner and
  // ignoring the warning bound evidence for 1.0.0 to an entry that installs
  // 2.0.0 — the very comparison this is supposed to make safe.
  const conflicted = entry(verified(), { version: '2.0.0' });
  const r = classifyEntry(conflicted, pass, at);
  assert.equal(r.classification, 'Experimental');
  assert.match(r.why, /does not name one artifact/);
});

test('a required dimension needs a status that dimension can produce', () => {
  // `POSITIVE_STATUSES` is one flat vocabulary, so `artifact: clean` and
  // `advisories: verified` — words neither check emits — satisfied
  // requirements neither had met. Evidence arrives through pull requests.
  const wrongWords = entry({
    artifact_id: AID,
    dimensions: { availability: dim('present'), artifact: dim('clean'), advisories: dim('verified') },
  });
  const r = classifyEntry(wrongWords, pass, at);
  assert.equal(r.classification, 'Experimental');
  assert.match(r.why, /not an affirmative result/);
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

  // And enough positive points must not outweigh a contradiction. It lands in
  // Experimental rather than Deprecated deliberately: `scores.cjs` excludes
  // source_binding from the blocking set, because a metadata disagreement
  // between a package's repository field and ours is something to read, not a
  // refusal to install. The tier uses that same set so the two cannot drift.
  const contradicted = entry(verified({ source_binding: dim('mismatch') }));
  const c = classifyEntry(contradicted, pass, at);
  assert.equal(c.classification, 'Experimental');
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

test('packageKeyOfId reads a stored id by ecosystem, not by the last @', () => {
  // Splitting at the last `@` turned a missing input into a value twice:
  // `npm:@scope/pkg` with no version became `"npm:"` — a key of nothing that
  // then matched any other id degrading the same way — and a git URL carrying
  // credentials became `git:git+https://user`.
  const { packageKeyOfId } = require('../mcp-ecosystem-intelligence/scripts/lib/tiers.cjs');
  const cases = {
    'npm:@scope/pkg@1.0.0':          'npm:@scope/pkg',
    'npm:@scope/pkg':                'npm:@scope/pkg',
    'npm:pkg@1.0.0':                 'npm:pkg',
    'npm:pkg':                       'npm:pkg',
    'pypi:a_b@1.0':                  'pypi:a-b',
    'pypi:a.b':                      'pypi:a-b',
    'oci:ghcr.io/o/r@sha256:aa':     'oci:ghcr.io/o/r',
    'oci:ghcr.io/o/r:tag':           'oci:ghcr.io/o/r',
    'oci:host:5000/o/r:tag':         'oci:host:5000/o/r',
    'git:git+https://user@host/x':   'git:git+https://user@host/x',
  };
  for (const [id, want] of Object.entries(cases)) assert.equal(packageKeyOfId(id), want, id);
  // An id this cannot read is null, never a prefix.
  for (const id of ['', 'npm:', 'nonsense', 'npm', null, undefined, 42]) {
    assert.equal(packageKeyOfId(id), null, String(id));
  }
});

test('PyPI versions compare by PEP 440, and never through Number', () => {
  // `Number` merged `9007199254740992` and `9007199254740993` — different
  // releases that round to the same double — so evidence could bind across
  // them. A version string is not a number.
  const m = require('../mcp-ecosystem-intelligence/scripts/lib/entry_model.cjs');
  const same = [['1.0.27.0', '1.0.27'], ['1.0.0', '1'], ['01.2', '1.2'],
    ['1.0rc01', '1.0rc1'], ['1.0+abc.01', '1.0+abc.1'],
    ['1.0.post007', '1.0.post7'], ['1.0.dev01', '1.0.dev1']];
  for (const [a, b] of same) {
    assert.equal(m.normalizePypiVersion(a), m.normalizePypiVersion(b), `${a} vs ${b}`);
  }
  assert.notEqual(
    m.normalizePypiVersion('9007199254740992'),
    m.normalizePypiVersion('9007199254740993'),
    'two releases a double cannot tell apart',
  );
  // npm is not folded: `1.0.0` and `1` are not the same semver, and `a-b` and
  // `a.b` are different packages.
  assert.equal(m.comparableArtifactId({ ecosystem: 'npm', package: 'a.b', version: '1.0.0' }), 'npm:a.b@1.0.0');
  assert.notEqual(
    m.comparableArtifactId({ ecosystem: 'npm', package: 'a-b', version: '1.0.0' }),
    m.comparableArtifactId({ ecosystem: 'npm', package: 'a.b', version: '1.0.0' }),
  );
});

test('an OCI digest has to look like one', () => {
  const m = require('../mcp-ecosystem-intelligence/scripts/lib/entry_model.cjs');
  assert.equal(m.isExactArtifact({ ecosystem: 'oci', image: 'x', digest: 'sha256:bad' }), false);
  assert.equal(m.isExactArtifact({ ecosystem: 'oci', image: 'x', digest: `sha256:${'a'.repeat(64)}` }), true);
  assert.equal(m.isExactArtifact({ ecosystem: 'oci', image: 'x', tag: 'latest' }), false);
  assert.equal(m.isExactArtifact({ ecosystem: 'git', source: 'git+https://x' }), false);
});

test('a local version label is not a bag of numbers', () => {
  // The fix for `Number` overshot: stripping zeros from every run of digits
  // made `1.0+abc01` equal `1.0+abc1`, and those are distinct versions. PEP
  // 440 compares a local label component-wise, and only an *entirely* numeric
  // component compares numerically.
  const m = require('../mcp-ecosystem-intelligence/scripts/lib/entry_model.cjs');
  for (const [a, b] of [['1.0+abc01', '1.0+abc1'], ['1.0+01abc', '1.0+1abc']]) {
    assert.notEqual(m.normalizePypiVersion(a), m.normalizePypiVersion(b), `${a} vs ${b}`);
  }
  // A purely numeric component still folds.
  assert.equal(m.normalizePypiVersion('1.0+abc.01'), m.normalizePypiVersion('1.0+abc.1'));
  assert.equal(m.normalizePypiVersion('1.0+007'), m.normalizePypiVersion('1.0+7'));
});
