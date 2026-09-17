'use strict';
/**
 * Three axes, because one number was answering three different questions.
 *
 * `health_score` mixes stars, recency, registry presence and a licence penalty.
 * That is a reasonable *discovery* signal — is this project alive and looked
 * after — and it was being read as a measure of trust. It is not one. A package
 * can have 30k stars, weekly commits, an official registry listing, and also a
 * broken pin, an unsigned release and seventy tools with filesystem access.
 *
 * So:
 *   health — is the project maintained?          (popularity, recency, issues)
 *   trust  — do we know what we are running?     (artifact, signature, advisories)
 *   fit    — does this project need it?          (stack match, tool surface)
 *
 * And a recommendation is a policy over the three, not their sum. The rule that
 * matters: trust is a gate, not a term. Stars cannot compensate for a hash
 * mismatch, so a failing trust verdict is never outweighed by the other axes —
 * which is exactly what adding the numbers together would do.
 *
 * `health_score` keeps its name and its formula (calculate_health.cjs): it is
 * consumed by discovery and by policy, and renaming a field to make a point is
 * a poor trade.
 *
 * API:
 *   trustScore(evidence, opts)        -> { score, gate, reasons }
 *   fitScore(tool, stack, opts)       -> { score, reasons }
 *   recommend({ trust, health, fit }) -> { verdict, reasons }
 */

const { staleDimensions, DEFAULT_MAX_AGE_DAYS } = require('./evidence.cjs');

// What each dimension is worth when it says something good. Deliberately front
// loaded on the artifact: knowing *which bytes* you are running is the claim
// everything else qualifies.
const TRUST_WEIGHTS = {
  artifact:       { verified: 40, unverified: 0, mismatch: -100 },
  signature:      { verified: 20, absent: 0 },
  provenance:     { claimed: 10 },
  source_binding: { verified: 10, mismatch: -20 },
  advisories:     { clean: 15, 'advisories-present': 5, unverified: 0, vulnerable: -100 },
  dependencies:   { clean: 5, hooks: 2, 'advisories-present': 0 },
  smoke:          { pass: 0, fail: -5, skipped: 0 },   // behavioural, not a trust claim
};

// A negative weight is a finding, not a deduction: it blocks.
const BLOCKING = new Set(['mismatch', 'vulnerable']);

/**
 * Trust from recorded evidence.
 *
 * `gate` is the part that matters for a decision:
 *   'block' — something is actively wrong
 *   'thin'  — too little is known to call it verified
 *   'ok'    — the artifact is known and nothing contradicts it
 */
function trustScore(evidence, { now = Date.now(), maxAgeDays = DEFAULT_MAX_AGE_DAYS } = {}) {
  const dims = (evidence && evidence.dimensions) || {};
  const reasons = [];
  if (!Object.keys(dims).length) {
    return { score: 0, gate: 'thin', reasons: ['no evidence recorded for this entry'] };
  }

  const stale = new Set(staleDimensions(evidence, maxAgeDays, now).map((s) => s.dimension));
  let score = 0;
  let blocked = false;

  for (const [name, value] of Object.entries(dims)) {
    const table = TRUST_WEIGHTS[name];
    if (!table) continue;
    const weight = table[value.status];
    if (weight === undefined) continue;

    if (BLOCKING.has(value.status)) {
      blocked = true;
      reasons.push(`${name}: ${value.status} (as of ${value.checked_at})`);
      continue;
    }
    if (stale.has(name)) {
      // Half credit for an answer that has aged out: it was true once, and
      // "true once" is worth more than nothing and less than current.
      score += Math.max(0, Math.round(weight / 2));
      reasons.push(`${name}: ${value.status}, but ${value.checked_at} is past its shelf life`);
      continue;
    }
    score += weight;
    if (weight > 0) reasons.push(`${name}: ${value.status}`);
  }

  score = Math.max(0, Math.min(100, score));

  // The gate is not a threshold on the sum. Signature + provenance +
  // source_binding + advisories add up to 55 on their own, so an artifact that
  // was never verified — or was verified eight months ago — could clear a
  // numeric bar. Knowing *which bytes* run is the claim the others qualify, so
  // it is a precondition, not a term.
  const artifact = dims.artifact;
  const artifactCurrent = artifact
    && artifact.status === 'verified'
    && !stale.has('artifact');
  const gate = blocked ? 'block' : (artifactCurrent && score >= 55 ? 'ok' : 'thin');
  if (!blocked && !artifactCurrent) {
    reasons.unshift(artifact
      ? `artifact: ${artifact.status}${stale.has('artifact') ? ` (and ${artifact.checked_at} is past its shelf life)` : ''} — nothing else substitutes for that`
      : 'artifact was never verified — nothing else substitutes for that');
  }
  return { score, gate, reasons };
}

/**
 * Fit: does this project have a use for the entry, and what does it cost?
 *
 * Stack match is the signal; tool surface is the tax. A server that matches the
 * stack but injects 150 tool definitions into every request is a worse fit than
 * one that matches and injects 5.
 */
function fitScore(tool, stack, { signalToTools = {}, universal = [] } = {}) {
  const reasons = [];
  if (!tool) return { score: 0, reasons: ['no entry'] };
  // Callers pass a Set or an Array depending on where the list lives.
  const isUniversal = typeof universal.has === 'function'
    ? universal.has(tool.name)
    : Array.isArray(universal) && universal.includes(tool.name);

  const cats    = stack && stack.cats  ? [...stack.cats]  : [];
  const dbs     = stack && stack.dbs   ? [...stack.dbs]   : [];
  const infra   = stack && stack.infra ? [...stack.infra] : [];
  const signals = (stack && stack.signals) || [];

  let score = 0;

  if (isUniversal) {
    score += 40;
    reasons.push('useful in any project');
  }
  if (tool.category && cats.includes(tool.category)) {
    score += 35;
    reasons.push(`category ${tool.category} matches the detected stack`);
  }
  // A direct signal → entry mapping is the strongest statement of fit, and the
  // signal's own confidence carries through: an entry recommended because of an
  // env var name is a weaker recommendation than one backed by a dependency.
  for (const [signal, names] of Object.entries(signalToTools)) {
    if (!names.includes(tool.name)) continue;
    if (!dbs.includes(signal) && !infra.includes(signal)) continue;
    const sig = signals.find((s) => s.value === signal);
    const confidence = sig ? sig.confidence : 0.8;
    score += Math.round(40 * confidence);
    reasons.push(`maps to "${signal}" (${sig ? `${sig.kind}, ${sig.sources.join(' + ')}` : 'detected'}, confidence ${confidence})`);
  }

  // The tax. Numbers from this repo's own README: ~200–500 tokens per tool
  // definition, injected on every request.
  const tools = Number.isFinite(tool.est_tools_count) ? tool.est_tools_count : null;
  if (tools !== null) {
    if (tools > 100)      { score -= 25; reasons.push(`${tools} tools — a large standing context cost`); }
    else if (tools > 40)  { score -= 15; reasons.push(`${tools} tools — sizeable context cost`); }
    else if (tools > 15)  { score -= 5;  reasons.push(`${tools} tools`); }
    if (tools > 15 && tool.toolsets) reasons.push('can be narrowed — see `toolsets`');
  }

  return { score: Math.max(0, Math.min(100, score)), reasons };
}

/**
 * The recommendation.
 *
 * Trust gates; health and fit rank. This is the asymmetry that makes the three
 * axes worth separating: no amount of popularity turns a mismatched hash into
 * an acceptable install.
 */
function recommend({ trust, health, fit } = {}) {
  const reasons = [];
  const t = trust || { score: 0, gate: 'thin', reasons: [] };
  const f = fit   || { score: 0, reasons: [] };
  const h = Number.isFinite(health) ? health : null;

  if (t.gate === 'block') {
    return { verdict: 'avoid', reasons: ['trust: ' + (t.reasons[0] || 'a check failed'), ...t.reasons.slice(1, 3)] };
  }

  if (t.gate === 'thin') reasons.push(`little is known about this artifact yet (trust ${t.score}/100)`);
  if (f.score >= 60)     reasons.push(`fits this project (fit ${f.score}/100)`);
  else if (f.score > 0)  reasons.push(`partial fit (${f.score}/100)`);
  else                   reasons.push('nothing in this project points at it');
  if (h !== null && h < 50) reasons.push(`project health is low (${h})`);

  let verdict;
  if (t.gate === 'ok' && f.score >= 60) verdict = 'recommended';
  else if (f.score >= 40)               verdict = 'consider';
  else                                  verdict = 'not-now';

  // A thin trust score never reads as "recommended": that is the word doing
  // the work the evidence has not done.
  if (verdict === 'recommended' && t.gate !== 'ok') verdict = 'consider';
  return { verdict, reasons };
}

module.exports = { trustScore, fitScore, recommend, TRUST_WEIGHTS };
