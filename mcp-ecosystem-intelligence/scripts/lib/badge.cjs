'use strict';
/**
 * A "vetted by mcp-vault" badge that cannot outlive what it says.
 *
 * The obvious badge is a green rectangle with a tier on it, generated once and
 * committed. It would be wrong within a week: the advisory check behind every
 * npm and PyPI tier has a shelf life of 7 days, and a README badge is read for
 * years. A badge that keeps saying "Core" after anyone last looked is the
 * `last_checked` field again, in a place more people see.
 *
 * So the badge is three facts and no adjectives, and none of them is decided
 * here (docs/adr/0001-findings-and-time.md):
 *
 *   the tier      derived by `classifyEntry`, never stored
 *   the date      of the newest observation behind it, on the badge itself, so
 *                 a reader can see how old the claim is without clicking
 *   the state     a view of the entry's Decision and its observations:
 *                   blocked     the Decision is `deny` — an observed, blocking
 *                               finding. Outranks stale: a failed check stays
 *                               news however old it is.
 *                   stale       an observation of a dimension the tier
 *                               *requires* is stale at asOf (observationState)
 *                   unverified  nothing was observed about *this* artifact
 *                   otherwise   the tier, in its colour
 *
 * The Decision is `decide()` over `fromEvidence` findings (the producer
 * `explain` uses) with the gate's own rules and no project policy: a badge on
 * somebody's README is the vault's claim, not any one project's bar. Evidence
 * counts only for the artifact it was collected on (a name-scoped `gone`
 * holds across versions), so the badge and the tier cannot disagree about
 * what blocks.
 *
 * Rendered here, by code, as a flat shields-style SVG — no request to
 * shields.io or anywhere else at generation time, and the same input produces
 * the same bytes. Text width comes from a fixed per-character table for
 * Verdana 11px (the font shields uses), so there is no font measurement and
 * nothing platform-dependent. The table is an approximation; a badge a pixel
 * too wide is fine, a badge that differs between two machines is not.
 *
 * The shields.io endpoint JSON is the alternative for authors who prefer their
 * badges served by shields; it carries the same label, message and colour.
 *
 * API:
 *   badgeModel(tool, { asOf, maxAgeDays }) -> { subject, observations, findings, decision, facts, policy }
 *   badgeState(tool, evalResult, { asOf, maxAgeDays, model })
 *                                       -> { name, slug, tier, why, state, effect, decided_by, stale,
 *                                            stale_dimensions, latest_evidence, label, message, color,
 *                                            color_name, model }
 *   evidenceAboutArtifact(tool)         -> the stored evidence that is about the current artifact, or null
 *   BADGE_POLICY                        -> the frozen effective policy badges are decided under
 *   renderSvg({ label, message, color, title }) -> string
 *   endpointJson(state)                 -> shields endpoint object
 *   slugFor(name)                       -> file-safe slug
 *   badgeUrls(name, base)               -> { svg, json, page, shields }
 *   snippet(name, base)                 -> { markdown, html, shields_markdown }
 *   textWidth(s)                        -> number (px at Verdana 11)
 *   escXml(s)                           -> string
 */

const { classifyEntry, evidenceBinding, packageBinding, NAME_SCOPED } = require('./tiers.cjs');
const { requiredFor, DEFAULT_MAX_AGE_DAYS } = require('./evidence.cjs');
const { toTypedEntry } = require('./entry_model.cjs');
const { decide, observationState } = require('./finding.cjs');
const { subjectForTool, fromEvidence } = require('./findings_from.cjs');
const { effectivePolicy } = require('./policy_rules.cjs');
const { requireAsOf } = require('./clock.cjs');

// The gate's own rules, no policy file: `--no-policy`, frozen once.
const BADGE_POLICY = effectivePolicy(null, {}, { policyRules: false });

const SITE = 'https://mcp.froggychips.xyz';
const LABEL = 'mcp-vault';

// Hex for the SVG, the shields colour name for the endpoint JSON. Same pairs
// shields uses, so the two forms look alike.
const COLORS = {
  Core:         { hex: '#4c1',    name: 'brightgreen' },
  Recommended:  { hex: '#97ca00', name: 'green' },
  Experimental: { hex: '#dfb317', name: 'yellow' },
  Deprecated:   { hex: '#e05d44', name: 'red' },
  stale:        { hex: '#9f9f9f', name: 'lightgrey' },
  unverified:   { hex: '#9f9f9f', name: 'lightgrey' },
};

function escXml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;')
    // Characters XML 1.0 does not allow at all. An entry name is text from a
    // pull request; a control character in it must not make every badge file
    // unparsable.
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F￾￿]/g, '');
}

// Verdana 11px advance widths for printable ASCII, 32..126, rounded to 0.1px.
const WIDTHS = [
  3.9, 4.3, 5.0, 9.0, 7.0, 11.9, 7.9, 3.0, 4.9, 4.9, 7.0, 9.0, 4.0, 4.9, 4.0, 4.9, // ' '..'/'
  7.0, 7.0, 7.0, 7.0, 7.0, 7.0, 7.0, 7.0, 7.0, 7.0,                               // 0..9
  4.9, 4.9, 9.0, 9.0, 9.0, 6.0, 11.0,                                             // :..@
  7.5, 7.6, 7.7, 8.5, 7.0, 6.3, 8.5, 8.3, 4.6, 5.0, 7.6, 6.1, 9.2,                // A..M
  8.2, 8.7, 6.6, 8.7, 7.7, 7.5, 6.8, 8.1, 7.5, 10.9, 7.5, 6.8, 7.5,               // N..Z
  4.9, 4.9, 4.9, 9.0, 7.0, 7.0,                                                   // [..`
  6.6, 6.9, 5.7, 6.9, 6.6, 3.9, 6.9, 7.0, 3.0, 3.8, 6.5, 3.0, 10.7,               // a..m
  7.0, 6.7, 6.9, 6.9, 4.7, 5.7, 4.3, 7.0, 6.5, 9.0, 6.5, 6.5, 5.8,                // n..z
  7.0, 4.9, 7.0, 9.0,                                                             // {..~
];
const MIDDLE_DOT = 4.0;
const FALLBACK = 7.0;

function textWidth(s) {
  let w = 0;
  for (const ch of String(s ?? '')) {
    const c = ch.codePointAt(0);
    if (c >= 32 && c <= 126) w += WIDTHS[c - 32];
    else if (c === 0xB7) w += MIDDLE_DOT;
    else w += FALLBACK;
  }
  // Tenths, so floating-point accumulation cannot differ run to run.
  return Math.round(w * 10) / 10;
}

/**
 * A file-safe name for an entry. Readable on purpose (`@scope/pkg` becomes
 * `scope__pkg`) — and therefore not injective in principle, so the writer
 * checks for collisions and refuses rather than letting one entry's badge
 * overwrite another's.
 */
function slugFor(name) {
  const s = String(name ?? '')
    .toLowerCase()
    .replace(/^@/, '')
    .replace(/\//g, '__')
    .replace(/[^a-z0-9._-]/g, '-')
    .replace(/^[.-]+/, '');
  return s || 'entry';
}

function newestDate(values) {
  return values.filter((d) => typeof d === 'string' && /^\d{4}-\d{2}-\d{2}/.test(d))
    .map((d) => d.slice(0, 10))
    .sort()
    .pop() || null;
}

function ecosystemOf(tool) {
  try { const t = toTypedEntry(tool); return t ? t.artifact.ecosystem : null; } catch { return null; }
}

/**
 * The stored evidence that is about the artifact this entry installs today.
 * Evidence recorded against another version, or not tied to a named artifact
 * at all, says nothing about these bytes — except a name-scoped status
 * (`gone`), which is about the package name and holds for every version. The
 * same preconditions `classifyEntry` applies before it reads a blocking
 * finding, so the tier and the badge cannot disagree about what blocks.
 */
function evidenceAboutArtifact(tool) {
  const ev = tool && tool.trust_evidence;
  if (!ev || !ev.dimensions || !Object.keys(ev.dimensions).length) return null;
  if (evidenceBinding(tool).state === 'yes') return ev;
  const av = ev.dimensions.availability;
  if (av && NAME_SCOPED.has(av.status) && packageBinding(tool).state === 'yes') {
    return { artifact_id: ev.artifact_id || null, dimensions: { availability: av } };
  }
  return null;
}

/**
 * Observations, findings and the one Decision for an entry's badge. Nothing
 * here computes an effect: `decide()` does, over the table in
 * lib/policy_rules.cjs.
 */
function badgeModel(tool, { asOf, maxAgeDays = DEFAULT_MAX_AGE_DAYS } = {}) {
  const at = requireAsOf(asOf, 'badgeModel');
  const s = subjectForTool(tool);
  const evidence = evidenceAboutArtifact(tool);
  // Required dimensions never checked are `no-data` findings: no evidence is
  // `unknown`, never a clean badge.
  const ev = fromEvidence(evidence, { subject: s, asOf: at, maxAgeDays, required: requiredFor(ecosystemOf(tool)) });
  const facts = {
    [s.id]: {
      mode: 'evidence',
      entry: {
        install_cmd:  (tool && tool.install_cmd) || '',
        license:      (tool && tool.license) ?? null,
        health_score: (tool && tool.health_score) ?? null,
        trust:        (tool && tool.trust) ?? null,
      },
      evidence: evidence || null,
    },
  };
  const [decision] = decide(ev.findings, BADGE_POLICY, at, { subjects: [s], facts });
  return { subject: s, observations: ev.observations, findings: ev.findings, decision, facts, policy: BADGE_POLICY };
}

/**
 * Everything a badge says about one entry, and why — read off the entry's
 * Decision and observations (`badgeModel`), plus the tier's name.
 *
 * `stale` is judged on the dimensions the tier *requires* for this ecosystem
 * (artifact + advisories for npm and PyPI, artifact for OCI): those are the
 * ones whose age makes the tier untrue. An old Scorecard read does not.
 */
function badgeState(tool, evalResult = null, opts = {}) {
  const { asOf, maxAgeDays = DEFAULT_MAX_AGE_DAYS } = opts;
  const at = requireAsOf(asOf, 'badgeState');
  const model = opts.model || badgeModel(tool, { asOf: at, maxAgeDays });
  const tier = classifyEntry(tool, evalResult, { now: at, maxAgeDays });
  const required = new Set(requiredFor(ecosystemOf(tool)));
  const staleRequired = model.observations
    .filter((o) => required.has(o.dimension) && observationState(o, at) === 'stale')
    .map((o) => o.dimension)
    .sort();

  // An observation with no recorded date is dated 1970-01-01 by the model; it
  // is not a date to print on somebody's README.
  const latest = newestDate(model.observations.map((o) => o.observed_at).filter((d) => d !== '1970-01-01'));
  const d = model.decision;
  let state;
  if (!model.observations.length) state = 'unverified';
  else if (d.effect === 'deny') state = 'Deprecated';
  else if (staleRequired.length) state = 'stale';
  // A tier that says Deprecated without a denying Decision cannot happen
  // (tests/badge.test.cjs checks the shipped DB); if it ever did, the badge
  // must not be red on the tier's word alone.
  else if (tier.classification === 'Deprecated') state = 'unverified';
  else state = tier.classification;

  // The Deprecated tier means "do not install: a check failed". On an author's
  // README "deprecated" would read as the author's own deprecation notice, so
  // the badge says what the tier does instead.
  const word = state === 'Deprecated' ? 'blocked' : state.toLowerCase();
  const message = latest ? `${word} · ${latest}` : word;
  const color = COLORS[state] || COLORS.unverified;
  return {
    name: tool.name,
    slug: slugFor(tool.name),
    tier: tier.classification,
    why: tier.why,
    state,
    effect: d.effect,
    decided_by: d.decided_by,
    stale: staleRequired.length > 0,
    stale_dimensions: staleRequired,
    latest_evidence: latest,
    label: LABEL,
    message,
    color: color.hex,
    color_name: color.name,
    model,
  };
}

/** Flat shields-style badge. Deterministic: same arguments, same bytes. */
function renderSvg({ label = LABEL, message, color, title }) {
  const lw = Math.round(textWidth(label)) + 10;
  const mw = Math.round(textWidth(message)) + 10;
  const w = lw + mw;
  const ltl = Math.round(textWidth(label) * 10);
  const mtl = Math.round(textWidth(message) * 10);
  const lx = lw * 5;              // centre, in the 10× text coordinate space
  const mx = lw * 10 + mw * 5;
  const L = escXml(label);
  const M = escXml(message);
  const T = escXml(title || `${label}: ${message}`);
  const fill = /^#[0-9a-fA-F]{3,8}$/.test(String(color)) ? color : COLORS.unverified.hex;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="20" role="img" aria-label="${L}: ${M}">`
    + `<title>${T}</title>`
    + '<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>'
    + `<clipPath id="r"><rect width="${w}" height="20" rx="3" fill="#fff"/></clipPath>`
    + `<g clip-path="url(#r)"><rect width="${lw}" height="20" fill="#555"/><rect x="${lw}" width="${mw}" height="20" fill="${fill}"/><rect width="${w}" height="20" fill="url(#s)"/></g>`
    + '<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">'
    + `<text aria-hidden="true" x="${lx}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="${ltl}">${L}</text>`
    + `<text x="${lx}" y="140" transform="scale(.1)" fill="#fff" textLength="${ltl}">${L}</text>`
    + `<text aria-hidden="true" x="${mx}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="${mtl}">${M}</text>`
    + `<text x="${mx}" y="140" transform="scale(.1)" fill="#fff" textLength="${mtl}">${M}</text>`
    + '</g></svg>\n';
}

/** https://shields.io/badges/endpoint-badge — schemaVersion 1. */
function endpointJson(state) {
  return {
    schemaVersion: 1,
    label: state.label,
    message: state.message,
    color: state.color_name,
    // A day: shields should not serve a verdict much older than the page.
    cacheSeconds: 86400,
  };
}

function badgeUrls(name, base = SITE) {
  const slug = slugFor(name);
  const svg  = `${base}/badges/${slug}.svg`;
  const json = `${base}/badges/${slug}.json`;
  return {
    svg,
    json,
    page: `${base}/entry/${slug}.html`,
    shields: `https://img.shields.io/endpoint?url=${encodeURIComponent(json)}`,
  };
}

function snippet(name, base = SITE) {
  const u = badgeUrls(name, base);
  const alt = 'vetted by mcp-vault';
  return {
    markdown: `[![${alt}](${u.svg})](${u.page})`,
    html: `<a href="${escXml(u.page)}"><img alt="${alt}" src="${escXml(u.svg)}"></a>`,
    shields_markdown: `[![${alt}](${u.shields})](${u.page})`,
  };
}

module.exports = {
  badgeModel, badgeState, evidenceAboutArtifact, BADGE_POLICY, renderSvg, endpointJson, slugFor, badgeUrls, snippet, textWidth, escXml,
  COLORS, LABEL, SITE,
};
