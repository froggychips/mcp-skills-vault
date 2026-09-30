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
 * So the badge is three facts and no adjectives:
 *
 *   the tier      derived by `classifyEntry`, never stored
 *   the date      of the newest evidence behind it, on the badge itself, so a
 *                 reader can see how old the claim is without clicking
 *   staleness     if any dimension the tier *requires* is past its shelf life,
 *                 the badge says `stale` in grey instead of the tier's colour.
 *                 Deprecated (shown as `blocked`) outranks stale: a failed
 *                 check stays news however old it is.
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
 *   badgeState(tool, evalResult, opts)  -> { name, slug, tier, why, state, stale, stale_dimensions,
 *                                            latest_evidence, label, message, color, color_name }
 *   renderSvg({ label, message, color, title }) -> string
 *   endpointJson(state)                 -> shields endpoint object
 *   slugFor(name)                       -> file-safe slug
 *   badgeUrls(name, base)               -> { svg, json, page, shields }
 *   snippet(name, base)                 -> { markdown, html, shields_markdown }
 *   textWidth(s)                        -> number (px at Verdana 11)
 *   escXml(s)                           -> string
 */

const { classifyEntry } = require('./tiers.cjs');
const { staleDimensions, requiredFor, DEFAULT_MAX_AGE_DAYS } = require('./evidence.cjs');
const { toTypedEntry } = require('./entry_model.cjs');

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

/**
 * Everything a badge says about one entry, and why.
 *
 * `stale` is judged on the dimensions the tier *requires* for this ecosystem
 * (artifact + advisories for npm and PyPI, artifact for OCI): those are the
 * ones whose age makes the tier untrue. An old Scorecard read does not.
 */
function badgeState(tool, evalResult = null, opts = {}) {
  const { now = Date.now(), maxAgeDays = DEFAULT_MAX_AGE_DAYS } = opts;
  const tier = classifyEntry(tool, evalResult, { now, maxAgeDays });
  const evidence = (tool && tool.trust_evidence) || null;
  const dims = (evidence && evidence.dimensions) || {};
  let ecosystem = null;
  try { const t = toTypedEntry(tool); ecosystem = t ? t.artifact.ecosystem : null; } catch { /* unparsable */ }
  const required = new Set(requiredFor(ecosystem));
  const staleRequired = staleDimensions(evidence, maxAgeDays, now)
    .filter((s) => required.has(s.dimension))
    .map((s) => s.dimension)
    .sort();

  const latest = newestDate(Object.values(dims).map((v) => v && v.checked_at));
  let state;
  if (!Object.keys(dims).length) state = 'unverified';
  else if (tier.classification === 'Deprecated') state = 'Deprecated';
  else if (staleRequired.length) state = 'stale';
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
    stale: staleRequired.length > 0,
    stale_dimensions: staleRequired,
    latest_evidence: latest,
    label: LABEL,
    message,
    color: color.hex,
    color_name: color.name,
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
  badgeState, renderSvg, endpointJson, slugFor, badgeUrls, snippet, textWidth, escXml,
  COLORS, LABEL, SITE,
};
