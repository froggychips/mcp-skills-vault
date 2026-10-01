'use strict';
/**
 * Lookalike names: a package that is not in the vault but is shaped like one
 * that is.
 *
 * Every other check here asks "is this artifact the one we verified?". None of
 * them asked the question a typosquat is built to slip past: "is this the
 * package you meant?". `mcp-server-memmory` is not in the DB, so the gate never
 * saw it; `audit` filed it under `unknown (informational)`, next to the user's
 * own custom servers. An unvetted server and a server wearing a vetted one's
 * name are not the same finding, and the second one is the attack.
 *
 * Deterministic and offline: the only input is the DB. No popularity data, no
 * registry lookup, no external confusables file — the tables below are the
 * whole of it, so the answer for a given DB never changes.
 *
 * What counts as "shaped like" (strongest first):
 *   homoglyph        Cyrillic/Greek letters, 0/o, 1/l, rn/m, vv/w, fullwidth
 *   separator        mcp_server_memory vs mcp-server-memory (distinct on npm)
 *   scope-typo       @modelcontextprotocl/… vs @modelcontextprotocol/…
 *   scope-dropped    unscoped copy of @official/pkg
 *   scope-added      @someone/pkg-name vs the unscoped pkg-name
 *   foreign-scope    same distinctive name in somebody else's scope/namespace
 *   registry-swap    ghcr.io/o/image vs docker.io/o/image
 *   vault-name-reused  the vault's display name published as a package, when
 *                    the vault's artifact is a different package
 *   doubled-letter / missing-letter / extra-letter / transposition /
 *   substitution     Damerau-Levenshtein 1, with a length-dependent threshold
 *   edit-distance-2  two edits, only for longer names
 *   affix            -mcp, mcp-, -server, -official, -js … added or removed
 *   vault-name-on-other-package  (checkServer only) a config key that is a
 *                    vault name, launching a package that is not that entry's
 *
 * A server *key* gets only the misspelling and homoglyph checks: people name
 * their servers `github` or `memory`, and that is not an attack.
 *
 * The DB's own entries are never flagged: a name that *is* one of the vault's
 * identities is known, full stop. Several legitimate entries do look alike
 * (`mcp-server-kubernetes`, `kubernetes-mcp-server`); that is exactly why the
 * exact-identity short-circuit comes first.
 *
 * API:
 *   identitiesOf(tool)                 -> [{ kind, value }]
 *   buildIndex(tools)                  -> index (reuse across many checks)
 *   checkName(value, kind, index)      -> { candidate, kind, known, lookalike, matches }
 *   checkServer({ name, install_cmd }, index, { dbName }) -> result | null
 *   describe(result)                   -> one-line human message | null
 *   ruleFor(technique)                 -> 'lookalike/<technique>'
 *   subjectFor(result)                 -> lib/finding.cjs `name` subject
 *   toFinding(result, { scope })       -> lib/finding.cjs Finding (no effect)
 *   factsFor(result, { intent, allow }) -> what the `lookalike/*` row reads
 *   packageOf(install_cmd)             -> { kind, value } | null
 *   allowFromArgv(argv)                -> Set of --allow-lookalike names
 *   damerauLevenshtein(a, b)           -> number
 *   skeleton(s)                        -> string (confusables folded)
 *
 * This module observes; it does not decide. Whether a lookalike refuses an
 * install, warns in a scan or is excused by `--allow-lookalike` is the
 * `lookalike/*` row in lib/policy_rules.cjs, reached through `decide()`
 * (docs/adr/0001-findings-and-time.md).
 */

const { npmPkgName, pypiPkgName, dockerImageRef } = require('./install_cmd.cjs');
const { subject: mkSubject, finding } = require('./finding.cjs');

// Characters that render as a Latin letter or digit in common fonts. Compact on
// purpose: the attacks seen in package registries use a handful of Cyrillic and
// Greek letters and the classic digit swaps, not the full Unicode table.
// Uppercase I is folded before lowercasing, because `fiIesystem` lowercases to
// `fiiesystem` and the resemblance to `filesystem` would be lost.
const CONFUSABLES = {
  // Cyrillic
  'а': 'a', 'в': 'b', 'е': 'e', 'ё': 'e', 'к': 'k', 'м': 'm', 'н': 'h', 'о': 'o',
  'р': 'p', 'с': 'c', 'т': 't', 'у': 'y', 'х': 'x', 'ѕ': 's', 'і': 'i', 'ї': 'i',
  'ј': 'j', 'һ': 'h', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w', 'ү': 'y', 'ɡ': 'g', 'ӏ': 'l',
  // Greek
  'α': 'a', 'β': 'b', 'ε': 'e', 'η': 'n', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o',
  'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x', 'ω': 'w',
  // Digits and look-alike Latin
  '0': 'o', '1': 'l', '3': 'e', '5': 's', '|': 'l', 'ı': 'i', 'ł': 'l',
};
// Multi-character shapes: `rn` next to `m` in most sans-serif fonts.
const CONFUSABLE_SEQUENCES = [['rn', 'm'], ['vv', 'w']];

// Pieces a squatter bolts onto a real name. Longest first, so `-mcp-server` is
// removed as one piece rather than leaving `-mcp` behind.
const AFFIX_PREFIXES = ['mcp-server-', 'server-mcp-', 'official-', 'mcp-', 'server-', 'the-'];
const AFFIX_SUFFIXES = [
  '-mcp-server', '-server-mcp', '-official', '-server', '-mcp', '-js', '-ts',
  '-node', '-nodejs', '-py', '-python', '-cli', '-sdk', '-tool', '-tools',
  '-latest', '-dev', '-pro', '-plus', '-v2', '-2',
];

// A core this short carries no identity: `@upstash/mcp-server` and
// `@mapbox/mcp-server` share the base `mcp-server`, and that is not a
// resemblance anyone would be fooled by — the scope is the whole name.
const MIN_CORE = 3;

const CONFIDENCE_RANK = { high: 0, medium: 1 };

// Unscoped npm packages published by the same publisher as an npm scope the
// vault knows. Dropping a scope is the attack `scope-dropped` / `affix`
// describe — unless the unscoped name is that publisher's own package, which
// the registry says nothing about offline: npm does not tie the scope
// `@playwright` to the name `playwright`. Without this, `npx playwright
// run-test-mcp-server` (Microsoft's own package, the documented way to start
// Playwright's test MCP server) was reported as an impersonation of
// `@playwright/mcp` in a public config.
//
// A row is a fact checked by hand against the registry (`npm view <name>
// maintainers` and the publishing repository), not a heuristic: an attacker
// cannot get onto it by choosing a name. Keep it small; add a row only with
// its source.
const PUBLISHER_UNSCOPED = Object.freeze({
  // github.com/microsoft/playwright publishes these from packages/* alongside
  // @playwright/test; @playwright/mcp is github.com/microsoft/playwright-mcp.
  playwright: Object.freeze(['playwright', 'playwright-core', 'playwright-chromium', 'playwright-firefox', 'playwright-webkit']),
  // github.com/supabase/cli publishes the CLI as `supabase`.
  supabase:   Object.freeze(['supabase']),
  // github.com/stripe/stripe-node publishes `stripe`; @stripe is Stripe's scope.
  stripe:     Object.freeze(['stripe']),
  // github.com/eslint/eslint publishes `eslint`; @eslint is the ESLint team's scope.
  eslint:     Object.freeze(['eslint']),
});

/** The npm scopes whose publisher also publishes this unscoped name. */
function publisherScopesOf(name) {
  const n = String(name).toLowerCase();
  return new Set(Object.keys(PUBLISHER_UNSCOPED).filter((scope) => PUBLISHER_UNSCOPED[scope].includes(n)));
}

// ── normalisation ──────────────────────────────────────────────────────────

/** Lowercase, NFKC, and every run of `-`, `_`, `.`, space as one `-` (PEP 503). */
function norm(s) {
  return String(s).normalize('NFKC').toLowerCase().replace(/[-_.\s]+/g, '-').replace(/^-+|-+$/g, '');
}

/** Separators removed entirely. */
function flat(s) {
  return norm(s).replace(/-/g, '');
}

/** Confusables folded, separators removed: two names with one skeleton read the same. */
function skeleton(s) {
  let out = '';
  for (const ch of String(s).normalize('NFKC').replace(/I/g, 'l')) {
    const lower = ch.toLowerCase();
    out += CONFUSABLES[lower] !== undefined ? CONFUSABLES[lower] : lower;
  }
  out = out.replace(/[-_.\s]+/g, '');
  for (const [from, to] of CONFUSABLE_SEQUENCES) out = out.split(from).join(to);
  return out;
}

/**
 * Split `@scope/name` (npm) and `registry/namespace/name` (OCI) into parts.
 * An OCI name with no registry host is Docker Hub, and `library/` is its
 * implicit namespace, so `docker.io/library/x` and `x` are one image.
 */
function splitName(value, kind) {
  let v = String(value).trim();
  if (kind === 'oci') {
    v = v.replace(/@sha256:[0-9a-f]+$/i, '').replace(/:[^:/]+$/, '');
    const segs = v.split('/');
    let registry = 'docker.io';
    if (segs.length > 1 && (/[.:]/.test(segs[0]) || segs[0] === 'localhost')) registry = segs.shift().toLowerCase();
    if (registry === 'index.docker.io') registry = 'docker.io';
    if (registry === 'docker.io' && segs[0] === 'library' && segs.length > 1) segs.shift();
    const base = segs.pop();
    return { oci: true, registry, scope: segs.length ? segs.join('/') : null, base };
  }
  const m = v.match(/^@([^/]+)\/(.+)$/);
  return m ? { oci: false, registry: null, scope: m[1], base: m[2] } : { oci: false, registry: null, scope: null, base: v };
}

function fullName({ oci, registry, scope, base }) {
  if (oci) return [registry === 'docker.io' ? null : registry, scope, base].filter(Boolean).join('/');
  return scope ? `@${scope}/${base}` : base;
}

/** Strip known affixes until nothing more comes off. */
function core(base) {
  let s = norm(base);
  for (let changed = true; changed;) {
    changed = false;
    for (const p of AFFIX_PREFIXES) {
      if (s.startsWith(p) && s.length > p.length) { s = s.slice(p.length); changed = true; }
    }
    for (const x of AFFIX_SUFFIXES) {
      if (s.endsWith(x) && s.length > x.length) { s = s.slice(0, -x.length); changed = true; }
    }
  }
  // `mcp` and `server` alone are what is left of a name that was all affix.
  if (s === 'mcp' || s === 'server' || s === 'mcp-server') return '';
  return s;
}

function isGeneric(base) {
  return flat(core(base)).length < MIN_CORE;
}

/**
 * How many edits a name of this length may be from a real one before the
 * resemblance stops meaning anything. Short names get none: `git` and `gh`
 * are one edit apart and unrelated.
 */
function threshold(length) {
  if (length <= 4) return 0;
  if (length <= 8) return 1;
  return 2;
}

// ── distance ───────────────────────────────────────────────────────────────

/** Optimal-string-alignment Damerau-Levenshtein: insert, delete, substitute, swap adjacent. */
function damerauLevenshtein(a, b) {
  a = String(a); b = String(b);
  const n = a.length, m = b.length;
  if (!n) return m;
  if (!m) return n;
  const d = Array.from({ length: n + 1 }, (_, i) => {
    const row = new Array(m + 1).fill(0);
    row[0] = i;
    return row;
  });
  for (let j = 0; j <= m; j++) d[0][j] = j;
  for (let i = 1; i <= n; i++) {
    for (let j = 1; j <= m; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      }
    }
  }
  return d[n][m];
}

/** Name the single edit that turns `target` into `cand`. */
function oneEditTechnique(cand, target) {
  if (cand.length === target.length + 1) {
    for (let i = 0; i < cand.length; i++) {
      if (cand.slice(0, i) + cand.slice(i + 1) === target) {
        return (cand[i] === cand[i - 1] || cand[i] === cand[i + 1]) ? 'doubled-letter' : 'extra-letter';
      }
    }
    return 'extra-letter';
  }
  if (cand.length + 1 === target.length) return 'missing-letter';
  for (let i = 0; i < cand.length - 1; i++) {
    if (cand[i] !== target[i]) {
      return cand[i] === target[i + 1] && cand[i + 1] === target[i]
        && cand.slice(i + 2) === target.slice(i + 2) ? 'transposition' : 'substitution';
    }
  }
  return 'substitution';
}

// ── the DB side ────────────────────────────────────────────────────────────

/**
 * Everything a vault entry is known by: its display name, and the package or
 * image its launch command names. A git-source install has no package, only
 * the name.
 */
function identitiesOf(tool) {
  const out = [];
  if (!tool || typeof tool.name !== 'string') return out;
  out.push({ kind: 'name', value: tool.name });
  const cmd = typeof tool.install_cmd === 'string' ? tool.install_cmd.trim() : '';
  const npm = /^npx\s/.test(cmd) ? npmPkgName(cmd) : null;
  const pypi = /^uvx\s/.test(cmd) ? pypiPkgName(cmd) : null;
  const ref = /^docker\s+run/.test(cmd) ? dockerImageRef(cmd) : null;
  if (npm) out.push({ kind: 'npm', value: npm });
  if (pypi) out.push({ kind: 'pypi', value: pypi });
  if (ref) out.push({ kind: 'oci', value: ref });
  return out;
}

/** The form under which two values of this kind are the *same* thing. */
function sameKey(value, kind) {
  const parts = splitName(value, kind);
  const v = fullName(parts);
  // PyPI: PEP 503. A server key: naming is free, so case and separators are
  // cosmetic. npm and OCI names are compared as the registry compares them.
  if (kind === 'pypi' || kind === 'name') return norm(v);
  return v.toLowerCase();
}

function buildIndex(tools) {
  const identities = [];
  for (const tool of Array.isArray(tools) ? tools : []) {
    for (const id of identitiesOf(tool)) {
      const parts = splitName(id.value, id.kind);
      identities.push({
        ...parts,
        db_name: tool.name,
        kind:    id.kind,
        value:   id.value,
        display: fullName(parts),
        same:    sameKey(id.value, id.kind),
        loose:   norm(fullName(parts)),
      });
    }
  }
  const packageOf = new Map();
  for (const id of identities) {
    if (id.kind !== 'name' && !packageOf.has(id.db_name)) packageOf.set(id.db_name, `${id.kind} ${id.display}`);
  }
  return { identities, packageOf };
}

// ── comparison ─────────────────────────────────────────────────────────────

/**
 * Edits that fit the name. When both names carry the same affixes
 * (`lsp-mcp-server`, `fsb-mcp-server`) every edit is in the core, so the core's
 * length is what decides: two edits in a three-letter core is a different
 * word. Otherwise the whole name's length does.
 */
function fuzzyDistance(candBase, targetBase) {
  const d = damerauLevenshtein(skeleton(candBase), skeleton(targetBase));
  if (d === 0) return null;
  const cc = core(candBase), tc = core(targetBase);
  const shell = (base, c) => (c ? norm(base).replace(c, '\u0000') : norm(base));
  const sameShell = cc && tc && shell(candBase, cc) === shell(targetBase, tc);
  const room = sameShell ? threshold(flat(tc).length) : threshold(flat(targetBase).length);
  return d <= room ? d : null;
}

/**
 * One candidate against one vault identity. Returns a match or null.
 *
 * A server key (`kind: 'name'`) gets the narrow version: people nickname their
 * servers — `github`, `filesystem`, `memory` — so a key that is a vault name
 * minus its affixes, or without its scope, is how configs are written. What a
 * key cannot plausibly be by accident is a misspelling or a homoglyph.
 */
function compare(cand, candKind, t) {
  const cFull = fullName(cand), tFull = t.display;
  const isKey = candKind === 'name';

  // A package named exactly like a vault entry's *display name*, when that
  // entry's artifact is some other package.
  if (!isKey && t.kind === 'name' && cFull.toLowerCase() === tFull.toLowerCase()) {
    return { technique: 'vault-name-reused', confidence: 'high', distance: 0 };
  }
  if (flat(cFull) === flat(tFull)) {
    return cFull.toLowerCase() === tFull.toLowerCase()
      ? null  // only case differs; not a resemblance worth a refusal
      : { technique: 'separator', confidence: 'high', distance: 0 };
  }
  if (skeleton(cFull) === skeleton(tFull)) {
    return { technique: 'homoglyph', confidence: 'high', distance: 0 };
  }

  const cs = cand.scope ? norm(cand.scope) : null;
  const ts = t.scope ? norm(t.scope) : null;
  const cb = skeleton(cand.base), tb = skeleton(t.base);
  const scopeLike = (a, b) => Boolean(a && b && a !== b
    && (skeleton(a) === skeleton(b) || damerauLevenshtein(skeleton(a), skeleton(b)) <= threshold(b.length)));

  // The same image path pulled from another registry: ghcr.io/o/r vs docker.io/o/r.
  if (cand.oci && t.oci && cs === ts && cb === tb && cand.registry !== t.registry) {
    return { technique: 'registry-swap', confidence: 'high', distance: 0 };
  }

  if (cs !== ts && cb === tb) {
    if (scopeLike(cs, ts)) return { technique: 'scope-typo', confidence: 'high', distance: damerauLevenshtein(skeleton(cs), skeleton(ts)) };
    if (isKey || isGeneric(t.base)) return null;
    if (!cs) return { technique: 'scope-dropped', confidence: 'high', distance: 0 };
    if (!ts) return { technique: 'scope-added', confidence: 'medium', distance: 0 };
    return { technique: 'foreign-scope', confidence: 'medium', distance: 0 };
  }

  // Beyond this point the scope has to be the same one, or a typo of it: a
  // fuzzy base in an unrelated scope is two coincidences, not one attack.
  const sameScope = cs === ts;
  if (!sameScope && !scopeLike(cs, ts)) return null;
  const scopePart = sameScope ? '' : 'scope-typo+';

  if (!isGeneric(t.base)) {
    const d = fuzzyDistance(cand.base, t.base);
    if (d) {
      const technique = d === 1 ? oneEditTechnique(flat(cand.base), flat(t.base)) : 'edit-distance-2';
      return { technique: scopePart + technique, confidence: d === 1 ? 'high' : 'medium', distance: d };
    }
  }

  if (isKey) return null;
  const cc = core(cand.base), tc = core(t.base);
  if (cc && tc && flat(cc).length >= MIN_CORE && skeleton(cc) === skeleton(tc) && norm(cand.base) !== norm(t.base)) {
    return { technique: `${scopePart}affix`, confidence: 'medium', distance: 0 };
  }
  return null;
}

function detailFor(technique, cand, target, pkg) {
  if (technique === 'vault-name-reused') {
    return `${cand} is the vault's name for ${pkg || 'another package'}, not this package`;
  }
  const plain = technique.replace(/^scope-typo\+/, '');
  const words = {
    'homoglyph':         'look-alike characters',
    'separator':         'different separators',
    'scope-typo':        'misspelled scope',
    'scope-dropped':     'the same name without its scope',
    'scope-added':       'the same name under a scope',
    'foreign-scope':     'the same name in another scope or namespace',
    'registry-swap':     'the same image path on another registry',
    'vault-name-reused': "the vault's entry name used as a package name",
    'doubled-letter':    'a doubled letter',
    'missing-letter':    'a missing letter',
    'extra-letter':      'an extra letter',
    'transposition':     'two letters swapped',
    'substitution':      'one letter replaced',
    'edit-distance-2':   'two letters changed',
    'affix':             'an added or removed prefix/suffix',
  };
  const prefix = technique.startsWith('scope-typo+') ? 'misspelled scope and ' : '';
  return `${prefix}${words[plain] || plain}: ${cand} vs ${target}`;
}

/**
 * Is `value` one of the vault's names, a lookalike of one, or neither?
 *
 * `kind` is what the value is: 'npm', 'pypi', 'oci', or 'name' for a server
 * key / vault name typed by a person. `known` names the entry when the value
 * *is* one of its identities; `matches` is empty then, always.
 */
function checkName(value, kind, index, { limit = 3 } = {}) {
  const result = { candidate: String(value), kind, known: null, lookalike: false, matches: [] };
  if (!value || !index) return result;
  const key = sameKey(value, kind);
  const exact = index.identities.find((t) => {
    if (kind === 'name') return t.loose === key || t.same === key;
    // A package is known only as a package of the same ecosystem. The display
    // name matching is not enough — that is the `vault-name-reused` case.
    return t.kind === kind && t.same === key;
  });
  if (exact) { result.known = exact.db_name; return result; }

  const cand = splitName(value, kind);
  // A publisher's own unscoped package (`playwright`, next to the vault's
  // `@playwright/mcp`) is a known, legitimate registry name: it resembles that
  // publisher's entries by construction, and it cannot be a squat of anything
  // else, because the name is taken — by the publisher. Not a lookalike.
  if (kind === 'npm' && !cand.scope && publisherScopesOf(cand.base).size) return result;
  const best = new Map();
  for (const t of index.identities) {
    const m = compare(cand, kind, t);
    if (!m) continue;
    const prev = best.get(t.db_name);
    if (prev && (CONFIDENCE_RANK[prev.confidence] < CONFIDENCE_RANK[m.confidence]
      || (prev.confidence === m.confidence && prev.distance <= m.distance))) continue;
    best.set(t.db_name, {
      db_name:     t.db_name,
      target:      t.display,
      target_kind: t.kind,
      package:     index.packageOf.get(t.db_name) || null,
      technique:   m.technique,
      confidence:  m.confidence,
      distance:    m.distance,
      detail:      detailFor(m.technique, fullName(cand), t.display, index.packageOf.get(t.db_name)),
    });
  }
  result.matches = [...best.values()]
    .sort((a, b) => CONFIDENCE_RANK[a.confidence] - CONFIDENCE_RANK[b.confidence]
      || a.distance - b.distance
      || (a.db_name < b.db_name ? -1 : a.db_name > b.db_name ? 1 : 0))
    .slice(0, limit);
  result.lookalike = result.matches.length > 0;
  return result;
}

/** The package a launch command names, as { kind, value }, or null. */
function packageOf(installCmd) {
  // The shared parser reads npx options in any order (`--yes`, `-p pkg bin`),
  // so a vault-named key launching `npx --yes other` is read, not skipped.
  const cmd = typeof installCmd === 'string' ? installCmd.trim() : '';
  const kind = /^npx\s/.test(cmd) ? 'npm' : (/^uvx\s/.test(cmd) ? 'pypi' : (/^docker\s+run/.test(cmd) ? 'oci' : null));
  const value = kind === 'npm' ? npmPkgName(cmd)
    : kind === 'pypi' ? pypiPkgName(cmd)
    : kind === 'oci' ? dockerImageRef(cmd)
    : null;
  return value ? { kind, value } : null;
}

/**
 * Check one configured server: `{ name, install_cmd }`, where `name` is the
 * key in the host config. Returns the lookalike result, or null.
 *
 * The package is what runs, so it is checked first; a vault package under any
 * key is fine. The key is checked only when the package told us nothing.
 *
 * `dbName` is the vault entry the key already matched by name, if any; a key
 * that is a vault name up to case and separators (`MCP_Server_Memory`) is
 * found here too, because it reads as that entry just as well. A key that is
 * a vault name launching a package that is not that entry's is the sharpest
 * form of the attack — the config reads as the vetted server — and it is
 * reported even when the package resembles nothing, or cannot be read at all
 * (`npx -y --registry=… pkg`): an unreadable launch is not the entry's.
 *
 * Names the user has said are theirs (`--allow-lookalike`) are not looked at
 * here: the match is still a match, and excusing it is a policy input
 * (`factsFor(…, { allow })`), applied by the `lookalike/*` row.
 */
function checkServer(server, index, { dbName = null } = {}) {
  if (!server || !index) return null;
  const done = (r) => ({ ...r, server: server.name || null });
  let keyEntry = dbName;
  if (!keyEntry && server.name) {
    const k = checkName(server.name, 'name', index);
    if (k.known) keyEntry = k.known;
  }
  const impersonation = (r, launched) => {
    const target = index.identities.find((t) => t.db_name === keyEntry && t.kind !== 'name');
    if (!target) return null;
    return done({
      ...r,
      lookalike: true,
      matches: [{
        db_name:     keyEntry,
        target:      target.display,
        target_kind: target.kind,
        package:     index.packageOf.get(keyEntry) || null,
        technique:   'vault-name-on-other-package',
        confidence:  'high',
        distance:    null,
        detail:      `configured as "${server.name}", the vault's name for ${target.display}, but launches ${launched}`,
      }],
    });
  };
  const cmd = typeof server.install_cmd === 'string' ? server.install_cmd.trim() : '';
  const pkg = packageOf(cmd);
  if (pkg) {
    const r = checkName(pkg.value, pkg.kind, index);
    if (r.lookalike) return done(r);
    if (r.known && (!keyEntry || r.known === keyEntry)) return null;
    if (keyEntry) {
      const hit = impersonation(r, pkg.value);
      if (hit) return hit;
    }
    if (r.known) return null;
  } else if (keyEntry && /^(npx|uvx|docker)\s/.test(cmd)) {
    return impersonation({ candidate: String(server.name), kind: 'name', known: null, lookalike: false, matches: [] },
      `a command whose package cannot be read (${cmd})`);
  }
  if (!keyEntry && server.name) {
    const r = checkName(server.name, 'name', index);
    if (r.lookalike) return done(r);
  }
  return null;
}

/** `--allow-lookalike <name>` (repeatable, or comma-separated) -> Set. */
function allowFromArgv(argv) {
  const out = new Set();
  const add = (list) => { for (const v of String(list).split(',')) if (v.trim()) out.add(v.trim()); };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--allow-lookalike' && argv[i + 1] && !argv[i + 1].startsWith('--')) add(argv[++i]);
    else if (argv[i].startsWith('--allow-lookalike=')) add(argv[i].slice('--allow-lookalike='.length));
  }
  return out;
}

function describe(result) {
  if (!result || !result.lookalike) return null;
  const top = result.matches[0];
  const others = result.matches.slice(1).map((m) => m.db_name);
  if (top.technique === 'vault-name-on-other-package') {
    return `${top.detail[0].toUpperCase()}${top.detail.slice(1)}. Likely an impersonation of ${top.db_name}.`;
  }
  const subject = result.kind === 'name' ? `"${result.candidate}"` : `${result.kind} package ${result.candidate}`;
  return `${subject} is not in the vault but looks like ${top.db_name}`
    + `${top.package ? ` (${top.package})` : ''} — ${top.detail}. Likely an impersonation of ${top.db_name}.`
    + `${others.length ? ` Also resembles: ${others.join(', ')}.` : ''}`;
}

// ── as findings (docs/adr/0001) ────────────────────────────────────────────

/**
 * The rule a technique is reported under. A compound (`scope-typo+substitution`)
 * is reported as its scope typo: the scope is the part of an npm name that says
 * who published it, and the detail keeps the rest.
 */
function ruleFor(technique) {
  const t = String(technique || 'unknown');
  return `lookalike/${t.startsWith('scope-typo+') ? 'scope-typo' : t}`;
}

/**
 * A lookalike is about a *name*: there is no artifact of ours behind it. The
 * ecosystem is the registry the name was read as; a server key has none.
 */
function subjectFor(result) {
  return mkSubject.name({ name: result.candidate, ecosystem: result.kind === 'name' ? null : result.kind });
}

/**
 * One finding per candidate, for its strongest match — the other matches are
 * in the message. Severity `low` on purpose, like a dependency hook
 * (lib/legacy_tags.cjs): a resemblance is not a refusal by itself, and the
 * generic `finding/severity` row must not turn it into one. What it means is
 * the `lookalike/*` row's call, with the context this module does not have —
 * whether a person asked for this name, or a config merely contains it, and
 * whether the user has vouched for it.
 */
function toFinding(result, { scope = null } = {}) {
  if (!result || !result.lookalike || !result.matches.length) return null;
  const top = result.matches[0];
  return finding({
    rule: ruleFor(top.technique),
    subject: subjectFor(result),
    scope,
    severity: 'low',
    confidence: top.confidence === 'medium' ? 'medium' : 'high',
    state: 'observed',
    message: describe(result),
  });
}

/**
 * What the `lookalike/*` row reads that is not a finding:
 *   intent  'requested'  a person asked for this name (install, explain)
 *           'configured' a host config launches it (audit, verify --installed)
 *   names   what the user may have vouched for: the package and the server key
 *   allow   the `--allow-lookalike` names, as given
 *   matches the vault entries it resembles — for a reader of the document
 */
function factsFor(result, { intent = 'configured', allow = [] } = {}) {
  const names = [...new Set([result.candidate, result.server].filter(Boolean).map(String))].sort();
  return {
    lookalike: {
      intent,
      names,
      allow: [...new Set([...(allow || [])].map(String))].sort(),
      matches: (result.matches || []).map((m) => ({ db_name: m.db_name, technique: m.technique, confidence: m.confidence, package: m.package || null })),
    },
  };
}

module.exports = {
  PUBLISHER_UNSCOPED,
  publisherScopesOf,
  ruleFor,
  subjectFor,
  toFinding,
  factsFor,
  identitiesOf,
  buildIndex,
  checkName,
  checkServer,
  packageOf,
  allowFromArgv,
  describe,
  damerauLevenshtein,
  skeleton,
  core,
  threshold,
};
