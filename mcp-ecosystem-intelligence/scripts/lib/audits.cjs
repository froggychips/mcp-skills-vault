'use strict';
/**
 * Audits: "I read this exact artifact and it meets this bar", written down,
 * signed, and exchangeable — the cargo-vet model, for MCP servers.
 *
 * https://mozilla.github.io/cargo-vet/importing-audits.html is the reference
 * and most of it carries over unchanged:
 *
 *   - An audit names who, what (ecosystem, package, version), a criterion and a
 *     date. Here it also names the artifact's *integrity*: an audit of other
 *     bytes published under the same version string is not an audit of these.
 *   - Imports are declared in a file, fetched by an explicit command, and the
 *     result is kept locally (cargo-vet's `imports.lock`). Everything after the
 *     fetch is offline and deterministic.
 *   - Imports are **not transitive**: "you can't directly import someone else's
 *     list of imports … which keeps trust relationships direct and easy to
 *     reason about." An export carries its author's own audits and nothing
 *     else; a bundle that tries to carry more is refused, not followed.
 *   - You say which criteria you accept from each source.
 *
 * What cargo-vet does not have and this adds: a signature. An import names the
 * source's Ed25519 public key, and a bundle that does not verify under it
 * contributes nothing. The lock keeps the verified bundle and its hash, and is
 * re-verified on every read against the key in the *config*, so editing the
 * lock cannot swap a key or a record in.
 *
 * What an audit is not: trust. An audit is an *Observation* with its source
 * (`audit:local`, or `audit:<key id>` for an import) and an `audits/recorded`
 * finding that rests on it (docs/adr/0001, "#121"), shown in `explain`'s
 * trace. It does not enter `trust_evidence.dimensions`, neither `deriveTrust`
 * nor `trustScore` reads it, and the `audits/recorded` row can only say
 * `allow` — worst effect wins, so it never lifts a decision. Someone else
 * having looked at a package does not make its hash match or its advisories
 * go away.
 *
 * The import check (`audits fetch` / `audits check`) is findings too, one set
 * per configured source (a `name` subject, `audit-source:<name>`):
 * `audits/import-verified`, `audits/import-unverified`, `audits/import-not-fetched`,
 * decided by the `audits/import` row.
 *
 * Files, in the project (`--cwd`), beside `.mcp-vault.policy.json`:
 *
 *   .mcp-vault.audits.json        your audits           { "audits": [ … ] }
 *   .mcp-vault.imports.json       what you import       { "sources": { name: { url | path, public_key, criteria } } }
 *   .mcp-vault.imports.lock.json  what `fetch` verified { "sources": { name: { location, key_id, sha256, fetched_at, bundle } } }
 *
 * Audit record (every field required but `notes`; any other field is refused):
 *   { who, ecosystem: npm|pypi|oci, package, version, integrity, criteria, date: YYYY-MM-DD, notes? }
 *
 * Export bundle:
 *   { "$schema": "mcp-vault/audit-export@1", "payload": { "audits": [ … ] }, "signature": <envelope> }
 *   The envelope (lib/signing.cjs) covers the canonical payload.
 */

const fs   = require('fs');
const path = require('path');
const { canonicalBytes, sha256Hex, signCanonical, verifyCanonical, keyIdFor } = require('./signing.cjs');
const { toTypedEntry } = require('./entry_model.cjs');
const { requireAsOf } = require('./clock.cjs');
const F = require('./finding.cjs');

const AUDITS_FILE  = '.mcp-vault.audits.json';
const IMPORTS_FILE = '.mcp-vault.imports.json';
const LOCK_FILE    = '.mcp-vault.imports.lock.json';
const EXPORT_SCHEMA = 'mcp-vault/audit-export@1';
const EXPORT_ARTIFACT = 'mcp-vault-audits';

// Built-in criteria, as in cargo-vet. `implies` is what lets a source trusted
// only for the weaker bar still contribute a stronger audit — as the weaker one.
const CRITERIA = {
  'safe-to-run':    { implies: [], description: 'starting this server on a developer machine does nothing it does not advertise' },
  'safe-to-deploy': { implies: ['safe-to-run'], description: 'fit to run with production credentials and data' },
};

const AUDIT_FIELDS = new Set(['who', 'ecosystem', 'package', 'version', 'integrity', 'criteria', 'date', 'notes']);
const ECOSYSTEMS = new Set(['npm', 'pypi', 'oci']);

function validateAudit(a) {
  const errors = [];
  if (!a || typeof a !== 'object' || Array.isArray(a)) return { ok: false, errors: ['an audit must be an object'] };
  for (const k of Object.keys(a)) {
    // Refused rather than ignored: a field this format does not have is most
    // likely an attempt to say something it cannot — `imported_from`,
    // `via`, a nested list of somebody else's audits.
    if (!AUDIT_FIELDS.has(k)) errors.push(`unknown field "${k}"`);
  }
  for (const k of ['who', 'package', 'version', 'integrity', 'criteria']) {
    if (typeof a[k] !== 'string' || !a[k].trim()) errors.push(`"${k}" is required`);
  }
  if (!ECOSYSTEMS.has(a.ecosystem)) errors.push(`"ecosystem" must be one of ${[...ECOSYSTEMS].join(' | ')}`);
  if (typeof a.date !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(a.date)) errors.push('"date" must be YYYY-MM-DD');
  if (a.notes !== undefined && typeof a.notes !== 'string') errors.push('"notes" must be a string');
  return { ok: errors.length === 0, errors };
}

const auditKey = (a) => [a.ecosystem, a.package, a.version, a.integrity, a.criteria, a.who, a.date].join('\u0000');

/** Deterministic order, so an export of the same audits is the same bytes. */
function sortAudits(list) {
  return [...list].sort((x, y) => (auditKey(x) < auditKey(y) ? -1 : auditKey(x) > auditKey(y) ? 1 : 0));
}

/**
 * What an audit of this DB entry would have to name. `null` when there is no
 * pinned artifact to audit (a git source install, an image by tag): an audit
 * of "whatever that resolves to today" is not an audit.
 */
function subjectOf(tool) {
  const typed = toTypedEntry(tool);
  const art = typed && typed.artifact;
  if (!art) return null;
  if (art.ecosystem === 'npm' || art.ecosystem === 'pypi') {
    if (!art.package || !art.version || !art.integrity) return null;
    return { ecosystem: art.ecosystem, package: art.package, version: art.version, integrity: art.integrity };
  }
  if (art.ecosystem === 'oci') {
    if (!art.image || !art.digest) return null;
    return { ecosystem: 'oci', package: art.image, version: art.digest, integrity: art.digest };
  }
  return null;
}

/** Same package, same version, same bytes. All three, or it is not this artifact. */
function auditMatches(audit, subject) {
  return Boolean(subject)
    && audit.ecosystem === subject.ecosystem
    && audit.package === subject.package
    && audit.version === subject.version
    && audit.integrity === subject.integrity;
}

function readJsonFile(file) {
  try { return { ok: true, value: JSON.parse(fs.readFileSync(file, 'utf8')) }; }
  catch (e) { return { ok: false, error: e.message }; }
}

function writeJsonFile(file, value) {
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

// ── your own audits ──────────────────────────────────────────────────────────

function readLocalAudits(cwd) {
  const file = path.join(cwd, AUDITS_FILE);
  if (!fs.existsSync(file)) return { ok: true, path: file, found: false, audits: [], errors: [] };
  const r = readJsonFile(file);
  if (!r.ok) return { ok: false, path: file, found: true, audits: [], errors: [`could not read ${file}: ${r.error}`] };
  const list = r.value && Array.isArray(r.value.audits) ? r.value.audits : null;
  if (!list) return { ok: false, path: file, found: true, audits: [], errors: [`${file}: must be an object with an "audits" array`] };
  const audits = [];
  const errors = [];
  list.forEach((a, i) => {
    const v = validateAudit(a);
    if (v.ok) audits.push(a); else errors.push(`audit #${i}: ${v.errors.join('; ')}`);
  });
  return { ok: errors.length === 0, path: file, found: true, audits, errors };
}

function addLocalAudit(cwd, audit) {
  const v = validateAudit(audit);
  if (!v.ok) throw new Error(v.errors.join('; '));
  const current = readLocalAudits(cwd);
  if (!current.ok) throw new Error(current.errors.join('; '));
  const exists = current.audits.some((a) => auditKey(a) === auditKey(audit));
  const audits = exists ? current.audits : sortAudits([...current.audits, audit]);
  writeJsonFile(current.path, { $schema: 'mcp-vault/audits@1', audits });
  return { path: current.path, added: !exists };
}

// ── export ───────────────────────────────────────────────────────────────────

/**
 * A signed bundle of *your* audits. Only local audits are ever exported: the
 * export is what makes imports non-transitive from this side.
 */
function exportBundle(audits, { privateKeyPem, now } = {}) {
  for (const [i, a] of audits.entries()) {
    const v = validateAudit(a);
    if (!v.ok) throw new Error(`audit #${i}: ${v.errors.join('; ')}`);
  }
  const payload = { audits: sortAudits(audits) };
  const signature = signCanonical(canonicalBytes(payload), { privateKeyPem, artifact: EXPORT_ARTIFACT, now });
  return { $schema: EXPORT_SCHEMA, payload, signature };
}

/**
 * Verify a bundle under one source's public key. The whole bundle fails on a
 * bad signature or an unexpected shape; a single malformed record inside an
 * otherwise good bundle is dropped and reported.
 */
function verifyBundle(bundle, { publicKey }) {
  const fail = (code, error) => ({ ok: false, code, error, audits: [], rejected: [] });
  if (!bundle || typeof bundle !== 'object' || bundle.$schema !== EXPORT_SCHEMA) return fail('malformed', `not an ${EXPORT_SCHEMA} document`);
  const payload = bundle.payload;
  if (!payload || typeof payload !== 'object' || !Array.isArray(payload.audits)) return fail('malformed', 'payload has no "audits" array');
  const extra = Object.keys(payload).filter((k) => k !== 'audits');
  if (extra.length) {
    // Most likely `imports`. Following it would make trust transitive, and
    // ignoring it silently would hide that someone tried.
    return fail('transitive', `payload carries ${extra.map((k) => `"${k}"`).join(', ')}; a bundle may carry its author's audits and nothing else`);
  }
  let keyId;
  try { keyId = keyIdFor(publicKey); } catch (e) { return fail('malformed', `public key: ${e.message}`); }
  const keys = [{ key_id: keyId, public_key: publicKey, revoked: false, valid_from: null, valid_until: null }];
  const check = verifyCanonical(canonicalBytes(payload), bundle.signature, keys, { artifact: EXPORT_ARTIFACT });
  if (!check.ok) return { ...fail(check.code, check.error) };
  const audits = [];
  const rejected = [];
  payload.audits.forEach((a, i) => {
    const v = validateAudit(a);
    if (v.ok) audits.push(a); else rejected.push({ index: i, reason: v.errors.join('; ') });
  });
  return { ok: true, code: 'verified', key_id: keyId, signed_at: check.signed_at, audits, rejected };
}

// ── imports ──────────────────────────────────────────────────────────────────

const SOURCE_KEYS = new Set(['url', 'path', 'public_key', 'criteria', 'comment']);

function readImportsConfig(cwd) {
  const file = path.join(cwd, IMPORTS_FILE);
  if (!fs.existsSync(file)) return { ok: true, path: file, found: false, sources: {}, errors: [] };
  const r = readJsonFile(file);
  if (!r.ok) return { ok: false, path: file, found: true, sources: {}, errors: [`could not read ${file}: ${r.error}`] };
  const raw = r.value && r.value.sources;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { ok: false, path: file, found: true, sources: {}, errors: [`${file}: must be an object with a "sources" object`] };
  }
  const sources = {};
  const errors = [];
  for (const [name, s] of Object.entries(raw)) {
    const err = (m) => errors.push(`source "${name}": ${m}`);
    if (!s || typeof s !== 'object') { err('must be an object'); continue; }
    const unknown = Object.keys(s).filter((k) => !SOURCE_KEYS.has(k));
    if (unknown.length) { err(`unknown key ${unknown.map((k) => `"${k}"`).join(', ')}`); continue; }
    if (Boolean(s.url) === Boolean(s.path)) { err('give exactly one of "url" or "path"'); continue; }
    if (s.url && !/^https:\/\//.test(s.url)) { err('"url" must be https://'); continue; }
    let keyId;
    try { keyId = keyIdFor(s.public_key); } catch (e) { err(`"public_key": ${e.message}`); continue; }
    if (!Array.isArray(s.criteria) || !s.criteria.length || !s.criteria.every((c) => typeof c === 'string' && c)) {
      err('"criteria" must be a non-empty array — which of their criteria you accept'); continue;
    }
    sources[name] = {
      name,
      // `spec` is what the config says, and what the lock records; `location`
      // is where that resolves on this machine.
      spec: s.url || s.path,
      location: s.url || path.resolve(path.dirname(file), s.path),
      kind: s.url ? 'url' : 'path',
      public_key: s.public_key,
      key_id: keyId,
      criteria: [...new Set(s.criteria)].sort(),
    };
  }
  return { ok: errors.length === 0, path: file, found: true, sources, errors };
}

/** The criteria of `audit` this source is trusted for, after implication. */
function acceptedCriteria(criterion, trusted) {
  const reach = new Set([criterion]);
  const walk = (c) => { for (const i of (CRITERIA[c] && CRITERIA[c].implies) || []) { reach.add(i); walk(i); } };
  walk(criterion);
  return [...reach].filter((c) => trusted.includes(c)).sort();
}

/**
 * Fetch every configured source, verify it, and return the lock to write.
 * All or nothing: a source that fails leaves the lock as it was, so a
 * half-updated lock never exists.
 *
 * `fetchText(url)` and `readText(path)` are injected so this is testable
 * without a network; the only URLs ever requested are the configured ones.
 */
async function fetchImports(config, { fetchText, readText = (p) => fs.readFileSync(p, 'utf8'), now } = {}) {
  requireAsOf(now, 'fetchImports');
  const lock = { $schema: 'mcp-vault/imports-lock@1', sources: {} };
  const report = [];
  let failed = false;
  for (const name of Object.keys(config.sources).sort()) {
    const src = config.sources[name];
    let bundle;
    try {
      const text = src.kind === 'url' ? await fetchText(src.location) : readText(src.location);
      bundle = JSON.parse(text);
    } catch (e) {
      failed = true;
      report.push({ source: name, ok: false, code: 'unreachable', error: e.message });
      continue;
    }
    const v = verifyBundle(bundle, { publicKey: src.public_key });
    if (!v.ok) {
      failed = true;
      report.push({ source: name, ok: false, code: v.code, error: v.error });
      continue;
    }
    lock.sources[name] = {
      location:   src.spec,
      key_id:     v.key_id,
      sha256:     sha256Hex(canonicalBytes(bundle)),
      fetched_at: new Date(now).toISOString(),
      bundle,
    };
    report.push({ source: name, ok: true, key_id: v.key_id, audits: v.audits.length, rejected: v.rejected });
  }
  return { ok: !failed, lock, report };
}

function readLock(cwd) {
  const file = path.join(cwd, LOCK_FILE);
  if (!fs.existsSync(file)) return { ok: true, path: file, found: false, lock: { sources: {} } };
  const r = readJsonFile(file);
  if (!r.ok || !r.value || typeof r.value.sources !== 'object') {
    return { ok: false, path: file, found: true, lock: { sources: {} }, error: r.error || 'no "sources" object' };
  }
  return { ok: true, path: file, found: true, lock: r.value };
}

function writeLock(cwd, lock) {
  const file = path.join(cwd, LOCK_FILE);
  writeJsonFile(file, lock);
  return file;
}

/**
 * The imported audits in force, offline, from the config and the lock.
 *
 * Every source is re-verified on every read against the key in the config —
 * not the key id in the lock — so a lock edited by hand, or left over from a
 * config that has since changed, contributes nothing and says why.
 */
function loadImportedAudits(cwd, { config = readImportsConfig(cwd), lockRead = readLock(cwd) } = {}) {
  const audits = [];
  const errors = [];
  const ignored = [];
  if (!config.ok) errors.push(...config.errors.map((e) => ({ source: null, code: 'config', error: e })));
  if (!lockRead.ok) errors.push({ source: null, code: 'lock-unreadable', error: `${lockRead.path}: ${lockRead.error}` });
  const locked = (lockRead.lock && lockRead.lock.sources) || {};

  for (const name of Object.keys(config.sources).sort()) {
    const src = config.sources[name];
    const entry = locked[name];
    const err = (code, error) => errors.push({ source: name, code, error });
    if (!entry) { err('not-fetched', 'configured but never fetched — run `mcp-vault audits fetch`'); continue; }
    if (entry.location !== src.spec) {
      err('stale-lock', `the lock holds ${entry.location}, the config names ${src.spec} — run \`mcp-vault audits fetch\``); continue;
    }
    if (!entry.bundle || sha256Hex(canonicalBytes(entry.bundle)) !== entry.sha256) {
      err('lock-tampered', 'the locked bundle does not match its recorded sha256'); continue;
    }
    const v = verifyBundle(entry.bundle, { publicKey: src.public_key });
    if (!v.ok) { err(v.code, v.error); continue; }
    for (const r of v.rejected) ignored.push({ source: name, reason: `record #${r.index}: ${r.reason}` });
    for (const a of v.audits) {
      const accepted = acceptedCriteria(a.criteria, src.criteria);
      if (!accepted.length) {
        ignored.push({ source: name, reason: `${a.package}@${a.version}: criterion "${a.criteria}" is not one this source is trusted for (${src.criteria.join(', ')})` });
        continue;
      }
      audits.push({ ...a, source: name, key_id: v.key_id, accepted_criteria: accepted });
    }
  }
  for (const name of Object.keys(locked).sort()) {
    if (!config.sources[name]) ignored.push({ source: name, reason: 'in the lock but no longer configured' });
  }
  return { audits, errors, ignored };
}

/** Local and imported audits that name exactly this entry's artifact. */
function auditsFor(tool, { local = [], imported = [] } = {}) {
  const subject = subjectOf(tool);
  if (!subject) return [];
  return [
    ...local.filter((a) => auditMatches(a, subject)).map((a) => ({ ...a, source: 'local', key_id: null, accepted_criteria: [a.criteria] })),
    ...imported.filter((a) => auditMatches(a, subject)),
  ];
}

// ── as the findings model sees it ─────────────────────────────────────────

const auditSource = (a) => (a.source === 'local' ? 'audit:local' : `audit:${a.key_id}`);

/**
 * Audits of one subject (auditsFor's output) as Observations and the
 * `audits/recorded` findings resting on them. Info, observed: a statement that
 * somebody looked, which the policy table shows and never counts.
 */
function auditObservations(audits, subj) {
  const observations = [];
  const findings = [];
  for (const a of audits || []) {
    const crit = (a.accepted_criteria || [a.criteria]).join(', ');
    const obs = F.observation({
      subject: subj, dimension: `audit/${a.source}/${a.who}`, status: crit,
      observed_at: a.date, source: auditSource(a), detail: a.notes || null,
    });
    observations.push(obs);
    findings.push(F.finding({
      rule: 'audits/recorded', subject: subj, severity: 'info',
      confidence: a.source === 'local' ? 'high' : 'medium',
      refs: [obs.id],
      message: `${crit} by ${a.who} on ${a.date} (${a.source === 'local' ? 'your audit' : `imported from ${a.source}, key ${a.key_id}`})`,
    }));
  }
  return { observations, findings };
}

const sourceSubject = (name) => F.subject.name({ name, ecosystem: 'audit-source' });

/**
 * The import check as findings: one set per configured source, plus a file
 * subject for a config or lock that could not be read at all.
 *
 *   rows      [{ source, ok, code?, error?, audits?, key_id? }] — fetchImports'
 *             report, or the per-source view of loadImportedAudits
 *   global    errors not tied to a source (unreadable config / lock)
 */
function importFindings({ rows = [], global = [], configPath = null, facts: extra = {} } = {}) {
  const subjects = [];
  const findings = [];
  const facts = {};
  for (const r of rows) {
    const s = sourceSubject(r.source);
    subjects.push(s);
    facts[s.id] = { source: r.source, ...(extra[r.source] || {}) };
    if (r.ok) {
      findings.push(F.finding({
        rule: 'audits/import-verified', subject: s, severity: 'info',
        message: `${r.source}: ${r.audits} audit(s) in force, signed by ${r.key_id}`,
      }));
    } else if (r.code === 'not-fetched') {
      findings.push(F.finding({
        rule: 'audits/import-not-fetched', subject: s, severity: 'medium', state: 'not-run',
        message: `${r.source}: ${r.error}`,
      }));
    } else {
      findings.push(F.finding({
        rule: 'audits/import-unverified', subject: s, severity: 'high',
        message: `${r.source}: ${r.error} [${r.code}]`,
      }));
    }
  }
  for (const e of global) {
    const s = F.subject.hostConfig({ path: configPath || IMPORTS_FILE, scope: 'audits' });
    if (!subjects.some((x) => x.id === s.id)) subjects.push(s);
    findings.push(F.finding({ rule: 'audits/import-unverified', subject: s, severity: 'high', message: `${e.error} [${e.code}]` }));
  }
  return { subjects, findings, facts };
}

module.exports = {
  auditSource, auditObservations, importFindings, sourceSubject,
  AUDITS_FILE, IMPORTS_FILE, LOCK_FILE, EXPORT_SCHEMA, EXPORT_ARTIFACT, CRITERIA,
  validateAudit, sortAudits, subjectOf, auditMatches,
  readLocalAudits, addLocalAudit,
  exportBundle, verifyBundle,
  readImportsConfig, acceptedCriteria, fetchImports, readLock, writeLock, loadImportedAudits,
  auditsFor,
};
