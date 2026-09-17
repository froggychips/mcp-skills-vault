'use strict';
/**
 * Machine-readable renderings of a verify_integrity run.
 *
 * The gate only ever spoke in prose, which is why `orchestrate --install` used
 * to grep its own report for lines starting with FAIL — and missed SKIP lines
 * entirely. A structured document removes the need to parse prose, and SARIF
 * puts each finding on the DB line that caused it, so GitHub code scanning can
 * annotate the pull request that introduced it.
 *
 * API:
 *   toJsonReport({ results, meta })      -> plain object, JSON-serialisable
 *   toSarif(report, { dbPath, lineOf })  -> SARIF 2.1.0 log
 *   dbLineIndex(rawJson)                 -> (entryName) => 1-based line number
 *
 * Finding levels map the report's own tags:
 *   FAIL, CVE        → error    (hard failures)
 *   UNVERIFIED, MISS → warning  (nothing was compared; error under --fail-unverified)
 *   WARN, HOOK       → warning
 *   NOTE, DIGEST     → note
 */

const TAG_LEVEL = {
  FAIL:       'error',
  CVE:        'error',
  UNVERIFIED: 'warning',
  MISS:       'warning',
  WARN:       'warning',
  HOOK:       'warning',
  DIGEST:     'note',
  DEEP:       'note',
  SIG:        'note',
  PROV:       'note',
  DEPS:       'note',
  DEPHOOK:    'warning',
  DEPCVE:     'warning',
  NOTE:       'note',
};

// Tag → SARIF rule id. Rules are what GitHub groups alerts by, so they need to
// be stable and few.
const TAG_RULE = {
  FAIL:       'integrity-mismatch',
  CVE:        'known-advisory',
  UNVERIFIED: 'unverified-entry',
  MISS:       'missing-pin',
  WARN:       'metadata-mismatch',
  HOOK:       'install-hook',
  DIGEST:     'unpinned-image',
  DEEP:       'deep-verified',
  SIG:        'signature-verified',
  PROV:       'provenance-claim',
  DEPS:       'dependency-tree',
  DEPHOOK:    'dependency-install-hook',
  DEPCVE:     'dependency-advisory',
  NOTE:       'note',
};

const RULE_HELP = {
  'integrity-mismatch': 'The artifact the registry serves does not hash to the value pinned in the DB. Do not install; investigate before refreshing the pin.',
  'known-advisory':     'An advisory feed reports a high or critical vulnerability affecting the pinned version.',
  'unverified-entry':   'Nothing about this entry was compared against a registry — the feed was unreachable, the install command was not parsable, or there is no artifact to hash. Not a pass.',
  'missing-pin':        'The entry has no pinned version or no stored integrity hash, so there is nothing to compare.',
  'metadata-mismatch':  'Registry metadata disagrees with the DB (repository URL, license).',
  'install-hook':       'The package runs code at install time (preinstall/install/postinstall/prepare/prepack).',
  'unpinned-image':     'A container image is referenced by tag rather than by @sha256 digest.',
  'deep-verified':      'The artifact was downloaded and hashed locally; the bytes match both the registry metadata and the DB pin.',
  'signature-verified': "The registry's signature over <name>@<version>:<integrity> verifies against a published npm key.",
  'provenance-claim':   'A provenance attestation is published and names the source repository. The claim is read, not cryptographically verified.',
  'dependency-tree':    'Size and depth of the resolved dependency tree.',
  'dependency-install-hook': 'A transitive dependency runs code at install time. It runs whether or not the top-level package has hooks of its own.',
  'dependency-advisory':'An advisory affects a package inside the dependency tree.',
  'note':               'Informational.',
};

function levelForTag(tag) {
  return TAG_LEVEL[tag] || 'note';
}

/**
 * Normalise the run's internal result objects into a report document.
 *
 * `results` entries look like { tool, status, msg, lines?, failures? }; `lines`
 * is a list of [tag, text] pairs.
 */
function toJsonReport({ results = [], meta = {} } = {}) {
  const entries = results.map((r) => {
    const tool = r.tool || {};
    const findings = (r.lines || []).map(([tag, text]) => ({
      tag,
      level:   levelForTag(tag),
      rule:    TAG_RULE[tag] || 'note',
      message: String(text).replace(/\s*\n\s*/g, ' ').trim(),
    }));
    // The status line itself carries the verdict for single-line results
    // (UNVERIFIED for an unreachable registry, SKIP for UPD runs).
    if (!findings.length && (r.status === 'UNVERIFIED' || r.status === 'SKIP')) {
      findings.push({
        tag:     r.status,
        level:   levelForTag(r.status === 'SKIP' ? 'NOTE' : 'UNVERIFIED'),
        rule:    TAG_RULE[r.status] || 'note',
        message: String(r.msg || '').trim(),
      });
    }
    return {
      name:      tool.name ?? null,
      status:    r.status,
      version:   tool.version ?? null,
      integrity: tool.pkg_integrity ?? null,
      trust:     tool.trust ?? null,
      install_cmd: tool.install_cmd ?? null,
      failures:  r.failures || 0,
      findings,
    };
  });

  return {
    schema:       'mcp-vault/verify-report@1',
    generated_at: new Date().toISOString(),
    ...meta,
    checked:    entries.length,
    failures:   entries.reduce((n, e) => n + e.failures, 0),
    unverified: entries.filter((e) => e.status === 'UNVERIFIED').length,
    entries,
  };
}

/**
 * Build a name → line-number lookup for tools_database.json, so a finding can
 * point at the entry that caused it rather than at the top of the file.
 */
function dbLineIndex(rawJson) {
  const lines = String(rawJson).split('\n');
  const index = new Map();
  lines.forEach((line, i) => {
    const m = line.match(/"name"\s*:\s*"((?:[^"\\]|\\.)*)"/);
    if (!m) return;
    let name;
    try { name = JSON.parse(`"${m[1]}"`); } catch { name = m[1]; }
    if (!index.has(name)) index.set(name, i + 1);
  });
  return (name) => index.get(name) || 1;
}

/**
 * SARIF 2.1.0. Only findings at warning/error level are emitted: notes would
 * bury the alert list for no benefit.
 */
function toSarif(report, { dbPath = 'mcp-ecosystem-intelligence/assets/tools_database.json', lineOf = () => 1 } = {}) {
  const usedRules = new Map();
  const sarifResults = [];

  for (const entry of report.entries || []) {
    for (const f of entry.findings || []) {
      if (f.level === 'note') continue;
      usedRules.set(f.rule, true);
      sarifResults.push({
        ruleId: f.rule,
        level:  f.level,
        // Some messages already lead with the entry name; don't say it twice.
        message: { text: f.message.startsWith(`${entry.name}:`) ? f.message : `${entry.name}: ${f.message}` },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: dbPath },
            region: { startLine: lineOf(entry.name) },
          },
        }],
        partialFingerprints: {
          // Keep an alert stable across runs and line moves.
          entryRule: `${entry.name}:${f.rule}`,
        },
      });
    }
  }

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'mcp-vault verify',
          informationUri: 'https://github.com/froggychips/mcp-skills-vault',
          rules: [...usedRules.keys()].map((id) => ({
            id,
            shortDescription: { text: id.replace(/-/g, ' ') },
            fullDescription:  { text: RULE_HELP[id] || id },
            help:             { text: RULE_HELP[id] || id },
            defaultConfiguration: { level: id === 'integrity-mismatch' || id === 'known-advisory' ? 'error' : 'warning' },
          })),
        },
      },
      results: sarifResults,
    }],
  };
}

module.exports = { toJsonReport, toSarif, dbLineIndex, levelForTag, TAG_RULE };
