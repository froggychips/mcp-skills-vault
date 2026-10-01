#!/usr/bin/env node
/**
 * Draft issue texts for the authors of entries with a real finding.
 *
 * The gate finds things about other people's packages — an advisory against a
 * pinned version, a registry that names a different repository, a yanked
 * release — and until now that knowledge stayed in this repo's DB. The people
 * who could fix it are the authors. This writes, for each entry that has a
 * finding, a short factual issue text a maintainer can read, check and paste
 * into the author's tracker by hand.
 *
 * It opens nothing. There is no code here that talks to GitHub or anywhere else,
 * not behind a flag, not in a dry-run toggle: every issue is a decision a
 * person makes about one repository, after reading the draft. The output is
 * files in a directory and nothing else. This is a repo chore, not part of the
 * published CLI — it does not ship in the npm package.
 *
 * What counts as a finding, read only from what the DB and eval results
 * already record (offline):
 *
 *   advisory             advisories: vulnerable (high/critical) or
 *                        advisories-present (lower severity) against the pin
 *   identity             source_binding: mismatch, or the official registry
 *                        record contradicted / withdrawn
 *   dependency-hooks     dependencies: hooks — something in the transitive
 *                        tree runs install-time scripts
 *   availability         the pinned release is yanked, the package deprecated,
 *                        or the name / version unpublished
 *   surface-unexplained  the tool surface changed while the artifact did not
 *
 * Each one is a lib/finding.cjs Finding (docs/adr/0001) on the entry's
 * artifact subject, resting on an Observation of the stored evidence — and
 * only evidence about the artifact the entry installs today: a record for the
 * previous version is not news about this one (lib/badge.cjs
 * `evidenceAboutArtifact`, the rule the tier and the badge use). A finding
 * whose observation is past its shelf life has `state: stale`. index.json
 * carries them as an `mcp-vault/findings@1` document under `findings`; the
 * drafts are renderings of it. Nothing here decides anything — a draft is
 * not a verdict, so there is no Decision.
 *
 * An entry with none of these is not in the output at all. A clean entry is
 * not news, and an issue saying "we checked and it is fine" is noise in
 * someone else's tracker.
 *
 * The DB records that an advisory applies, not which one. `--upgrade` takes
 * the JSON of `mcp-vault upgrade --json` (the weekly refresh already produces
 * it) and adds advisory IDs and the shortest clean version; without it the
 * draft says the IDs are missing and the index marks the draft as not ready.
 *
 * Every finding carries the date it was established. One past its shelf life
 * (lib/evidence.cjs) is still drafted, but the index says so: re-verify before
 * sending, because a finding that was fixed last week is the worst thing to
 * put in somebody's tracker.
 *
 * Usage:
 *   node .github/scripts/finding_reports.cjs [--out <dir>] [--upgrade <upgrade.json>]
 *                                            [--as-of <date>] [--json]
 *
 * Writes <dir>/<slug>.md per entry and <dir>/index.json. Default dir:
 * ./finding-reports. The same DB, upgrade file and day produce the same bytes:
 * the instant is taken to the start of its UTC day, the only granularity at
 * which an observation goes stale.
 *
 * Exit codes:
 *   0  written (including "no findings")
 *   2  bad arguments, or the output directory holds files this did not write
 */

'use strict';

const fs   = require('fs');
const path = require('path');

const SCRIPTS = path.resolve(__dirname, '..', '..', 'mcp-ecosystem-intelligence', 'scripts');
const { readDb } = require(path.join(SCRIPTS, 'lib', 'db_io.cjs'));
const { evalIndex } = require(path.join(SCRIPTS, 'lib', 'tiers.cjs'));
const { DEFAULT_MAX_AGE_DAYS, isPositive } = require(path.join(SCRIPTS, 'lib', 'evidence.cjs'));
const { toTypedEntry } = require(path.join(SCRIPTS, 'lib', 'entry_model.cjs'));
const { githubSlug } = require(path.join(SCRIPTS, 'lib', 'repo_url.cjs'));
const { slugFor, evidenceAboutArtifact } = require(path.join(SCRIPTS, 'lib', 'badge.cjs'));
const {
  observation, observationsFromEvidence, observationState, finding, findingsDocument, toJson,
} = require(path.join(SCRIPTS, 'lib', 'finding.cjs'));
const { subjectForTool } = require(path.join(SCRIPTS, 'lib', 'findings_from.cjs'));
const { asOfFromArgv, parseAsOf, isoDay, requireAsOf } = require(path.join(SCRIPTS, 'lib', 'clock.cjs'));

const DB_PATH   = path.join(SCRIPTS, '..', 'assets', 'tools_database.json');
const EVAL_PATH = path.join(SCRIPTS, '..', 'assets', 'eval_results.json');
const VAULT     = 'https://github.com/froggychips/mcp-skills-vault';
const CLI       = 'npx -y @froggychips/mcp-vault';
const STALE_NOTE = 'stale — re-verify before sending';
const MAX_LISTED = 8;

const TYPES = ['advisory', 'identity', 'dependency-hooks', 'availability', 'surface-unexplained'];

const HELP = `finding_reports — draft issue texts for authors of entries with a finding

USAGE
  node .github/scripts/finding_reports.cjs [--out <dir>] [--upgrade <upgrade.json>]
                                           [--as-of <date>] [--json]

  --out       where to write <slug>.md + index.json (default ./finding-reports)
  --upgrade   output of \`mcp-vault upgrade --json\`: advisory IDs and safe versions
  --as-of     the day staleness is judged at: YYYY-MM-DD or ISO-8601 with a
              zone, taken to the start of its UTC day (default: today)
  --json      print the index instead of a summary

Writes files only. Nothing is opened, posted or sent anywhere.
`;

function parseArgs(argv) {
  const opts = { out: path.resolve('finding-reports'), upgrade: null, json: false, help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') opts.json = true;
    else if (a === '-h' || a === '--help') opts.help = true;
    else if (a === '--out') { const v = argv[++i]; if (!v) return { ...opts, error: '--out needs a directory' }; opts.out = path.resolve(v); }
    else if (a === '--upgrade') { const v = argv[++i]; if (!v) return { ...opts, error: '--upgrade needs a file' }; opts.upgrade = path.resolve(v); }
    else if (a === '--as-of') i++;              // read by asOfFromArgv
    else if (a.startsWith('--as-of=')) continue;
    else return { ...opts, error: `unknown argument ${a}` };
  }
  const clock = asOfFromArgv(argv);
  if (clock.error) return { ...opts, error: clock.error };
  return { ...opts, asOf: dayOf(clock.asOf) };
}

/** The start of asOf's UTC day. */
const dayOf = (asOf) => parseAsOf(isoDay(requireAsOf(asOf, 'finding_reports')));

/** `pkg@version`, the way the author would write it. */
function artifactLabel(tool) {
  try {
    const a = toTypedEntry(tool).artifact;
    if (a.ecosystem === 'oci') return `${a.image}${a.digest ? `@${a.digest}` : a.tag ? `:${a.tag}` : ''}`;
    return a.version ? `${a.package}@${a.version}` : a.package;
  } catch {
    return tool.name;
  }
}

function ecosystemOf(tool) {
  try { return toTypedEntry(tool).artifact.ecosystem; } catch { return null; }
}

// What each author-facing (dimension, status) concludes: the Finding's rule
// and severity, and the draft type it is rendered as. Rule ids reuse the
// gate's where the fact is the same one (lib/legacy_tags.cjs: CVE, DEPHOOK).
const RULES = {
  'advisories:vulnerable':         { rule: 'advisories/known-vulnerability', severity: 'high',   type: 'advisory' },
  'advisories:advisories-present': { rule: 'advisories/known-advisory',      severity: 'low',    type: 'advisory' },
  'source_binding:mismatch':       { rule: 'identity/source-mismatch',       severity: 'medium', type: 'identity' },
  'registry:contradicted':         { rule: 'identity/registry-contradicted', severity: 'medium', type: 'identity' },
  'registry:withdrawn':            { rule: 'identity/registry-withdrawn',    severity: 'medium', type: 'identity' },
  'dependencies:hooks':            { rule: 'dependencies/install-hook',      severity: 'low',    type: 'dependency-hooks' },
  'availability:gone':             { rule: 'availability/gone',              severity: 'high',   type: 'availability' },
  'availability:version-gone':     { rule: 'availability/version-gone',      severity: 'high',   type: 'availability' },
  'availability:yanked':           { rule: 'availability/yanked',            severity: 'high',   type: 'availability' },
  'availability:deprecated':       { rule: 'availability/deprecated',        severity: 'medium', type: 'availability' },
  'smoke:drift':                   { rule: 'surface/unexplained-change',     severity: 'medium', type: 'surface-unexplained' },
};

// No dates in the message: a Finding's id is what was concluded about what,
// not when (lib/finding.cjs). The date is on the Observation it refs.
const MESSAGES = {
  advisory: (v) => (v.status === 'vulnerable' ? 'advisories of high or critical severity apply to this version' : 'advisories of low or moderate severity apply to this version'),
  identity: (v) => `${v.dimension}: ${v.status}`,
  'dependency-hooks': () => 'a package in the dependency tree runs install-time scripts',
  availability: (v) => `availability: ${v.status}`,
  'surface-unexplained': () => 'the advertised tool list changed while the artifact did not',
};

/**
 * The model for one entry: Observations of the stored evidence about the
 * current artifact (and of the eval's surface drift), and one Finding per
 * author-facing fact. `state` is `stale` when the observation is past its
 * shelf life at asOf, `observed` otherwise.
 */
function modelFor(tool, evalResult = null, { asOf } = {}) {
  const at = requireAsOf(asOf, 'modelFor');
  const s = subjectForTool(tool);
  const evidence = s.type === 'artifact' ? evidenceAboutArtifact(tool) : null;
  const observations = evidence
    ? observationsFromEvidence(evidence, { subject: s, source: 'stored', maxAgeDays: DEFAULT_MAX_AGE_DAYS, positive: isPositive })
    : [];
  const drift = evalResult && evalResult.surface_drift;
  if (s.type === 'artifact' && drift && drift.artifact_changed === false) {
    observations.push(observation({
      subject: s, dimension: 'smoke', status: 'drift',
      observed_at: String(evalResult.checked_at || '').slice(0, 10) || '1970-01-01',
      ttl_days: DEFAULT_MAX_AGE_DAYS.smoke, source: 'eval',
    }));
  }
  const findings = [];
  for (const o of observations) {
    const r = RULES[`${o.dimension}:${o.status}`];
    if (!r) continue;
    findings.push({
      o, r,
      f: finding({
        rule: r.rule, subject: s, scope: 'database', severity: r.severity,
        state: observationState(o, at) === 'stale' ? 'stale' : 'observed',
        refs: [o.id], message: MESSAGES[r.type](o),
      }),
    });
  }
  return { subject: s, observations, findings };
}

/**
 * The findings for one entry, as the drafts render them: each one a view of
 * a model Finding (`finding`), with the extra detail its text needs. Empty
 * array: nothing to tell the author.
 */
function findingsFor(tool, evalResult = null, upgradeRow = null, { asOf } = {}) {
  const model = modelFor(tool, evalResult, { asOf });
  const dims = (evidenceAboutArtifact(tool) || {}).dimensions || {};
  const byDim = new Map(model.findings.map((x) => [x.o.dimension, x]));
  const out = [];
  const add = (type, dimension, v, extra = {}) => {
    const m = byDim.get(dimension);
    if (!m) return;
    out.push({
      type, dimension, status: v.status, checked_at: v.checked_at || null,
      stale: m.f.state === 'stale', rule: m.f.rule, finding: m.f, ...extra,
    });
  };

  const adv = dims.advisories;
  if (adv && (adv.status === 'vulnerable' || adv.status === 'advisories-present')) {
    // An upgrade plan for a different version is about a different artifact.
    const plan = upgradeRow && upgradeRow.plan && (upgradeRow.current == null || upgradeRow.current === tool.version)
      ? upgradeRow.plan : null;
    add('advisory', 'advisories', adv, {
      severity: adv.status === 'vulnerable' ? 'high or critical' : 'low or moderate',
      advisories: plan && Array.isArray(plan.advisories)
        ? [...plan.advisories].map((a) => ({ id: a.id, severity: a.severity || 'UNKNOWN', fixed: a.fixed || [], summary: a.summary || null }))
            .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
        : null,
      plan_state: plan ? plan.state : null,
      target: plan && plan.state === 'upgrade' ? plan.target : null,
    });
  }

  if (dims.source_binding && dims.source_binding.status === 'mismatch') {
    add('identity', 'source_binding', dims.source_binding);
  }
  if (dims.registry && ['contradicted', 'withdrawn'].includes(dims.registry.status)) {
    add('identity', 'registry', dims.registry, { server_id: dims.registry.server_id || null });
  }

  if (dims.dependencies && dims.dependencies.status === 'hooks') {
    add('dependency-hooks', 'dependencies', dims.dependencies, { count: Number.isFinite(dims.dependencies.count) ? dims.dependencies.count : null });
  }

  const av = dims.availability;
  if (av && ['gone', 'version-gone', 'yanked', 'deprecated'].includes(av.status)) {
    add('availability', 'availability', av, { detail: av.detail || null });
  }

  const drift = evalResult && evalResult.surface_drift;
  if (drift && drift.artifact_changed === false) {
    const date = String(evalResult.checked_at || '').slice(0, 10) || null;
    add('surface-unexplained', 'smoke', { status: 'drift', checked_at: date }, {
      since: drift.since ? String(drift.since).slice(0, 10) : null,
      lines: Array.isArray(drift.lines) ? drift.lines.slice(0, 10) : [],
    });
  }
  return out;
}

// ── the text ────────────────────────────────────────────────────────────────

function advisoryLines(f, tool) {
  const lines = [f.status === 'vulnerable'
    ? `- **Known advisories apply to \`${artifactLabel(tool)}\`, at least one of high or critical severity** (checked ${f.checked_at}).`
    : `- **Known advisories of low or moderate severity apply to \`${artifactLabel(tool)}\`** (checked ${f.checked_at}).`];
  if (f.advisories && f.advisories.length) {
    // Worst first, then by id; a list of 28 is not short, so it stops at 8
    // and points at the command that prints all of them.
    const RANK = { CRITICAL: 0, HIGH: 1, MODERATE: 2, MEDIUM: 2, LOW: 3 };
    const ordered = [...f.advisories].sort((a, b) => ((RANK[a.severity] ?? 4) - (RANK[b.severity] ?? 4)) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    for (const a of ordered.slice(0, MAX_LISTED)) {
      lines.push(`  - [${a.id}](https://osv.dev/vulnerability/${encodeURIComponent(a.id)}) (${a.severity})`
        + `${a.fixed.length ? ` — fixed in ${a.fixed.join(' / ')}` : ' — no fixed version published'}`);
    }
    if (ordered.length > MAX_LISTED) {
      lines.push(`  - …and ${ordered.length - MAX_LISTED} more; \`${CLI} upgrade --entry ${tool.name}\` lists all of them.`);
    }
  } else {
    lines.push(`  - The advisory IDs were not recorded with this check; \`${CLI} upgrade --entry ${tool.name}\` lists them.`);
  }
  return lines;
}

function findingLines(f, tool) {
  switch (f.type) {
    case 'advisory': return advisoryLines(f, tool);
    case 'identity':
      return f.dimension === 'registry'
        ? [`- **The official MCP registry record${f.server_id ? ` \`${f.server_id}\`` : ''} is ${f.status}** for this package (checked ${f.checked_at}).`]
        : [`- **The repository published with \`${artifactLabel(tool)}\` does not point at ${tool.source_url}** (checked ${f.checked_at}). `
          + 'Anyone checking where the package was built from lands somewhere else.'];
    case 'dependency-hooks':
      return [`- **Something in the dependency tree of \`${artifactLabel(tool)}\` runs install-time scripts** (checked ${f.checked_at}`
        + `${f.count != null ? `, ${f.count} packages in the tree` : ''}). \`npx -y\` runs them without asking.`];
    case 'availability': {
      const what = {
        gone: 'the package name returns 404 from the registry, which leaves the name claimable by someone else',
        'version-gone': 'this version is no longer published',
        yanked: 'this release is yanked',
        deprecated: 'the registry marks this package as deprecated',
      }[f.status];
      return [`- **\`${artifactLabel(tool)}\`: ${what}** (checked ${f.checked_at}).${f.detail ? ` The registry says: “${f.detail}”` : ''}`];
    }
    case 'surface-unexplained':
      return [`- **The list of tools the server advertises changed${f.since ? ` since ${f.since}` : ''} while the published artifact did not** (seen ${f.checked_at}).`,
        ...f.lines.map((l) => `  - ${l}`)];
    default: return [];
  }
}

function reproduceLines(findings, tool) {
  const cmds = [`${CLI} explain ${tool.name}`];
  const types = new Set(findings.map((f) => f.type));
  if (types.has('advisory')) cmds.push(`${CLI} upgrade --entry ${tool.name}`);
  if (types.has('availability')) cmds.push(`${CLI} availability --entry ${tool.name}`);
  if (types.has('identity') || types.has('dependency-hooks')) cmds.push(`${CLI} verify --entry ${tool.name}${types.has('dependency-hooks') ? ' --deps' : ''}`);
  if (types.has('surface-unexplained')) cmds.push(`${CLI} eval --name ${tool.name} --sandbox`);
  return cmds;
}

function helpLines(findings, tool) {
  const out = [];
  for (const f of findings) {
    if (f.type === 'advisory') {
      if (f.target) out.push(`- \`${f.target}\` clears every advisory above and had none of its own when checked; a note in the README or release notes pointing users off \`${tool.version}\` may be enough.`);
      else if (f.plan_state === 'no-fix') out.push('- None of these advisories names a fixed version yet; a fix, or a note on whether the server is affected in practice, would help users decide.');
      else out.push('- If a fixed release exists, nothing is needed beyond perhaps pointing users at it.');
    } else if (f.type === 'identity') {
      out.push(f.dimension === 'registry'
        ? '- Updating the official registry record, or telling us which listing is current.'
        : '- Setting the package\'s repository field to this repository in the next release.');
    } else if (f.type === 'dependency-hooks') {
      out.push('- Checking whether the dependency that needs the install script can be avoided or replaced.');
    } else if (f.type === 'availability') {
      out.push(f.status === 'gone'
        ? '- If the package moved, a pointer to the new name in this README; if it was retired, keeping the name reserved.'
        : '- If there is a successor, a pointer to it in this README.');
    } else if (f.type === 'surface-unexplained') {
      out.push('- Letting us know whether the tool list depends on configuration, credentials or a remote backend — that makes the change expected.');
    }
  }
  return [...new Set(out)];
}

const TITLES = {
  advisory: (t) => `Advisory against ${artifactLabel(t)}`,
  identity: (t) => `Repository metadata for ${artifactLabel(t)} points elsewhere`,
  'dependency-hooks': (t) => `Install-time scripts in the dependency tree of ${artifactLabel(t)}`,
  availability: (t) => `Registry status of ${artifactLabel(t)}`,
  'surface-unexplained': (t) => `Tool list of ${artifactLabel(t)} changed without a new release`,
};

function renderIssue(tool, findings) {
  const title = findings.length === 1
    ? TITLES[findings[0].type](tool)
    : `${findings.length} findings for ${artifactLabel(tool)}`;
  const body = [
    `Hi — a short, factual note about \`${artifactLabel(tool)}\`. If it is already known or intended, feel free to close this.`,
    '',
    '## What was found',
    '',
    ...findings.flatMap((f) => findingLines(f, tool)),
    '',
    '## How to reproduce',
    '',
    '```',
    ...reproduceLines(findings, tool),
    '```',
    '',
    '## What might help',
    '',
    ...helpLines(findings, tool),
    '',
    '## If this is wrong',
    '',
    'These come from public registries and advisory feeds and can be out of date or wrong. '
      + `If so, a reply here or an issue at ${VAULT}/issues is enough: the entry is re-checked and corrected if the check disagrees.`,
    '',
    `Found with [mcp-vault](${VAULT}).`,
    '',
  ];
  return { title, markdown: `# ${title}\n\n${body.join('\n')}` };
}

// ── the run ─────────────────────────────────────────────────────────────────

function loadUpgrade(file) {
  if (!file) return new Map();
  const r = JSON.parse(fs.readFileSync(file, 'utf8'));
  return new Map((r.entries || []).map((e) => [e.name, e]));
}

/**
 * Everything to write, as data. Deterministic: sorted by entry name, dates
 * only, no timestamps of the run itself beyond the `as_of` day.
 */
function buildReports(tools, evals = new Map(), upgrades = new Map(), { asOf } = {}) {
  const day = dayOf(asOf);
  const files = new Map();
  const entries = [];
  const modelFindings = [];
  const modelObservations = [];
  const sorted = [...tools].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  const seen = new Map();
  for (const tool of sorted) {
    const findings = findingsFor(tool, evals.get(tool.name) || null, upgrades.get(tool.name) || null, { asOf: day });
    if (!findings.length) continue;
    modelFindings.push(...findings.map((f) => f.finding));
    const refs = new Set(findings.flatMap((f) => f.finding.refs));
    modelObservations.push(...modelFor(tool, evals.get(tool.name) || null, { asOf: day }).observations.filter((o) => refs.has(o.id)));
    const slug = slugFor(tool.name);
    if (seen.has(slug)) throw new Error(`"${seen.get(slug)}" and "${tool.name}" would share ${slug}.md`);
    seen.set(slug, tool.name);
    const issue = renderIssue(tool, findings);
    const file = `${slug}.md`;
    files.set(file, issue.markdown);
    const stale = findings.some((f) => f.stale);
    const needs = [];
    if (stale) needs.push(STALE_NOTE);
    if (findings.some((f) => f.type === 'advisory' && !f.advisories)) needs.push('advisory IDs missing — rerun with --upgrade');
    const repo = githubSlug(tool.source_url);
    if (!repo) needs.push('no GitHub repository in source_url — find the tracker by hand');
    // Not a blocker, a judgement aid: an advisory against an old pin that the
    // author has already fixed is news to our users, rarely to the author.
    const adv = findings.find((f) => f.type === 'advisory');
    const hint = adv && adv.target && findings.length === 1
      ? `a fixed release (${adv.target}) already exists — the finding is about the pin; an issue may add little`
      : null;
    entries.push({
      name: tool.name,
      repo,
      repo_url: tool.source_url || null,
      new_issue_url: repo ? `https://github.com/${repo}/issues/new` : null,
      artifact: artifactLabel(tool),
      ecosystem: ecosystemOf(tool),
      file,
      title: issue.title,
      types: [...new Set(findings.map((f) => f.type))],
      // The Findings themselves are in `findings` (findings@1) at the top.
      finding_ids: findings.map((f) => f.finding.id).sort(),
      evidence_date: findings.map((f) => f.checked_at).filter(Boolean).sort()[0] || null,
      stale,
      ready: needs.length === 0,
      needs,
      hint,
    });
  }
  const by_type = Object.fromEntries(TYPES.map((t) => [t, entries.filter((e) => e.types.includes(t)).length]));
  const index = {
    schema: 'mcp-vault/finding-reports@1',
    as_of: isoDay(day),
    note: 'Drafts only. Nothing was opened or sent; each issue is filed by hand, one repository at a time.',
    checked: tools.length,
    count: entries.length,
    by_type,
    entries,
    findings: toJson(findingsDocument({ asOf: day, scope: 'database', observations: modelObservations, findings: modelFindings })),
  };
  files.set('index.json', `${JSON.stringify(index, null, 2)}\n`);
  return { files, index };
}

/**
 * Write into `dir`, replacing a previous run's files. A directory holding
 * anything else is refused: this must not delete what it did not write.
 */
function writeReports(dir, files) {
  if (fs.existsSync(dir)) {
    const present = fs.readdirSync(dir);
    if (present.length) {
      let previous;
      try { previous = JSON.parse(fs.readFileSync(path.join(dir, 'index.json'), 'utf8')); } catch { previous = null; }
      if (!previous || previous.schema !== 'mcp-vault/finding-reports@1') {
        throw new Error(`${dir} is not empty and holds no earlier finding-reports index — pick another --out`);
      }
      const ours = new Set(['index.json', ...(previous.entries || []).map((e) => e.file)]);
      const foreign = present.filter((f) => !ours.has(f));
      if (foreign.length) throw new Error(`${dir} holds files this did not write (${foreign.slice(0, 3).join(', ')}) — pick another --out`);
      for (const f of present) fs.rmSync(path.join(dir, f));
    }
  }
  fs.mkdirSync(dir, { recursive: true });
  for (const [rel, body] of files) fs.writeFileSync(path.join(dir, rel), body);
}

function main(argv) {
  const opts = parseArgs(argv);
  if (opts.help) { process.stdout.write(HELP); return 0; }
  if (opts.error) { process.stderr.write(`finding_reports: ${opts.error}\n\n${HELP}`); return 2; }

  const { db } = readDb(DB_PATH);
  let evals = new Map();
  try { evals = evalIndex(JSON.parse(fs.readFileSync(EVAL_PATH, 'utf8')).results); } catch { /* none shipped */ }
  let upgrades;
  try { upgrades = loadUpgrade(opts.upgrade); }
  catch (e) { process.stderr.write(`finding_reports: cannot read --upgrade: ${e.message}\n`); return 2; }

  let built;
  try {
    built = buildReports(db.tools || [], evals, upgrades, { asOf: opts.asOf });
    writeReports(opts.out, built.files);
  } catch (e) {
    process.stderr.write(`finding_reports: ${e.message}\n`);
    return 2;
  }
  const { index } = built;
  if (opts.json) {
    process.stdout.write(`${JSON.stringify(index, null, 2)}\n`);
  } else {
    process.stdout.write(`${index.count} of ${index.checked} entries have a finding (as of ${index.as_of}); drafts in ${opts.out}\n`);
    for (const t of TYPES) process.stdout.write(`  ${t.padEnd(20)} ${index.by_type[t]}\n`);
    const notReady = index.entries.filter((e) => !e.ready).length;
    if (notReady) process.stdout.write(`${notReady} not ready to send — see "needs" in index.json\n`);
    process.stdout.write('Nothing was opened or sent.\n');
  }
  return 0;
}

if (require.main === module) {
  const code = main(process.argv.slice(2));
  process.exitCode = code;
}

module.exports = { parseArgs, modelFor, findingsFor, renderIssue, buildReports, writeReports, TYPES, RULES, STALE_NOTE };
