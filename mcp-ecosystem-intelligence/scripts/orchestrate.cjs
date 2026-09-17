#!/usr/bin/env node
/**
 * MCP Ecosystem Orchestrator
 *
 * Deterministically scans the project stack, matches the vetted DB,
 * reports integrity status, and writes .mcp.json on install consent.
 * Claude reads the output and answers user questions — no manual steps needed.
 *
 * Usage:
 *   node scripts/orchestrate.cjs [--cwd <path>] [--query <text>]
 *   node scripts/orchestrate.cjs --install <name> [--global] [--cwd <path>]
 *                                 [--strict] [--allow-unpinned]
 *                                 [--host claude-code|claude-desktop|cursor|vscode|codex]
 *                                 [--scope project|user]
 *   node scripts/orchestrate.cjs --list-hosts
 *   node scripts/orchestrate.cjs --json   (machine-readable, for Claude)
 *
 * Exit codes:
 *   0  success / all clear
 *   1  install aborted (FAIL or CVE in integrity scan)
 *   2  bad arguments / tool not found in DB
 */

'use strict';

const fs            = require('fs');
const path          = require('path');
const { spawnSync } = require('child_process');
const { exitAfterFlush } = require('./lib/exit.cjs');
const { listHosts, resolveTarget, writeServerEntry } = require('./lib/hosts.cjs');
const { trustScore, fitScore, behaviour, recommend } = require('./lib/scores.cjs');
const { toTypedEntry, artifactId } = require('./lib/entry_model.cjs');
// Reuse the gate's parsers so "what gets pinned" and "what gets checked" can
// never drift apart — they were two independent regexes before.
const {
  npmPkgName, pypiPkgName, dockerImageRef, dockerDigestPinned,
} = require('./verify_integrity.cjs');

const DB_PATH    = path.resolve(__dirname, '../assets/tools_database.json');
const EVAL_PATH  = path.resolve(__dirname, '../assets/eval_results.json');
const VERIFY_CJS = path.resolve(__dirname, 'verify_integrity.cjs');

// ── CLI args ────────────────────────────────────────────────────────────────

const argv       = process.argv.slice(2);
const CWD        = argVal('--cwd')     || process.cwd();
const QUERY      = argVal('--query')   || null;
const INSTALL    = argVal('--install') || null;
const AS_JSON    = argv.includes('--json');
const GLOBAL     = argv.includes('--global');
// Skip the network-bound advisory feeds during install — useful for CI /
// air-gapped runs / integration tests. Hash check still runs.
const OFFLINE    = argv.includes('--offline');
const STRICT     = argv.includes('--strict');
// Escape hatch for installing an entry whose DB record has no pinned version.
// Off by default: writing an unpinned command into .mcp.json means the thing
// that runs is not the thing the gate checked.
const ALLOW_UNPINNED = argv.includes('--allow-unpinned');
// Which host's config to write. The same vault entry is just as useful in
// Cursor, VS Code, Claude Desktop or Codex; only the path (and in two cases the
// shape) differs.
const HOST   = argVal('--host') || 'claude-code';
const SCOPE  = argv.includes('--global') ? 'user' : (argVal('--scope') || 'project');

function argVal(flag) {
  const i = argv.indexOf(flag);
  return i !== -1 && argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : null;
}

// ── ANSI helpers ────────────────────────────────────────────────────────────

const T = process.stdout.isTTY;
const B  = T ? '\x1b[1m'  : '';
const DM = T ? '\x1b[2m'  : '';
const YL = T ? '\x1b[33m' : '';
const RD = T ? '\x1b[31m' : '';
const GN = T ? '\x1b[32m' : '';
const RS = T ? '\x1b[0m'  : '';

// ── Stack detection ─────────────────────────────────────────────────────────

function detectStack(cwd) {
  // Signals are recorded with where they came from and how much they imply.
  // The sets below are derived from them, which is the way round that lets a
  // recommendation be explained: "aws, because .env has an AWS_ prefix" is a
  // different statement from "aws, because boto3 is a dependency", and only one
  // of them means the project actually talks to AWS.
  //
  //   detected — the project declares it (a manifest dependency, a config file)
  //   inferred — something suggests it (an env var name, a directory)
  const signals = [];
  let src = 'unknown';
  let kind = 'detected';
  let conf = 0.9;
  const from = (source, confidence, k = 'detected') => { src = source; conf = confidence; kind = k; };
  const note = (dimension, value) => {
    const existing = signals.find((x) => x.dimension === dimension && x.value === value);
    // Two sources agreeing is stronger evidence than either alone, but never
    // certainty: keep the best, and record that it was seen more than once.
    if (existing) {
      existing.sources = [...new Set([...existing.sources, src])];
      if (conf > existing.confidence) { existing.confidence = conf; existing.kind = kind; }
      return;
    }
    signals.push({ dimension, value, kind, sources: [src], confidence: conf });
  };

  const langs  = new Set();
  const dbs    = new Set();
  const infra  = new Set();
  const cats   = new Set();
  const keys   = [];
  const addLang  = (v) => { langs.add(v);  note('lang', v); };
  const addDb    = (v) => { dbs.add(v);    note('db', v); };
  const addInfra = (v) => { infra.add(v);  note('infra', v); };
  const addCat   = (v) => { cats.add(v);   note('category', v); };

  // package.json
  from('package.json dependency', 0.95);
  try {
    const pkg  = JSON.parse(fs.readFileSync(path.join(cwd, 'package.json'), 'utf8'));
    const deps = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies });
    addLang('Node');
    if (deps.some(d => ['next','react','remix','nuxt','vue','svelte'].includes(d))) addLang('Next.js/React');
    if (deps.some(d => ['express','fastify','koa','hono'].includes(d)))             addLang('Node HTTP');
    if (deps.some(d => d === 'pg' || d === 'postgres' || d.includes('prisma') || d.includes('sequelize') || d === 'knex')) { addDb('postgres'); addCat('database'); }
    if (deps.some(d => d === 'mongoose' || d.includes('mongodb') || d === '@typegoose/typegoose')) { addDb('mongodb');  addCat('database'); }
    if (deps.some(d => d === 'redis' || d === 'ioredis' || d === '@upstash/redis'))  { addDb('redis');    addCat('database'); }
    if (deps.some(d => d.includes('clickhouse')))                                    { addDb('clickhouse'); addCat('database'); }
    if (deps.some(d => d.includes('stripe')))                                        { addInfra('stripe');     addCat('payments'); }
    if (deps.some(d => d.includes('@sentry')))                                       { addInfra('sentry');     addCat('observability'); }
    if (deps.some(d => d.includes('cloudflare') || d === 'wrangler'))                { addInfra('cloudflare'); addCat('infra'); }
    if (deps.some(d => d.startsWith('@aws-sdk') || d === 'aws-sdk'))                 { addInfra('aws');        addCat('infra'); }
    if (deps.some(d => d.includes('@kubernetes') || d === 'kubernetes-client'))      { addInfra('kubernetes'); addCat('infra'); }
  } catch { /* no package.json */ }

  // pyproject.toml / requirements.txt
  from('python requirements', 0.95);
  for (const f of ['pyproject.toml', 'requirements.txt']) {
    try {
      const txt = fs.readFileSync(path.join(cwd, f), 'utf8').toLowerCase();
      addLang('Python');
      if (/psycopg2|sqlalchemy|asyncpg|databases/.test(txt)) { addDb('postgres');   addCat('database'); }
      if (/pymongo|motor/.test(txt))                          { addDb('mongodb');    addCat('database'); }
      if (/\bredis\b/.test(txt))                              { addDb('redis');      addCat('database'); }
      if (/clickhouse/.test(txt))                             { addDb('clickhouse'); addCat('database'); }
      if (/boto3|aiobotocore/.test(txt))                      { addInfra('aws');        addCat('infra'); }
      if (/\bstripe\b/.test(txt))                             { addInfra('stripe');     addCat('payments'); }
      if (/\bsentry\b/.test(txt))                             { addInfra('sentry');     addCat('observability'); }
    } catch {}
  }

  // go.mod / Cargo.toml
  from('language manifest', 0.95);
  if (fs.existsSync(path.join(cwd, 'go.mod')))    addLang('Go');
  if (fs.existsSync(path.join(cwd, 'Cargo.toml'))) addLang('Rust');

  // Swift — Package.swift (SwiftPM) or Project.swift (Tuist)
  from('language manifest', 0.95);
  if (fs.existsSync(path.join(cwd, 'Package.swift')))  addLang('swift');
  if (fs.existsSync(path.join(cwd, 'Project.swift')))  addLang('swift');

  // JVM — pom.xml / build.gradle / build.gradle.kts. Dep parsing skipped:
  // pom.xml is XML, build.gradle is Groovy/Kotlin DSL — out of scope here.
  if (fs.existsSync(path.join(cwd, 'pom.xml')))             addLang('jvm');
  if (fs.existsSync(path.join(cwd, 'build.gradle')))        addLang('jvm');
  if (fs.existsSync(path.join(cwd, 'build.gradle.kts')))    addLang('jvm');

  // Ruby — Gemfile (preferred) with line-by-line gem scan; Gemfile.lock fallback.
  from('Gemfile', 0.9);
  for (const f of ['Gemfile', 'Gemfile.lock']) {
    try {
      const txt = fs.readFileSync(path.join(cwd, f), 'utf8');
      addLang('ruby');
      // Simple string-contains lookup — no real parser. Matches both
      // `gem "pg"` and Gemfile.lock dependency lines.
      if (/\bpg\b/.test(txt))         { addDb('postgres');   addCat('database'); }
      if (/\bmysql2\b/.test(txt))     { addDb('mysql');      addCat('database'); }
      if (/\bredis\b/.test(txt))      { addDb('redis');      addCat('database'); }
      if (/\bmongo\b/.test(txt))      { addDb('mongodb');    addCat('database'); }
      if (/\bdalli\b/.test(txt))      { addInfra('memcached'); addCat('database'); }
      if (/\baws-sdk\b/.test(txt))    { addInfra('aws');      addCat('infra'); }
      break; // Gemfile wins over Gemfile.lock — don't double-scan.
    } catch {}
  }

  // PHP — composer.json with JSON `require` map scan.
  from('composer.json require', 0.95);
  try {
    const composer = JSON.parse(fs.readFileSync(path.join(cwd, 'composer.json'), 'utf8'));
    addLang('php');
    const req = { ...(composer.require || {}), ...(composer['require-dev'] || {}) };
    const reqKeys = Object.keys(req);
    if (reqKeys.some(k => k === 'mongodb/mongodb' || k.startsWith('mongodb/')))    { addDb('mongodb');  addCat('database'); }
    if (reqKeys.some(k => k === 'predis/predis' || k.startsWith('predis/')))       { addDb('redis');    addCat('database'); }
    if (reqKeys.some(k => k.startsWith('aws/aws-sdk-php')))                         { addInfra('aws');    addCat('infra'); }
    if (reqKeys.some(k => k === 'firebase/php-jwt'))                                { /* auth dep, no MCP signal */ }
    if (reqKeys.some(k => k.startsWith('stripe/')))                                 { addInfra('stripe'); addCat('payments'); }
    if (reqKeys.some(k => k.startsWith('sentry/')))                                 { addInfra('sentry'); addCat('observability'); }
  } catch { /* no composer.json or invalid JSON */ }

  // .NET — *.csproj / *.sln. Skip parsing; flag the language only.
  from('project file', 0.95);
  try {
    const entries = fs.readdirSync(cwd);
    if (entries.some(f => f.endsWith('.csproj') || f.endsWith('.sln'))) addLang('dotnet');
  } catch {}

  // Elixir — mix.exs. Skip dep parsing (Elixir DSL).
  from('mix.exs', 0.95);
  if (fs.existsSync(path.join(cwd, 'mix.exs'))) addLang('elixir');

  // docker-compose.yml
  from('docker-compose service', 0.85);
  try {
    const txt = fs.readFileSync(path.join(cwd, 'docker-compose.yml'), 'utf8').toLowerCase();
    if (/image:\s*(postgres|pg[^s])/.test(txt))     { addDb('postgres');   addCat('database'); }
    if (/image:\s*(mysql|mariadb)/.test(txt))        { addDb('mysql');      addCat('database'); }
    if (/image:\s*mongo/.test(txt))                  { addDb('mongodb');    addCat('database'); }
    if (/image:\s*redis/.test(txt))                  { addDb('redis');      addCat('database'); }
    if (/clickhouse/.test(txt))                      { addDb('clickhouse'); addCat('database'); }
    if (/image:\s*(confluentinc\/|bitnami\/kafka|apache\/kafka)/.test(txt)) { addInfra('kafka');      addCat('streaming'); }
    if (/image:\s*(prom\/prometheus|prometheus)/.test(txt))                 { addInfra('prometheus'); addCat('observability'); }
    if (/image:\s*grafana/.test(txt))                                       { addInfra('grafana');    addCat('observability'); }
    if (/image:\s*grafana\/loki/.test(txt))                                 { addInfra('loki');       addCat('observability'); }
    if (/image:\s*nginx/.test(txt))                                         { addInfra('nginx');      addCat('infra'); }
    if (/image:\s*hashicorp\/vault/.test(txt))                              { addInfra('vault');      addCat('infra'); }
  } catch {}

  // Infra files at well-known paths (one-shot existence check, no content scan)
  const fileSignals = [
    [['.teamcity'],                       'teamcity', 'ci-cd'],
    [['helm', 'charts'],                  'helm',     'infra'],
    [['Chart.yaml'],                      'helm',     'infra'],
    [['argocd', '.argocd'],               'argocd',   'infra'],
    [['terraform', '.terraform'],         'terraform','infra'],
    [['Pulumi.yaml'],                     'pulumi',   'infra'],
    [['ansible', 'playbook.yml', 'playbook.yaml'], 'ansible', 'infra'],
    [['prometheus.yml', 'prometheus.yaml'],'prometheus','observability'],
    [['grafana', 'dashboards'],           'grafana',  'observability'],
    [['.gitlab-ci.yml'],                  'gitlab',   'vcs'],
    [['.circleci'],                       'circleci', 'ci-cd'],
    [['.github/workflows'],               'github-actions', 'ci-cd'],
    [['Jenkinsfile'],                     'jenkins',  'ci-cd'],
    [['k8s', 'kubernetes', 'manifests'],  'kubernetes','infra'],
    [['Dockerfile'],                      'docker',   'infra'],
  ];
  from('project file or directory', 0.85);
  for (const [paths, signal, cat] of fileSignals) {
    if (paths.some(p => fs.existsSync(path.join(cwd, p)))) {
      addInfra(signal); addCat(cat);
    }
  }

  // Surface .tf files anywhere in the repo root as a terraform signal
  // (covers projects that don't put them in a dedicated dir).
  try {
    from('.tf file in the repo root', 0.85);
    if (fs.readdirSync(cwd).some(f => f.endsWith('.tf'))) { addInfra('terraform'); addCat('infra'); }
  } catch {}

  // .env / .env.example / .env.local — key names only, never values.
  // Weakest signal of the lot, and marked `inferred`: a configured credential
  // says someone has an account, not that this project calls that service.
  from('.env key name', 0.6, 'inferred');
  for (const f of ['.env.example', '.env.local', '.env']) {
    try {
      for (const line of fs.readFileSync(path.join(cwd, f), 'utf8').split('\n')) {
        const m = line.match(/^([A-Z][A-Z0-9_]{2,})\s*=/);
        if (!m) continue;
        const k = m[1];
        keys.push(k);
        if (/^GITHUB_/.test(k))                              { addInfra('github');     addCat('vcs'); }
        if (/^GITLAB_/.test(k))                              { addInfra('gitlab');     addCat('vcs'); }
        if (/^LINEAR_/.test(k))                              { addInfra('linear');     addCat('pm'); }
        if (/^NOTION_/.test(k))                              { addInfra('notion');     addCat('docs'); }
        if (/^SENTRY_/.test(k))                              { addInfra('sentry');     addCat('observability'); }
        if (/^STRIPE_/.test(k))                              { addInfra('stripe');     addCat('payments'); }
        if (/^SUPABASE_/.test(k))                            { addDb('supabase');     addCat('database'); }
        if (/^NEON_/.test(k) || k === 'NEON_DATABASE_URL')  { addDb('neon');         addCat('database'); }
        if (/^(CLOUDFLARE_|CF_API_TOKEN)/.test(k))          { addInfra('cloudflare'); addCat('infra'); }
        if (/^AWS_/.test(k))                                 { addInfra('aws');        addCat('infra'); }
        if (/^MONGO/.test(k))                                { addDb('mongodb');      addCat('database'); }
        if (/^CLICKHOUSE_/.test(k))                          { addDb('clickhouse');   addCat('database'); }
        if (/^(KUBE_|KUBERNETES_)/.test(k))                  { addInfra('kubernetes'); addCat('infra'); }
        if (/^(MYSQL_|MARIADB_)/.test(k))                    { addDb('mysql');        addCat('database'); }
        if (/^(PG_|POSTGRES_|POSTGRESQL_)/.test(k))          { addDb('postgres');     addCat('database'); }
        if (/^(TEAMCITY_|TC_(URL|TOKEN|API))/.test(k))       { addInfra('teamcity');   addCat('ci-cd'); }
        if (/^(CIRCLECI_|CIRCLE_)/.test(k))                  { addInfra('circleci');   addCat('ci-cd'); }
        if (/^JENKINS_/.test(k))                             { addInfra('jenkins');    addCat('ci-cd'); }
        if (/^(ARGOCD_|ARGO_)/.test(k))                      { addInfra('argocd');     addCat('infra'); }
        if (/^HELM_/.test(k))                                { addInfra('helm');       addCat('infra'); }
        if (/^(TERRAFORM_|TF_(VAR|CLI))/.test(k))            { addInfra('terraform');  addCat('infra'); }
        if (/^VAULT_(ADDR|TOKEN|NAMESPACE)/.test(k))         { addInfra('vault');      addCat('infra'); }
        if (/^PROMETHEUS_/.test(k))                          { addInfra('prometheus'); addCat('observability'); }
        if (/^GRAFANA_/.test(k))                             { addInfra('grafana');    addCat('observability'); }
        if (/^LOKI_/.test(k))                                { addInfra('loki');       addCat('observability'); }
        if (/^DATADOG_/.test(k))                             { addInfra('datadog');    addCat('observability'); }
        if (/^DYNATRACE_/.test(k))                           { addInfra('dynatrace');  addCat('observability'); }
        if (/^NEWRELIC_/.test(k))                            { addInfra('newrelic');   addCat('observability'); }
        if (/^KAFKA_/.test(k))                               { addInfra('kafka');      addCat('streaming'); }
        if (/^(SALESFORCE_|SFDC_)/.test(k))                  { addInfra('salesforce'); addCat('crm'); }
        if (/^MAPBOX_/.test(k))                              { addInfra('mapbox');     addCat('maps'); }
        if (/^BROWSERSTACK_/.test(k))                        { addInfra('browserstack');addCat('browser'); }
        if (/^POSTMAN_/.test(k))                             { addInfra('postman');    addCat('testing'); }
        if (/^(AZURE_DEVOPS_|ADO_)/.test(k))                 { addInfra('azure-devops');addCat('vcs'); }
        if (/^(JIRA_|CONFLUENCE_|ATLASSIAN_)/.test(k))       { addInfra('atlassian');  addCat('pm'); }
        // Jira/Confluence are both served by mcp-atlassian. Keep the
        // 'atlassian' signal above for back-compat and add 'jira' →
        // 'docs' so docs-oriented callers find the same server.
        if (/^JIRA_/.test(k) || k === 'ATLASSIAN_TOKEN')     { addInfra('jira');       addCat('docs'); }
        if (/^ATLASSIAN_/.test(k))                           { addInfra('jira');       addCat('docs'); }
        if (/^SEQ_/.test(k))                                 { addInfra('seq');        addCat('observability'); }
        if (/^SLACK_/.test(k))                               { addInfra('slack');      addCat('communication'); }
        if (/^DISCORD_/.test(k))                             { addInfra('discord');    addCat('communication'); }
        if (/^(MAILGUN_|SENDGRID_|POSTMARK_)/.test(k))       { addInfra('email');      addCat('communication'); }
      }
    } catch {}
  }

  return {
    langs, dbs, infra, cats,
    keys: [...new Set(keys)],
    // Ordered strongest-first, so a report can lead with what the project
    // actually declares rather than with what an env var hinted at.
    signals: signals.sort((a, b) => b.confidence - a.confidence || a.value.localeCompare(b.value)),
  };
}

// ── DB matching ─────────────────────────────────────────────────────────────

const SIGNAL_TO_TOOLS = {
  // Databases
  postgres:    ['mcp-server-neon'],
  neon:        ['mcp-server-neon'],
  supabase:    ['supabase-mcp'],
  mongodb:     ['mongodb-mcp-server'],
  redis:       ['mcp-redis'],
  clickhouse:  ['mcp-clickhouse'],
  // Infra
  cloudflare:  ['mcp-server-cloudflare'],
  aws:         ['mcp-server-aws'],
  kubernetes:  ['mcp-server-kubernetes'],
  argocd:      ['argocd-mcp'],
  // VCS / project mgmt
  github:      ['github-mcp-server'],
  gitlab:      ['gitlab-mcp'],
  'azure-devops': ['@azure-devops/mcp'],
  linear:      ['linear-mcp-server'],
  notion:      ['notion-mcp-server'],
  atlassian:   ['mcp-atlassian'],
  jira:        ['mcp-atlassian'],
  // TODO: no DB entry for discord — skip mapping
  // TODO: no DB entry for seq — skip mapping
  // Observability
  sentry:      ['sentry-mcp'],
  dynatrace:   ['@dynatrace-oss/dynatrace-mcp-server'],
  // Payments / wallet
  stripe:      ['stripe-agent-toolkit'],
  phantom:     ['@phantom/mcp-server'],
  // CRM / sales / maps / testing
  salesforce:  ['@salesforce/mcp'],
  mapbox:      ['@mapbox/mcp-server'],
  browserstack:['@browserstack/mcp-server'],
  postman:     ['@postman/postman-mcp-server'],
  // CI / dev tools
  circleci:    ['@circleci/mcp-server-circleci'],
  // Communication
  slack:       ['slack-mcp-server'],
  // Newly imported in PR #22 — WO/infra stack gaps closed via discover.cjs
  teamcity:    ['teamcity-mcp'],
  prometheus:  ['prometheus-mcp'],
  datadog:     ['datadog-mcp'],
  terraform:   ['terraform-mcp-server'],
  kafka:       ['kafka-mcp-server'],
  mysql:       ['mcp-server-mysql'],
  // jenkins, helm, argocd-server, vault, loki, ansible, airflow — left
  // intentionally unmapped: no public MCP server passed the quality bar
  // (low stars, archived, or doesn't exist yet). Surfaced via discover hint.
};

// Always surface for any project (filesystem/memory/context7 are universally useful)
const UNIVERSAL_TOOLS = new Set(['mcp-server-filesystem', 'mcp-server-memory', 'context7']);

// SIGNAL_TO_TOOLS is hand-curated. As the DB grows, the map lags: new vendor
// servers (e.g. @mapbox/mcp-server, @salesforce/mcp) ship without anyone
// updating the map, and the matcher silently misses them. Fall back to a
// substring scan over name+notes when the map has nothing for a signal —
// covers the common case where the vendor's name is the signal.
function fallbackBySignal(db, signal) {
  const sig = signal.toLowerCase();
  const hits = [];
  for (const t of db.tools) {
    if (t.classification === 'Deprecated') continue;
    const hay = `${t.name} ${t.notes || ''}`.toLowerCase();
    if (hay.includes(sig)) hits.push(t.name);
  }
  return hits;
}

function matchDB(db, stack, query) {
  const names = new Set(UNIVERSAL_TOOLS);

  for (const signal of [...stack.dbs, ...stack.infra]) {
    const mapped = SIGNAL_TO_TOOLS[signal] || [];
    if (mapped.length) {
      for (const name of mapped) names.add(name);
    } else {
      // Curated map said nothing — try semantic fallback.
      for (const name of fallbackBySignal(db, signal)) names.add(name);
    }
  }

  if (query) {
    const q = query.toLowerCase();
    for (const t of db.tools) {
      const haystack = `${t.name} ${t.category} ${t.notes || ''}`.toLowerCase();
      if (haystack.includes(q)) names.add(t.name);
    }
  }

  return db.tools.filter(t => names.has(t.name) && t.classification !== 'Deprecated');
}

// For every stack signal, decide whether the DB actually had something
// specific to offer. Three failure modes:
//   1. signal in neither SIGNAL_TO_TOOLS nor fallback hits → "no mapping"
//   2. signal mapped, but referenced tool absent in DB     → "mapping → X (not in DB)"
//   3. signal in fallback (not curated map) → not unmapped, but
//      surfaced as a "fallback" record so a reviewer can promote it to
//      SIGNAL_TO_TOOLS if the heuristic is reliable.
// Returns one record per gap so the reporter can suggest
// `discover.cjs --query <signal>` per gap, and so JSON consumers can
// distinguish fallback-hit signals from curated ones.
function unmappedSignals(db, stack) {
  const dbNames = new Set(db.tools.map(t => t.name));
  const out     = [];
  for (const signal of [...stack.dbs, ...stack.infra]) {
    const mapped = SIGNAL_TO_TOOLS[signal] || [];
    if (mapped.length === 0) {
      const fb = fallbackBySignal(db, signal);
      if (fb.length === 0) {
        out.push({ signal, reason: 'no mapping' });
      } else {
        out.push({ signal, reason: `fallback → ${fb.join(', ')}`, fallback: fb });
      }
      continue;
    }
    const present = mapped.filter(n => dbNames.has(n));
    if (present.length === 0) {
      out.push({ signal, reason: `mapping → ${mapped.join(', ')} (not in DB)` });
    }
  }
  return out;
}

// ── Installed servers ───────────────────────────────────────────────────────

function getInstalled(cwd) {
  const result = {};

  // project .mcp.json
  try {
    const cfg = JSON.parse(fs.readFileSync(path.join(cwd, '.mcp.json'), 'utf8'));
    for (const k of Object.keys(cfg.mcpServers || {})) result[k] = 'project (.mcp.json)';
  } catch {}

  // global ~/.claude.json — keys only, never values
  try {
    const cfgPath = path.join(process.env.HOME || '', '.claude.json');
    const cfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
    for (const k of Object.keys(cfg.mcpServers || {})) {
      if (!result[k]) result[k] = 'global (~/.claude.json)';
    }
  } catch {}

  return result;
}

// ── Install: verify + write ─────────────────────────────────────────────────

function installTool(tool, cwd, global_) {
  process.stderr.write(`\nRunning integrity scan for ${tool.name}…\n`);

  // Scan this one entry and trust the exit code, instead of scraping the
  // report for lines that mention the tool. The old text match had two holes:
  // a `SKIP` line (registry unreachable, unparsable name) matched neither the
  // FAIL nor the WARN pattern and read as "nothing wrong", and an entry with
  // no `version` made `l.includes(tool.version || '')` true for *every* line,
  // so an unrelated entry's FAIL aborted this install.
  // --fail-unverified: for an install, "couldn't check" is a refusal.
  // --cwd matters: the policy file that applies is the one belonging to the
  // project we are about to write into, not the directory this process happens
  // to have been started from.
  const verifyArgs = [VERIFY_CJS, '--entry', tool.name, '--fail-unverified', '--cwd', cwd];
  if (OFFLINE) verifyArgs.push('--offline');
  if (STRICT)  verifyArgs.push('--strict');

  const res = spawnSync(process.execPath, verifyArgs, { encoding: 'utf8' });
  const out = `${res.stdout || ''}${res.stderr || ''}`;
  for (const l of out.split('\n')) {
    if (l.trim()) process.stderr.write(`  ${l}\n`);
  }

  if (res.error) {
    process.stderr.write(`\n${RD}ABORT: could not run the integrity gate: ${res.error.message}${RS}\n`);
    process.exit(1);
  }
  if (res.status !== 0) {
    process.stderr.write(`\n${RD}ABORT: integrity gate did not clear ${tool.name} (verify exit ${res.status}). Do not install.${RS}\n`);
    process.exit(1);
  }
  if (/^(WARN|HOOK)\b|\[(WARN|HOOK)\]/m.test(out)) {
    process.stderr.write(`\n${YL}WARN: review the issue above before proceeding.${RS}\n`);
  }

  // Build the server config entry
  const serverEntry = buildServerEntry(tool);

  const target = resolveTarget(HOST, SCOPE, { cwd });
  if (!target) {
    const hosts = listHosts().map((h) => `${h.id} (${h.scopes.join('/')})`).join(', ');
    process.stderr.write(`${RD}No such host/scope: ${HOST}/${SCOPE}.${RS}\nAvailable: ${hosts}\n`);
    process.exit(2);
  }

  const diff = JSON.stringify({ [target.key]: { [tool.name]: serverEntry } }, null, 2);
  process.stderr.write(`\nWill add to ${target.path} (${target.label}, ${SCOPE} scope):\n${DM}${diff}${RS}\n\n`);

  let result;
  try {
    result = writeServerEntry(target, tool.name, serverEntry);
  } catch (e) {
    process.stderr.write(`${RD}${e.message}${RS}\n`);
    process.exit(2);
  }

  if (result.action === 'manual') {
    // Codex keeps TOML. Rewriting it without a TOML parser would destroy
    // comments and formatting, so hand over the three correct lines instead.
    process.stdout.write(
      `${target.label} keeps its config in TOML (${target.path}).\n` +
      `Add this block yourself — mcp-vault does not rewrite TOML:\n\n${result.snippet}\n`
    );
    return;
  }

  if (result.replaced) process.stderr.write(`${YL}NOTE: ${tool.name} was already configured here — replaced.${RS}\n`);
  if (result.backup)   process.stderr.write(`Backup: ${result.backup}\n`);
  process.stdout.write(`Added ${tool.name} to ${result.path}\nRestart ${target.label} to pick up the new server.\n`);
}

// Pin the package token of an install command to the version the DB records —
// and that verify_integrity actually hashed.
//
// Most DB entries store the command unpinned (`npx -y @scope/mcp-server`) with
// the checked version in a separate `version` field. Copying that command into
// .mcp.json verbatim means npx resolves `latest` every time the server starts:
// the artifact that runs is not the artifact whose sha512 the gate compared, so
// a compromised release published after our last refresh installs itself
// silently. Synthesise the pin instead.
//
// Returns { parts, pinned, reason } — `parts` is the argv-style token list.
//
// "Pinned" means: the launch command names the exact version the gate verified.
// A command that already carries *some* specifier is not automatically fine —
// `pkg@latest`, `pkg@^1.2` and a stale `pkg@1.0.0` all launch something other
// than the artifact whose hash was compared, so they get rewritten to the DB's
// version rather than trusted.
// "Exact" has to mean exact. `1`, `1.2` and `1.x` all satisfied the old
// pattern, so `pinInstallCmd` happily produced `pkg@1.x` and called it pinned —
// a range dressed as a pin.
//   npm:  semver, three components, optional pre-release/build
//   PyPI: PEP 440 release segment, optional pre/post/dev/local
const EXACT_NPM_VERSION  = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const EXACT_PYPI_VERSION = /^\d+(?:\.\d+)*(?:(?:a|b|rc)\d+)?(?:\.post\d+)?(?:\.dev\d+)?(?:\+[0-9A-Za-z.]+)?$/;

function isExactVersion(runner, version) {
  if (typeof version !== 'string' || !version) return false;
  return runner === 'npx' ? EXACT_NPM_VERSION.test(version) : EXACT_PYPI_VERSION.test(version);
}

function pinInstallCmd(cmd, version) {
  const raw    = String(cmd).trim();
  const parts  = raw.split(/\s+/);
  const runner = parts[0];

  if (runner === 'docker') {
    // The image is the first non-flag token; a digest sitting in some other
    // argument (`-e REF=img@sha256:…`) is not a pin on the image that runs.
    const ref = dockerImageRef(raw);
    if (!ref) return { parts, pinned: false, reason: 'cannot parse the docker image reference' };
    const ok = dockerDigestPinned(ref);
    return { parts, pinned: ok, reason: ok ? null : `docker image ${ref} is not pinned by @sha256 digest` };
  }

  if (runner !== 'npx' && runner !== 'uvx') {
    return { parts, pinned: false, reason: `unknown runner "${runner}" — cannot pin` };
  }

  // Resolve the package with the gate's own parser: a command shaped in a way
  // the gate declines to check (flags before the package, --package, uvx
  // --from/--with) must not be pinnable here either.
  const pkg = runner === 'npx' ? npmPkgName(raw) : pypiPkgName(raw);
  if (!pkg) {
    return {
      parts, pinned: false,
      reason: runner === 'npx'
        ? 'not a plain `npx -y <pkg>` command — the gate cannot check it either'
        : 'not a plain `uvx <pkg>` command (--from / --with / flags) — the gate cannot check it either',
    };
  }

  const sep = runner === 'npx' ? '@' : '==';
  const idx = parts.findIndex((p) => p === pkg || p.startsWith(pkg + sep));
  if (idx === -1) return { parts, pinned: false, reason: 'cannot locate the package token in install_cmd' };

  const current = parts[idx] === pkg ? null : parts[idx].slice(pkg.length + sep.length);

  if (!version) {
    return {
      parts, pinned: false,
      reason: current
        ? `install_cmd asks for "${current}", but the DB entry has no verified \`version\` — run verify_integrity.cjs --update`
        : 'no `version` in the DB entry — run verify_integrity.cjs --update',
    };
  }
  if (!isExactVersion(runner, version)) {
    return {
      parts, pinned: false,
      reason: `DB version "${version}" is not an exact ${runner === 'npx' ? 'semver' : 'PEP 440'} version — a range is not a pin`,
    };
  }
  if (current === version) return { parts, pinned: true, reason: null };

  // Unpinned, or pinned to something the gate did not verify: rewrite it.
  const pinnedParts = [...parts];
  pinnedParts[idx] = `${pkg}${sep}${version}`;
  return { parts: pinnedParts, pinned: true, reason: null };
}

function buildServerEntry(tool) {
  const { parts, pinned, reason } = pinInstallCmd(tool.install_cmd, tool.version);

  if (!pinned) {
    if (!ALLOW_UNPINNED) {
      process.stderr.write(
        `\n${RD}ABORT: refusing to write an unpinned launch command for ${tool.name}.${RS}\n` +
        `  ${reason}\n` +
        `  The gate verifies a specific version; an unpinned command runs whatever\n` +
        `  the registry serves at startup. Pass --allow-unpinned to override.\n`
      );
      process.exit(1);
    }
    process.stderr.write(`\n${YL}WARN: writing an unpinned launch command (${reason}).${RS}\n`);
  }

  return { command: parts[0], args: parts.slice(1) };
}

// ── Behavioural results ────────────────────────────────────────────────────

// Behavioural results, read once. The eval has always recorded whether an
// entry can complete a handshake; until now nothing consulted it at the point
// a recommendation was printed, which is the one place it changes a decision.
let _evalIndex = null;
function evalIndex() {
  if (_evalIndex) return _evalIndex;
  _evalIndex = new Map();
  try {
    const doc = JSON.parse(fs.readFileSync(EVAL_PATH, 'utf8'));
    for (const r of doc.results || []) if (r && r.name) _evalIndex.set(r.name, r);
  } catch {
    /* no snapshot in this install: behaviour reads as 'unknown', which is the
       honest answer rather than a failure */
  }
  return _evalIndex;
}

function behaviourFor(name) {
  return behaviour(evalIndex().get(name) || null);
}

// ── Report formatting ───────────────────────────────────────────────────────

const HEAVY = 30;
const HR    = '─'.repeat(60);

// How a behavioural state reads in one glance, next to the entry it describes.
const BEHAVIOUR_TAG = {
  starts:              () => '',
  unknown:             () => '',
  'needs-credentials': () => `${YL}needs credentials${RS}`,
  'needs-network':     () => `${YL}needs network${RS}`,
  'never-started':     () => `${RD}never started${RS}`,
};

function printTool(t) {
  const heavy   = t.est_tools_count >= HEAVY;
  const toolTag = heavy
    ? `${YL}${t.est_tools_count} tools ⚠${RS}`
    : `${DM}${t.est_tools_count} tools${RS}`;
  const tier  = t.classification.padEnd(13);
  const name  = t.name.padEnd(26);
  const behav = behaviourFor(t.name);
  const tag   = (BEHAVIOUR_TAG[behav.state] || (() => ''))();
  process.stdout.write(`  ${B}${tier}${RS} ${name} ${toolTag}  ${DM}score ${t.health_score}${RS}${tag ? `  ${tag}` : ''}\n`);
  process.stdout.write(`  ${' '.repeat(13)}  ${DM}${t.install_cmd}${RS}\n`);
  if (heavy && t.toolsets) {
    process.stdout.write(`  ${' '.repeat(13)}  ${YL}→ ${t.toolsets}${RS}\n`);
  }
  // The reason, not just the label: "crashed" and "wants an API key" are
  // different amounts of work for whoever reads this.
  if (behav.state === 'never-started') {
    process.stdout.write(`  ${' '.repeat(13)}  ${DM}${behav.reason}${RS}\n`);
  }
}

function printReport(stack, matched, installed, db, unmapped) {
  // Stack line
  const parts = [];
  if (stack.langs.size)  parts.push(`Langs: ${[...stack.langs].join('/')}`);
  if (stack.dbs.size)    parts.push(`DB: ${[...stack.dbs].join(', ')}`);
  if (stack.infra.size)  parts.push(`Infra: ${[...stack.infra].join(', ')}`);
  if (stack.keys.length) parts.push(`Keys: ${stack.keys.slice(0, 6).join(', ')}${stack.keys.length > 6 ? '…' : ''}`);
  process.stdout.write(`\nStack: ${parts.join(' | ') || '(nothing detected)'}\n`);
  if (stack.cats.size)   process.stdout.write(`Needs: ${[...stack.cats].join(', ')}\n`);
  if (QUERY)             process.stdout.write(`Query: "${QUERY}"\n`);
  process.stdout.write('\n');

  const installedNames = new Set(Object.keys(installed));
  const normal = matched.filter(t => t.est_tools_count < HEAVY && !installedNames.has(t.name));
  const heavy  = matched.filter(t => t.est_tools_count >= HEAVY && !installedNames.has(t.name));

  if (normal.length) {
    process.stdout.write(`${B}── Recommended ${HR.slice(14)}${RS}\n`);
    for (const t of normal) printTool(t);
    process.stdout.write('\n');
  }

  if (heavy.length) {
    process.stdout.write(`${B}── Heavy — scope before global install ${HR.slice(38)}${RS}\n`);
    for (const t of heavy) printTool(t);
    process.stdout.write('\n');
  }

  if (Object.keys(installed).length) {
    process.stdout.write(`${B}── Already installed ${HR.slice(20)}${RS}\n`);
    for (const [name, src] of Object.entries(installed)) {
      process.stdout.write(`  ${GN}✓${RS} ${name.padEnd(28)} ${DM}${src}${RS}\n`);
    }
    process.stdout.write('\n');
  }

  // Integrity summary from DB fields
  const matchedVerified  = matched.filter(t => t.trust === 'verified').length;
  const matchedCandidate = matched.filter(t => t.trust === 'candidate').length;
  const dates = matched.map(t => t.last_checked).filter(Boolean).sort();
  const oldest = dates[0] || 'unknown';

  process.stdout.write(`${B}── Integrity (DB snapshot) ${HR.slice(26)}${RS}\n`);
  process.stdout.write(`  Matched: ${GN}${matchedVerified} verified${RS}`);
  if (matchedCandidate) process.stdout.write(`  ${YL}${matchedCandidate} candidate${RS} (install with ⚠)`);
  process.stdout.write(`\n  DB last refreshed: ${oldest}\n`);
  process.stdout.write(`  ${DM}Full scan: node scripts/verify_integrity.cjs${RS}\n\n`);

  // Coverage gaps: stack signals the DB has nothing specific for. UNIVERSAL_TOOLS
  // are always added by matchDB, so a non-empty `matched` doesn't imply we
  // actually answered the user's stack — we may have silently fallen back to
  // universals. Surface that explicitly so the user knows whether to trust
  // the recommendation or escape into discovery.
  const matchedSpecific = matched.filter(t => !UNIVERSAL_TOOLS.has(t.name) && !installedNames.has(t.name));
  const fallbackHits = unmapped.filter(u => u.fallback);
  const trueGaps     = unmapped.filter(u => !u.fallback);

  if (fallbackHits.length) {
    process.stdout.write(`${B}── Signals matched via fallback (curated map missing) ${HR.slice(53)}${RS}\n`);
    for (const u of fallbackHits) {
      process.stdout.write(`  ${DM}·${RS} ${u.signal.padEnd(14)} ${DM}→ ${u.fallback.join(', ')}${RS}\n`);
    }
    process.stdout.write(`  ${DM}Promote to SIGNAL_TO_TOOLS if reliable; surfaced here so curated overrides stay honest.${RS}\n\n`);
  }

  if (trueGaps.length) {
    process.stdout.write(`${B}── Stack signals without a specific DB match ${HR.slice(45)}${RS}\n`);
    for (const u of trueGaps) {
      process.stdout.write(`  ${YL}·${RS} ${u.signal.padEnd(14)} ${DM}${u.reason}${RS}\n`);
      process.stdout.write(`    ${DM}→ try: node scripts/discover.cjs --source npm --query ${u.signal}${RS}\n`);
    }
    if (matchedSpecific.length === 0) {
      process.stdout.write(`\n  ${YL}Note:${RS} the entries above under "Recommended" are general-purpose universals,\n`);
      process.stdout.write(`  not stack-specific matches. Run discover.cjs to fill the gap.\n`);
    }
    process.stdout.write('\n');
  }

  process.stdout.write(`${DM}Install: node scripts/orchestrate.cjs --install <name> [--global]${RS}\n\n`);
}

// ── Main ────────────────────────────────────────────────────────────────────

if (require.main === module) {
  if (argv.includes('--list-hosts')) {
    for (const h of listHosts()) {
      process.stdout.write(`${h.id.padEnd(16)} ${h.label.padEnd(16)} scopes: ${h.scopes.join(', ').padEnd(14)} ${h.format === 'toml' ? '(snippet only — TOML config)' : ''}\n`);
    }
    // `return` as well as the exit: exitAfterFlush() queues the exit behind a
    // stdout drain, so execution would otherwise carry on into the scan.
    return exitAfterFlush(0);
  }

  const db        = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  const stack     = detectStack(CWD);
  const matched   = matchDB(db, stack, QUERY);
  const unmapped  = unmappedSignals(db, stack);
  const installed = getInstalled(CWD);

  // -- install mode --
  if (INSTALL) {
    const tool = db.tools.find(t => t.name === INSTALL);
    if (!tool) {
      process.stderr.write(`${RD}Tool not found in DB: "${INSTALL}"${RS}\n`);
      process.stderr.write(`Known names: ${db.tools.map(t => t.name).join(', ')}\n`);
      process.exit(2);
    }
    installTool(tool, CWD, GLOBAL);
    process.exit(0);
  }

  // -- json mode --
  if (AS_JSON) {
    process.stdout.write(JSON.stringify({
      stack: {
        langs:      [...stack.langs],
        dbs:        [...stack.dbs],
        infra:      [...stack.infra],
        categories: [...stack.cats],
        keys:       stack.keys.slice(0, 20),
        // Each signal with where it came from and how much it implies, so a
        // recommendation can be explained rather than asserted.
        signals:    stack.signals,
        unmapped_signals: unmapped,
      },
      recommended: matched.filter(t => t.est_tools_count < HEAVY).map(t => slim(t, stack)),
      heavy:       matched.filter(t => t.est_tools_count >= HEAVY).map(t => slim(t, stack)),
      installed,
      db_entry_count: db.tools.length,
    }, null, 2) + '\n');
    // `return` matters: exitAfterFlush() is asynchronous, so execution would
    // otherwise fall through to printReport() and append a human-readable
    // report after the JSON document.
    return exitAfterFlush(0);
  }

  // -- default: human-readable report --
  printReport(stack, matched, installed, db, unmapped);
}

module.exports = {
  detectStack,
  slim,
  behaviourFor,
  matchDB,
  unmappedSignals,
  fallbackBySignal,
  pinInstallCmd,
  isExactVersion,
  SIGNAL_TO_TOOLS,
  UNIVERSAL_TOOLS,
};

function slim(t, stack = null) {
  // health / trust / fit, kept apart on purpose: health says the project is
  // maintained, trust says we know which bytes we would run, fit says this
  // project has a use for it. A recommendation is a policy over the three —
  // trust gates, the others rank — so popularity cannot outvote a bad pin.
  // Evidence only counts for the artifact it was collected on. Bumping
  // `version` while leaving `trust_evidence` in place otherwise carries the old
  // release's verdict onto a version nothing has checked.
  const typed = toTypedEntry(t);
  const currentId = typed ? artifactId(typed.artifact) : null;
  const evidence = t.trust_evidence
    && (!t.trust_evidence.artifact_id || !currentId || t.trust_evidence.artifact_id === currentId)
    ? t.trust_evidence
    : null;
  const trust = trustScore(evidence);
  if (t.trust_evidence && !evidence) {
    trust.reasons.unshift(`stored evidence describes ${t.trust_evidence.artifact_id}, not ${currentId} — ignored`);
  }
  const fit   = stack ? fitScore(t, stack, { signalToTools: SIGNAL_TO_TOOLS, universal: UNIVERSAL_TOOLS }) : null;
  const behav = behaviourFor(t.name);
  return {
    name:            t.name,
    category:        t.category,
    classification:  t.classification,
    health_score:    t.health_score,
    est_tools_count: t.est_tools_count,
    toolsets:        t.toolsets,
    trust:           t.trust,
    install_cmd:     t.install_cmd,
    last_checked:    t.last_checked,
    scores: {
      health: Number.isFinite(t.health_score) ? t.health_score : null,
      trust:  { score: trust.score, gate: trust.gate, reasons: trust.reasons.slice(0, 4) },
      fit:    fit ? { score: fit.score, reasons: fit.reasons.slice(0, 4) } : null,
      // Behaviour is reported next to the scores rather than folded into one
      // of them: "it does not start" is not a trust finding and not a fit
      // penalty, it is a different kind of fact.
      behaviour: { state: behav.state, tools: behav.tools, reason: behav.reason },
      recommendation: recommend({ trust, health: t.health_score, fit, behaviour: behav }),
    },
  };
}
