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
const { execSync, spawnSync } = require('child_process');

const DB_PATH    = path.resolve(__dirname, '../assets/tools_database.json');
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
  const langs  = new Set();
  const dbs    = new Set();
  const infra  = new Set();
  const cats   = new Set();
  const keys   = [];

  // package.json
  try {
    const pkg  = JSON.parse(fs.readFileSync(path.join(cwd, 'package.json'), 'utf8'));
    const deps = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies });
    langs.add('Node');
    if (deps.some(d => ['next','react','remix','nuxt','vue','svelte'].includes(d))) langs.add('Next.js/React');
    if (deps.some(d => ['express','fastify','koa','hono'].includes(d)))             langs.add('Node HTTP');
    if (deps.some(d => d === 'pg' || d === 'postgres' || d.includes('prisma') || d.includes('sequelize') || d === 'knex')) { dbs.add('postgres'); cats.add('database'); }
    if (deps.some(d => d === 'mongoose' || d.includes('mongodb') || d === '@typegoose/typegoose')) { dbs.add('mongodb');  cats.add('database'); }
    if (deps.some(d => d === 'redis' || d === 'ioredis' || d === '@upstash/redis'))  { dbs.add('redis');    cats.add('database'); }
    if (deps.some(d => d.includes('clickhouse')))                                    { dbs.add('clickhouse'); cats.add('database'); }
    if (deps.some(d => d.includes('stripe')))                                        { infra.add('stripe');     cats.add('payments'); }
    if (deps.some(d => d.includes('@sentry')))                                       { infra.add('sentry');     cats.add('observability'); }
    if (deps.some(d => d.includes('cloudflare') || d === 'wrangler'))                { infra.add('cloudflare'); cats.add('infra'); }
    if (deps.some(d => d.startsWith('@aws-sdk') || d === 'aws-sdk'))                 { infra.add('aws');        cats.add('infra'); }
    if (deps.some(d => d.includes('@kubernetes') || d === 'kubernetes-client'))      { infra.add('kubernetes'); cats.add('infra'); }
  } catch { /* no package.json */ }

  // pyproject.toml / requirements.txt
  for (const f of ['pyproject.toml', 'requirements.txt']) {
    try {
      const txt = fs.readFileSync(path.join(cwd, f), 'utf8').toLowerCase();
      langs.add('Python');
      if (/psycopg2|sqlalchemy|asyncpg|databases/.test(txt)) { dbs.add('postgres');   cats.add('database'); }
      if (/pymongo|motor/.test(txt))                          { dbs.add('mongodb');    cats.add('database'); }
      if (/\bredis\b/.test(txt))                              { dbs.add('redis');      cats.add('database'); }
      if (/clickhouse/.test(txt))                             { dbs.add('clickhouse'); cats.add('database'); }
      if (/boto3|aiobotocore/.test(txt))                      { infra.add('aws');        cats.add('infra'); }
      if (/\bstripe\b/.test(txt))                             { infra.add('stripe');     cats.add('payments'); }
      if (/\bsentry\b/.test(txt))                             { infra.add('sentry');     cats.add('observability'); }
    } catch {}
  }

  // go.mod / Cargo.toml
  if (fs.existsSync(path.join(cwd, 'go.mod')))    langs.add('Go');
  if (fs.existsSync(path.join(cwd, 'Cargo.toml'))) langs.add('Rust');

  // Swift — Package.swift (SwiftPM) or Project.swift (Tuist)
  if (fs.existsSync(path.join(cwd, 'Package.swift')))  langs.add('swift');
  if (fs.existsSync(path.join(cwd, 'Project.swift')))  langs.add('swift');

  // JVM — pom.xml / build.gradle / build.gradle.kts. Dep parsing skipped:
  // pom.xml is XML, build.gradle is Groovy/Kotlin DSL — out of scope here.
  if (fs.existsSync(path.join(cwd, 'pom.xml')))             langs.add('jvm');
  if (fs.existsSync(path.join(cwd, 'build.gradle')))        langs.add('jvm');
  if (fs.existsSync(path.join(cwd, 'build.gradle.kts')))    langs.add('jvm');

  // Ruby — Gemfile (preferred) with line-by-line gem scan; Gemfile.lock fallback.
  for (const f of ['Gemfile', 'Gemfile.lock']) {
    try {
      const txt = fs.readFileSync(path.join(cwd, f), 'utf8');
      langs.add('ruby');
      // Simple string-contains lookup — no real parser. Matches both
      // `gem "pg"` and Gemfile.lock dependency lines.
      if (/\bpg\b/.test(txt))         { dbs.add('postgres');   cats.add('database'); }
      if (/\bmysql2\b/.test(txt))     { dbs.add('mysql');      cats.add('database'); }
      if (/\bredis\b/.test(txt))      { dbs.add('redis');      cats.add('database'); }
      if (/\bmongo\b/.test(txt))      { dbs.add('mongodb');    cats.add('database'); }
      if (/\bdalli\b/.test(txt))      { infra.add('memcached'); cats.add('database'); }
      if (/\baws-sdk\b/.test(txt))    { infra.add('aws');      cats.add('infra'); }
      break; // Gemfile wins over Gemfile.lock — don't double-scan.
    } catch {}
  }

  // PHP — composer.json with JSON `require` map scan.
  try {
    const composer = JSON.parse(fs.readFileSync(path.join(cwd, 'composer.json'), 'utf8'));
    langs.add('php');
    const req = { ...(composer.require || {}), ...(composer['require-dev'] || {}) };
    const reqKeys = Object.keys(req);
    if (reqKeys.some(k => k === 'mongodb/mongodb' || k.startsWith('mongodb/')))    { dbs.add('mongodb');  cats.add('database'); }
    if (reqKeys.some(k => k === 'predis/predis' || k.startsWith('predis/')))       { dbs.add('redis');    cats.add('database'); }
    if (reqKeys.some(k => k.startsWith('aws/aws-sdk-php')))                         { infra.add('aws');    cats.add('infra'); }
    if (reqKeys.some(k => k === 'firebase/php-jwt'))                                { /* auth dep, no MCP signal */ }
    if (reqKeys.some(k => k.startsWith('stripe/')))                                 { infra.add('stripe'); cats.add('payments'); }
    if (reqKeys.some(k => k.startsWith('sentry/')))                                 { infra.add('sentry'); cats.add('observability'); }
  } catch { /* no composer.json or invalid JSON */ }

  // .NET — *.csproj / *.sln. Skip parsing; flag the language only.
  try {
    const entries = fs.readdirSync(cwd);
    if (entries.some(f => f.endsWith('.csproj') || f.endsWith('.sln'))) langs.add('dotnet');
  } catch {}

  // Elixir — mix.exs. Skip dep parsing (Elixir DSL).
  if (fs.existsSync(path.join(cwd, 'mix.exs'))) langs.add('elixir');

  // docker-compose.yml
  try {
    const txt = fs.readFileSync(path.join(cwd, 'docker-compose.yml'), 'utf8').toLowerCase();
    if (/image:\s*(postgres|pg[^s])/.test(txt))     { dbs.add('postgres');   cats.add('database'); }
    if (/image:\s*(mysql|mariadb)/.test(txt))        { dbs.add('mysql');      cats.add('database'); }
    if (/image:\s*mongo/.test(txt))                  { dbs.add('mongodb');    cats.add('database'); }
    if (/image:\s*redis/.test(txt))                  { dbs.add('redis');      cats.add('database'); }
    if (/clickhouse/.test(txt))                      { dbs.add('clickhouse'); cats.add('database'); }
    if (/image:\s*(confluentinc\/|bitnami\/kafka|apache\/kafka)/.test(txt)) { infra.add('kafka');      cats.add('streaming'); }
    if (/image:\s*(prom\/prometheus|prometheus)/.test(txt))                 { infra.add('prometheus'); cats.add('observability'); }
    if (/image:\s*grafana/.test(txt))                                       { infra.add('grafana');    cats.add('observability'); }
    if (/image:\s*grafana\/loki/.test(txt))                                 { infra.add('loki');       cats.add('observability'); }
    if (/image:\s*nginx/.test(txt))                                         { infra.add('nginx');      cats.add('infra'); }
    if (/image:\s*hashicorp\/vault/.test(txt))                              { infra.add('vault');      cats.add('infra'); }
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
  for (const [paths, signal, cat] of fileSignals) {
    if (paths.some(p => fs.existsSync(path.join(cwd, p)))) {
      infra.add(signal); cats.add(cat);
    }
  }

  // Surface .tf files anywhere in the repo root as a terraform signal
  // (covers projects that don't put them in a dedicated dir).
  try {
    if (fs.readdirSync(cwd).some(f => f.endsWith('.tf'))) { infra.add('terraform'); cats.add('infra'); }
  } catch {}

  // .env / .env.example / .env.local — key names only, never values
  for (const f of ['.env.example', '.env.local', '.env']) {
    try {
      for (const line of fs.readFileSync(path.join(cwd, f), 'utf8').split('\n')) {
        const m = line.match(/^([A-Z][A-Z0-9_]{2,})\s*=/);
        if (!m) continue;
        const k = m[1];
        keys.push(k);
        if (/^GITHUB_/.test(k))                              { infra.add('github');     cats.add('vcs'); }
        if (/^GITLAB_/.test(k))                              { infra.add('gitlab');     cats.add('vcs'); }
        if (/^LINEAR_/.test(k))                              { infra.add('linear');     cats.add('pm'); }
        if (/^NOTION_/.test(k))                              { infra.add('notion');     cats.add('docs'); }
        if (/^SENTRY_/.test(k))                              { infra.add('sentry');     cats.add('observability'); }
        if (/^STRIPE_/.test(k))                              { infra.add('stripe');     cats.add('payments'); }
        if (/^SUPABASE_/.test(k))                            { dbs.add('supabase');     cats.add('database'); }
        if (/^NEON_/.test(k) || k === 'NEON_DATABASE_URL')  { dbs.add('neon');         cats.add('database'); }
        if (/^(CLOUDFLARE_|CF_API_TOKEN)/.test(k))          { infra.add('cloudflare'); cats.add('infra'); }
        if (/^AWS_/.test(k))                                 { infra.add('aws');        cats.add('infra'); }
        if (/^MONGO/.test(k))                                { dbs.add('mongodb');      cats.add('database'); }
        if (/^CLICKHOUSE_/.test(k))                          { dbs.add('clickhouse');   cats.add('database'); }
        if (/^(KUBE_|KUBERNETES_)/.test(k))                  { infra.add('kubernetes'); cats.add('infra'); }
        if (/^(MYSQL_|MARIADB_)/.test(k))                    { dbs.add('mysql');        cats.add('database'); }
        if (/^(PG_|POSTGRES_|POSTGRESQL_)/.test(k))          { dbs.add('postgres');     cats.add('database'); }
        if (/^(TEAMCITY_|TC_(URL|TOKEN|API))/.test(k))       { infra.add('teamcity');   cats.add('ci-cd'); }
        if (/^(CIRCLECI_|CIRCLE_)/.test(k))                  { infra.add('circleci');   cats.add('ci-cd'); }
        if (/^JENKINS_/.test(k))                             { infra.add('jenkins');    cats.add('ci-cd'); }
        if (/^(ARGOCD_|ARGO_)/.test(k))                      { infra.add('argocd');     cats.add('infra'); }
        if (/^HELM_/.test(k))                                { infra.add('helm');       cats.add('infra'); }
        if (/^(TERRAFORM_|TF_(VAR|CLI))/.test(k))            { infra.add('terraform');  cats.add('infra'); }
        if (/^VAULT_(ADDR|TOKEN|NAMESPACE)/.test(k))         { infra.add('vault');      cats.add('infra'); }
        if (/^PROMETHEUS_/.test(k))                          { infra.add('prometheus'); cats.add('observability'); }
        if (/^GRAFANA_/.test(k))                             { infra.add('grafana');    cats.add('observability'); }
        if (/^LOKI_/.test(k))                                { infra.add('loki');       cats.add('observability'); }
        if (/^DATADOG_/.test(k))                             { infra.add('datadog');    cats.add('observability'); }
        if (/^DYNATRACE_/.test(k))                           { infra.add('dynatrace');  cats.add('observability'); }
        if (/^NEWRELIC_/.test(k))                            { infra.add('newrelic');   cats.add('observability'); }
        if (/^KAFKA_/.test(k))                               { infra.add('kafka');      cats.add('streaming'); }
        if (/^(SALESFORCE_|SFDC_)/.test(k))                  { infra.add('salesforce'); cats.add('crm'); }
        if (/^MAPBOX_/.test(k))                              { infra.add('mapbox');     cats.add('maps'); }
        if (/^BROWSERSTACK_/.test(k))                        { infra.add('browserstack');cats.add('browser'); }
        if (/^POSTMAN_/.test(k))                             { infra.add('postman');    cats.add('testing'); }
        if (/^(AZURE_DEVOPS_|ADO_)/.test(k))                 { infra.add('azure-devops');cats.add('vcs'); }
        if (/^(JIRA_|CONFLUENCE_|ATLASSIAN_)/.test(k))       { infra.add('atlassian');  cats.add('pm'); }
        // Jira/Confluence are both served by mcp-atlassian. Keep the
        // 'atlassian' signal above for back-compat and add 'jira' →
        // 'docs' so docs-oriented callers find the same server.
        if (/^JIRA_/.test(k) || k === 'ATLASSIAN_TOKEN')     { infra.add('jira');       cats.add('docs'); }
        if (/^ATLASSIAN_/.test(k))                           { infra.add('jira');       cats.add('docs'); }
        if (/^SEQ_/.test(k))                                 { infra.add('seq');        cats.add('observability'); }
        if (/^SLACK_/.test(k))                               { infra.add('slack');      cats.add('communication'); }
        if (/^DISCORD_/.test(k))                             { infra.add('discord');    cats.add('communication'); }
        if (/^(MAILGUN_|SENDGRID_|POSTMARK_)/.test(k))       { infra.add('email');      cats.add('communication'); }
      }
    } catch {}
  }

  return { langs, dbs, infra, cats, keys: [...new Set(keys)] };
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

  const verifyArgs = OFFLINE ? [VERIFY_CJS, '--no-audit'] : [VERIFY_CJS];
  const res = spawnSync('node', verifyArgs, { encoding: 'utf8' });
  const out  = res.stdout + res.stderr;

  // Find this tool's line in the output
  const toolLines = out.split('\n').filter(l => l.includes(tool.name) || l.includes(tool.version || ''));
  const isFail    = toolLines.some(l => /^(FAIL|CVE)\b/.test(l));
  const isWarn    = toolLines.some(l => /^(WARN|HOOK)\b/.test(l));

  if (toolLines.length) {
    for (const l of toolLines) process.stderr.write(`  ${l}\n`);
  } else {
    process.stderr.write(`  (no integrity entry for ${tool.name} — MISS)\n`);
  }

  if (isFail) {
    process.stderr.write(`\n${RD}ABORT: integrity check failed for ${tool.name}. Do not install.${RS}\n`);
    process.exit(1);
  }

  if (isWarn) {
    process.stderr.write(`\n${YL}WARN: review the issue above before proceeding.${RS}\n`);
  }

  // Build the server config entry
  const serverEntry = buildServerEntry(tool);

  if (global_) {
    writeGlobal(tool.name, serverEntry);
  } else {
    writeProjectMcp(cwd, tool.name, serverEntry);
  }
}

function buildServerEntry(tool) {
  // Parse install_cmd into command + args
  const cmd = tool.install_cmd.trim();

  if (cmd.startsWith('docker ')) {
    // docker run -i --rm … <image>
    const parts = cmd.split(/\s+/);
    return { command: 'docker', args: parts.slice(1) };
  }

  if (cmd.startsWith('npx ')) {
    // npx -y <pkg>[@ver] [extra args]
    const parts = cmd.split(/\s+/);
    return { command: 'npx', args: parts.slice(1) };
  }

  if (cmd.startsWith('uvx ')) {
    const parts = cmd.split(/\s+/);
    return { command: 'uvx', args: parts.slice(1) };
  }

  // fallback
  const parts = cmd.split(/\s+/);
  return { command: parts[0], args: parts.slice(1) };
}

function writeProjectMcp(cwd, serverName, entry) {
  const mcpPath = path.join(cwd, '.mcp.json');
  let cfg = {};
  try { cfg = JSON.parse(fs.readFileSync(mcpPath, 'utf8')); } catch {}
  cfg.mcpServers = cfg.mcpServers || {};

  if (cfg.mcpServers[serverName]) {
    process.stderr.write(`\n${YL}NOTE: ${serverName} already in .mcp.json — overwriting.${RS}\n`);
  }

  cfg.mcpServers[serverName] = entry;

  const diff = JSON.stringify({ mcpServers: { [serverName]: entry } }, null, 2);
  process.stderr.write(`\nWill add to ${mcpPath}:\n${DM}${diff}${RS}\n\n`);

  fs.writeFileSync(mcpPath, JSON.stringify(cfg, null, 2) + '\n');
  process.stdout.write(`Added ${serverName} to .mcp.json\nRestart Claude Code to pick up the new server.\n`);
}

function writeGlobal(serverName, entry) {
  const cfgPath = path.join(process.env.HOME || '', '.claude.json');
  let cfg = {};
  try { cfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8')); } catch {
    process.stderr.write(`${RD}~/.claude.json not found — cannot write global config.${RS}\n`);
    process.exit(2);
  }

  // backup
  const bak = cfgPath + `.bak.${Date.now()}`;
  fs.copyFileSync(cfgPath, bak);
  process.stderr.write(`Backup: ${bak}\n`);

  cfg.mcpServers = cfg.mcpServers || {};
  cfg.mcpServers[serverName] = entry;

  fs.writeFileSync(cfgPath, JSON.stringify(cfg, null, 2) + '\n');
  process.stdout.write(`Added ${serverName} to ~/.claude.json\nRestart Claude Code to pick up the new server.\n`);
}

// ── Report formatting ───────────────────────────────────────────────────────

const HEAVY = 30;
const HR    = '─'.repeat(60);

function printTool(t) {
  const heavy   = t.est_tools_count >= HEAVY;
  const toolTag = heavy
    ? `${YL}${t.est_tools_count} tools ⚠${RS}`
    : `${DM}${t.est_tools_count} tools${RS}`;
  const tier  = t.classification.padEnd(13);
  const name  = t.name.padEnd(26);
  process.stdout.write(`  ${B}${tier}${RS} ${name} ${toolTag}  ${DM}score ${t.health_score}${RS}\n`);
  process.stdout.write(`  ${' '.repeat(13)}  ${DM}${t.install_cmd}${RS}\n`);
  if (heavy && t.toolsets) {
    process.stdout.write(`  ${' '.repeat(13)}  ${YL}→ ${t.toolsets}${RS}\n`);
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
        unmapped_signals: unmapped,
      },
      recommended: matched.filter(t => t.est_tools_count < HEAVY).map(slim),
      heavy:       matched.filter(t => t.est_tools_count >= HEAVY).map(slim),
      installed,
      db_entry_count: db.tools.length,
    }, null, 2) + '\n');
    process.exit(0);
  }

  // -- default: human-readable report --
  printReport(stack, matched, installed, db, unmapped);
}

module.exports = {
  detectStack,
  matchDB,
  unmappedSignals,
  fallbackBySignal,
  SIGNAL_TO_TOOLS,
  UNIVERSAL_TOOLS,
};

function slim(t) {
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
  };
}
