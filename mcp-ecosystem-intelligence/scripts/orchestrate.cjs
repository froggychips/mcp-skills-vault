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

  // docker-compose.yml
  try {
    const txt = fs.readFileSync(path.join(cwd, 'docker-compose.yml'), 'utf8').toLowerCase();
    if (/image:\s*(postgres|pg[^s])/.test(txt))     { dbs.add('postgres');   cats.add('database'); }
    if (/image:\s*(mysql|mariadb)/.test(txt))        { dbs.add('mysql');      cats.add('database'); }
    if (/image:\s*mongo/.test(txt))                  { dbs.add('mongodb');    cats.add('database'); }
    if (/image:\s*redis/.test(txt))                  { dbs.add('redis');      cats.add('database'); }
    if (/clickhouse/.test(txt))                      { dbs.add('clickhouse'); cats.add('database'); }
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
      }
    } catch {}
  }

  return { langs, dbs, infra, cats, keys: [...new Set(keys)] };
}

// ── DB matching ─────────────────────────────────────────────────────────────

const SIGNAL_TO_TOOLS = {
  postgres:   ['mcp-server-neon'],
  neon:       ['mcp-server-neon'],
  supabase:   ['supabase-mcp'],
  mongodb:    ['mongodb-mcp-server'],
  redis:      ['mcp-redis'],
  clickhouse: ['mcp-clickhouse'],
  github:     ['github-mcp-server'],
  gitlab:     ['gitlab-mcp'],
  linear:     ['linear-mcp-server'],
  notion:     ['notion-mcp-server'],
  sentry:     ['sentry-mcp'],
  stripe:     ['stripe-agent-toolkit'],
  cloudflare: ['mcp-server-cloudflare'],
  aws:        ['mcp-server-aws'],
  kubernetes: ['mcp-server-kubernetes'],
};

// Always surface for any project (filesystem/memory/context7 are universally useful)
const UNIVERSAL_TOOLS = new Set(['mcp-server-filesystem', 'mcp-server-memory', 'context7']);

function matchDB(db, stack, query) {
  const names = new Set(UNIVERSAL_TOOLS);

  for (const signal of [...stack.dbs, ...stack.infra]) {
    for (const name of (SIGNAL_TO_TOOLS[signal] || [])) names.add(name);
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
// specific to offer. Two failure modes:
//   1. signal not in SIGNAL_TO_TOOLS at all       → reason: "no mapping"
//   2. mapped, but referenced tool missing in DB  → reason: "mapping references unknown DB entry"
// Returns one record per unmapped signal so the reporter can suggest
// `discover.cjs --query <signal>` per gap.
function unmappedSignals(db, stack) {
  const dbNames = new Set(db.tools.map(t => t.name));
  const out     = [];
  for (const signal of [...stack.dbs, ...stack.infra]) {
    const mapped = SIGNAL_TO_TOOLS[signal] || [];
    if (mapped.length === 0) {
      out.push({ signal, reason: 'no mapping' });
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

  const res = spawnSync('node', [VERIFY_CJS], { encoding: 'utf8' });
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
  if (unmapped.length) {
    process.stdout.write(`${B}── Stack signals without a specific DB match ${HR.slice(45)}${RS}\n`);
    for (const u of unmapped) {
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
