#!/usr/bin/env node
// list_entries.cjs — print every server in tools_database.json with filters.
// Closes the "I don't know what's in the DB" gap before `install`.
//
// Usage:
//   node scripts/list_entries.cjs                                # all
//   node scripts/list_entries.cjs --category database
//   node scripts/list_entries.cjs --tier Core
//   node scripts/list_entries.cjs --trust verified
//   node scripts/list_entries.cjs --query github                 # name substring
//   node scripts/list_entries.cjs --json
//
// Exit codes:
//   0  any rows printed (or --json with empty result)
//   2  bad invocation

"use strict";

const fs   = require("fs");
const path = require("path");

const DB_PATH = path.join(
  __dirname, "..", "assets", "tools_database.json"
);

function argVal(flag) {
  const i = process.argv.indexOf(flag);
  return i > -1 ? process.argv[i + 1] : null;
}
const argv     = process.argv.slice(2);
const CATEGORY = argVal("--category");
const TIER     = argVal("--tier");      // Core | Recommended | Experimental | Deprecated
const TRUST    = argVal("--trust");     // verified | candidate
const QUERY    = argVal("--query");     // substring on .name
const AS_JSON  = argv.includes("--json");
const HELP     = argv.includes("--help") || argv.includes("-h");

if (HELP) {
  process.stdout.write(`mcp-vault list — show every server in the vault DB.

USAGE
  mcp-vault list [--category <c>] [--tier <t>] [--trust <t>] [--query <s>] [--json]

FILTERS
  --category <c>   browser, database, search, infra, observability, ...
  --tier <t>       Core | Recommended | Experimental | Deprecated
  --trust <t>      verified | candidate
  --query <s>      substring on entry name (case-insensitive)
  --json           machine-readable output

EXAMPLES
  mcp-vault list
  mcp-vault list --category database
  mcp-vault list --tier Core --trust verified
  mcp-vault list --query github
`);
  process.exit(0);
}

let db;
try {
  db = JSON.parse(fs.readFileSync(DB_PATH, "utf8"));
} catch (e) {
  process.stderr.write(`list: cannot read DB at ${DB_PATH}: ${e.message}\n`);
  process.exit(2);
}

let rows = Array.isArray(db?.tools) ? db.tools.slice() : [];

if (CATEGORY) rows = rows.filter(r => r.category === CATEGORY);
if (TIER)     rows = rows.filter(r => r.classification === TIER);
if (TRUST)    rows = rows.filter(r => r.trust === TRUST);
if (QUERY) {
  const q = QUERY.toLowerCase();
  rows = rows.filter(r => (r.name || "").toLowerCase().includes(q));
}

// Stable sort: tier order, then score desc, then name asc.
const TIER_ORDER = { Core: 0, Recommended: 1, Experimental: 2, Deprecated: 3 };
rows.sort((a, b) => {
  const ta = TIER_ORDER[a.classification] ?? 9;
  const tb = TIER_ORDER[b.classification] ?? 9;
  if (ta !== tb) return ta - tb;
  const sa = a.health_score ?? 0;
  const sb = b.health_score ?? 0;
  if (sa !== sb) return sb - sa;
  return (a.name || "").localeCompare(b.name || "");
});

if (AS_JSON) {
  process.stdout.write(JSON.stringify({
    filters: { category: CATEGORY, tier: TIER, trust: TRUST, query: QUERY },
    count: rows.length,
    entries: rows.map(r => ({
      name:           r.name,
      category:       r.category,
      classification: r.classification,
      trust:          r.trust,
      est_tools_count: r.est_tools_count,
      install_cmd:    r.install_cmd,
      license:        r.license,
      health_score:   r.health_score,
    })),
  }, null, 2));
  process.stdout.write("\n");
  process.exit(0);
}

// Pretty table — terminal-friendly, no ANSI to keep --json pipeable separately.
if (rows.length === 0) {
  process.stdout.write("No entries match the given filters.\n");
  process.exit(0);
}

const fmt = (s, w) => String(s ?? "").padEnd(w).slice(0, w);
const summary = [
  CATEGORY && `category=${CATEGORY}`,
  TIER && `tier=${TIER}`,
  TRUST && `trust=${TRUST}`,
  QUERY && `query=${QUERY}`,
].filter(Boolean).join(" ");

process.stdout.write(
  `${rows.length} entries${summary ? ` (${summary})` : ""}\n\n`
);
process.stdout.write(
  `${fmt("NAME", 32)} ${fmt("CATEGORY", 14)} ${fmt("TIER", 13)} ` +
  `${fmt("TRUST", 10)} ${fmt("TOOLS", 6)} INSTALL\n`
);
process.stdout.write(
  `${"-".repeat(32)} ${"-".repeat(14)} ${"-".repeat(13)} ` +
  `${"-".repeat(10)} ${"-".repeat(6)} -------\n`
);

for (const r of rows) {
  const tools = r.est_tools_count == null ? "?" : String(r.est_tools_count);
  process.stdout.write(
    `${fmt(r.name, 32)} ${fmt(r.category, 14)} ${fmt(r.classification, 13)} ` +
    `${fmt(r.trust, 10)} ${fmt(tools, 6)} ${r.install_cmd || ""}\n`
  );
}
