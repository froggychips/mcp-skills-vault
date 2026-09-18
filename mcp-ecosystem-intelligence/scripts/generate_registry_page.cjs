#!/usr/bin/env node
// Generate a static browsable registry page from assets/tools_database.json.

"use strict";

const fs = require("fs");
const path = require("path");
const { classifyEntry } = require("./lib/tiers.cjs");

const ROOT = path.resolve(__dirname, "..", "..");
const DB_PATH = path.join(ROOT, "mcp-ecosystem-intelligence", "assets", "tools_database.json");
const EVAL_PATH = path.join(ROOT, "mcp-ecosystem-intelligence", "assets", "eval_results.json");
const OUT_DIR = path.join(ROOT, "docs", "site");

function esc(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function slimEntry(t, evidence = null, smoke = null) {
  // The tier is derived here rather than read off the entry: it is a function
  // of the evidence and of today's date (claims age out), so a stored copy
  // would go quietly wrong while the file sat unchanged.
  const tier = classifyEntry(t, smoke);
  return {
    name: t.name,
    category: t.category,
    classification: tier.classification,
    tier_reason: tier.why,
    trust: t.trust,
    license: t.license,
    health_score: t.health_score,
    est_tools_count: t.est_tools_count,
    install_cmd: t.install_cmd,
    source_url: t.source_url,
    // What was checked, and when. A registry that publishes a verdict without
    // its date is asking to be read as current forever.
    evidence: evidence
      ? Object.fromEntries(Object.entries(evidence.dimensions || {})
          .map(([k, v]) => [k, { status: v.status, checked_at: v.checked_at }]))
      : null,
    smoke: smoke
      ? { status: smoke.status, tools: smoke.tool_count ?? null, checked_at: (smoke.checked_at || "").slice(0, 10) }
      : null,
  };
}

function renderHtml(entries) {
  const rows = entries.map((t) => `
        <tr data-name="${esc(t.name.toLowerCase())}" data-category="${esc(t.category)}" data-tier="${esc(t.classification)}" data-trust="${esc(t.trust)}">
          <td><a href="${esc(t.source_url || "#")}">${esc(t.name)}</a></td>
          <td>${esc(t.category)}</td>
          <td>${esc(t.classification)}</td>
          <td>${esc(t.trust)}</td>
          <td>${esc(t.health_score)}</td>
          <td>${esc(t.est_tools_count ?? "?")}</td>
          <td>${esc(t.license ?? "Unknown")}</td>
          <td><code>${esc(t.install_cmd)}</code></td>
        </tr>`).join("\n");

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>MCP Vault Registry</title>
  <meta name="description" content="Browsable registry of MCP servers from @froggychips/mcp-vault: pinned install commands, health score, trust, license, and estimated tool count.">
  <link rel="stylesheet" href="./style.css">
</head>
<body>
  <header>
    <nav>
      <a href="./index.html">home</a>
      <a href="./vault.html">vault</a>
      <a href="./registry.html">registry</a>
      <a href="./install.html">install</a>
      <a href="https://github.com/froggychips/mcp-skills-vault">github</a>
    </nav>
  </header>
  <main>
    <h1>MCP Vault Registry</h1>
    <p class="lede">${entries.length} MCP server entries with pinned install commands, trust tier, license, score, and estimated tool count.</p>

    <section class="filters" aria-label="registry filters">
      <input id="q" type="search" placeholder="Search name or install command" aria-label="Search registry">
      <select id="category" aria-label="Category"><option value="">All categories</option></select>
      <select id="tier" aria-label="Tier"><option value="">All tiers</option></select>
      <select id="trust" aria-label="Trust"><option value="">All trust</option></select>
    </section>

    <p id="count">${entries.length} shown</p>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Name</th><th>Category</th><th>Tier</th><th>Trust</th><th>Score</th><th>Tools</th><th>License</th><th>Install</th>
          </tr>
        </thead>
        <tbody id="rows">${rows}
        </tbody>
      </table>
    </div>
  </main>
  <script>
    const rows = [...document.querySelectorAll("tbody tr")];
    const q = document.getElementById("q");
    const category = document.getElementById("category");
    const tier = document.getElementById("tier");
    const trust = document.getElementById("trust");
    const count = document.getElementById("count");

    function fill(select, attr) {
      [...new Set(rows.map(r => r.dataset[attr]).filter(Boolean))].sort().forEach(v => {
        const o = document.createElement("option");
        o.value = v; o.textContent = v;
        select.appendChild(o);
      });
    }
    fill(category, "category"); fill(tier, "tier"); fill(trust, "trust");

    function apply() {
      const needle = q.value.trim().toLowerCase();
      let shown = 0;
      for (const r of rows) {
        const text = r.textContent.toLowerCase();
        const ok = (!needle || text.includes(needle)) &&
          (!category.value || r.dataset.category === category.value) &&
          (!tier.value || r.dataset.tier === tier.value) &&
          (!trust.value || r.dataset.trust === trust.value);
        r.hidden = !ok;
        if (ok) shown++;
      }
      count.textContent = shown + " shown";
    }
    [q, category, tier, trust].forEach(el => el.addEventListener("input", apply));
  </script>
</body>
</html>
`;
}

function main() {
  const db = JSON.parse(fs.readFileSync(DB_PATH, "utf8"));
  // Behavioural results are a separate stream, and may be absent (nothing has
  // run yet) — an empty file must not become an empty claim.
  let smokeByName = new Map();
  try {
    const evals = JSON.parse(fs.readFileSync(EVAL_PATH, "utf8"));
    smokeByName = new Map((evals.results || []).map((r) => [r.name, r]));
  } catch { /* no results shipped */ }

  const entries = db.tools
    .map((t) => slimEntry(t, t.trust_evidence || null, smokeByName.get(t.name) || null))
    .sort((a, b) =>
    (a.category || "").localeCompare(b.category || "") ||
    (b.health_score || 0) - (a.health_score || 0) ||
    (a.name || "").localeCompare(b.name || "")
  );
  fs.mkdirSync(OUT_DIR, { recursive: true });
  fs.writeFileSync(path.join(OUT_DIR, "registry.json"), `${JSON.stringify({ generated_at: new Date().toISOString(), count: entries.length, entries }, null, 2)}\n`);
  fs.writeFileSync(path.join(OUT_DIR, "registry.html"), renderHtml(entries));
  console.log(`Wrote ${entries.length} entries to ${path.join(OUT_DIR, "registry.html")}`);
}

if (require.main === module) main();

module.exports = { slimEntry, renderHtml };
