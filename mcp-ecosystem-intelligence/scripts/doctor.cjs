#!/usr/bin/env node
// doctor.cjs — local readiness check for mcp-vault + common MCP tooling.
//
// No network, no secrets, no dependencies. Reads only MCP server config keys.

"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

function parseArgs(argv) {
  const out = { json: false, strict: false, help: false, cwd: process.cwd() };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--json") out.json = true;
    else if (a === "--strict") out.strict = true;
    else if (a === "--help" || a === "-h") out.help = true;
    else if (a === "--cwd") out.cwd = argv[++i] || "";
    else return { error: `unknown argument: ${a}` };
  }
  return out;
}

const HELP = `mcp-vault doctor — check local MCP readiness.

USAGE
  mcp-vault doctor [--cwd <path>] [--json] [--strict]

CHECKS
  node              Node runtime version (mcp-vault needs >=18)
  gh                GitHub CLI availability (optional; raises GHSA limits)
  docker            Docker CLI availability (optional; needed for Docker MCP entries)
  uvx               uvx availability (optional; needed for PyPI MCP entries)
  project_config    <cwd>/.mcp.json exists and parses
  project_settings  <cwd>/.claude/settings.json exists and parses
  global_config     ~/.claude.json exists and exposes mcpServers

No network calls. No token values are read or printed.
`;

function versionParts(v) {
  const m = String(v || "").match(/v?(\d+)\.(\d+)\.(\d+)/);
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

function versionGte(v, minMajor) {
  const p = versionParts(v);
  return Boolean(p && p[0] >= minMajor);
}

function commandVersion(cmd, args) {
  const r = spawnSync(cmd, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  if (r.error) return { ok: false, error: r.error.code || r.error.message };
  const out = `${r.stdout || ""}${r.stderr || ""}`.trim().split("\n")[0] || `exit ${r.status}`;
  return { ok: r.status === 0, version: out, exit_code: r.status };
}

function readJson(file) {
  try {
    return { exists: true, value: JSON.parse(fs.readFileSync(file, "utf8")) };
  } catch (e) {
    if (e && e.code === "ENOENT") return { exists: false };
    return { exists: true, error: e.message };
  }
}

function status(level, name, message, details = {}) {
  return { level, name, message, ...details };
}

function runDoctor({ cwd }) {
  const checks = [];

  checks.push(status(
    versionGte(process.version, 18) ? "ok" : "fail",
    "node",
    `Node ${process.version}`,
    {
      required: ">=18",
      note: versionGte(process.version, 22)
        ? "mcp-trace can use built-in node:sqlite"
        : "mcp-vault works; mcp-trace needs Node 22+",
    },
  ));

  for (const [name, cmd, args, note] of [
    ["gh", "gh", ["--version"], "optional; raises GHSA rate limits from 60/hr when authenticated"],
    ["docker", "docker", ["--version"], "optional; needed for Docker-backed MCP entries"],
    ["uvx", "uvx", ["--version"], "optional; needed for PyPI/uvx MCP entries"],
  ]) {
    const r = commandVersion(cmd, args);
    checks.push(status(
      r.ok ? "ok" : "warn",
      name,
      r.ok ? r.version : `${cmd} not available (${r.error || `exit ${r.exit_code}`})`,
      { optional: true, note },
    ));
  }

  const projectConfig = path.join(cwd, ".mcp.json");
  const pc = readJson(projectConfig);
  checks.push(status(
    pc.error ? "fail" : (pc.exists ? "ok" : "warn"),
    "project_config",
    pc.error ? `.mcp.json parse failed: ${pc.error}` : (pc.exists ? ".mcp.json found" : ".mcp.json not found"),
    { path: projectConfig },
  ));

  const projectSettings = path.join(cwd, ".claude", "settings.json");
  const ps = readJson(projectSettings);
  checks.push(status(
    ps.error ? "fail" : (ps.exists ? "ok" : "warn"),
    "project_settings",
    ps.error ? `.claude/settings.json parse failed: ${ps.error}` : (ps.exists ? ".claude/settings.json found" : ".claude/settings.json not found"),
    { path: projectSettings },
  ));

  const globalConfig = path.join(os.homedir(), ".claude.json");
  const gc = readJson(globalConfig);
  let globalLevel = "warn";
  let globalMessage = "~/.claude.json not found";
  let serverCount = 0;
  if (gc.error) {
    globalLevel = "fail";
    globalMessage = `~/.claude.json parse failed: ${gc.error}`;
  } else if (gc.exists) {
    const servers = gc.value && typeof gc.value === "object" && gc.value.mcpServers && typeof gc.value.mcpServers === "object"
      ? gc.value.mcpServers
      : {};
    serverCount = Object.keys(servers).length;
    globalLevel = "ok";
    globalMessage = `~/.claude.json found (${serverCount} mcpServers)`;
  }
  checks.push(status(globalLevel, "global_config", globalMessage, { path: globalConfig, mcp_server_count: serverCount }));

  return {
    cwd,
    checked_at: new Date().toISOString(),
    counts: {
      ok: checks.filter(c => c.level === "ok").length,
      warn: checks.filter(c => c.level === "warn").length,
      fail: checks.filter(c => c.level === "fail").length,
    },
    checks,
  };
}

function printHuman(result) {
  for (const c of result.checks) {
    const icon = c.level === "ok" ? "OK  " : c.level === "warn" ? "WARN" : "FAIL";
    process.stdout.write(`${icon}  ${c.name.padEnd(16)} ${c.message}\n`);
    if (c.note) process.stdout.write(`      ${c.note}\n`);
  }
  process.stdout.write(`\n${result.counts.ok} ok · ${result.counts.warn} warn · ${result.counts.fail} fail\n`);
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.error) {
    process.stderr.write(`doctor: ${args.error}\n\n${HELP}`);
    process.exit(2);
  }
  if (args.help) {
    process.stdout.write(HELP);
    process.exit(0);
  }
  const result = runDoctor({ cwd: path.resolve(args.cwd || process.cwd()) });
  if (args.json) process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  else printHuman(result);

  const hard = result.counts.fail > 0 || (args.strict && result.counts.warn > 0);
  process.exit(hard ? 1 : 0);
}

if (require.main === module) main();

module.exports = { runDoctor, versionGte };
