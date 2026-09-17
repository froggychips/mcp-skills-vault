# mcp-skills-vault — FAQ

Quick answers for Claude Code users who wonder if this is worth installing.

---

## What is this?

A vetted database of 114 MCP servers (94 hand-verified + 20 candidates), a supply-chain security scanner, and a CLI that wires them together.

When you want to add an MCP server to a project, this gives you:
- A curated list of known-good servers with health scores (not the 1000+ entry official registry)
- A hash verification check before anything is written to your config
- A single command that detects what tools your project probably needs

---

## Why not just install MCP servers manually?

You can. But two problems:

**Quality signal.** The official MCP registry lists everything. This project lists what's worth using — 114 entries, all scored by recency, stars, license, and whether the install actually works.

**Token cost.** Every active MCP server injects its full tool list into Claude's context. Some servers have 100+ tools. That's thousands of tokens on every message, even if you never use those tools. The database includes `est_tools_count` for every entry so you can make informed decisions before installing.

---

## What does the hash check actually verify?

For npm: re-fetches `dist.integrity` from the registry for the pinned version and compares it byte-for-byte with the stored hash.  
For PyPI: sha256 of the sdist tarball.  
For Docker: the image must be pinned by `@sha256:<digest>`.

If the hash doesn't match — the install is blocked. If there's a known CVE — it's flagged via OSV.dev / npm advisory API.

**The important caveat:** a matching hash means the artifact is identical to what was published at that version. It does not mean the code is safe — only that it hasn't changed since the hash was recorded.

---

## Does it check the dependencies too?

With `--deps`, yes. The tree is resolved with `npm install --package-lock-only
--ignore-scripts` — nothing is installed and no package code runs — and every
distinct package in it goes to OSV. This matters more than it sounds: across the
shipped DB that is 19,377 transitive packages, 25 entries whose *dependencies*
run install scripts, and 38 with a high or critical advisory somewhere in the
tree. A one-level check is a check at the wrong depth.

## What does `trust: "verified"` mean, exactly?

It is computed, not typed. Each dimension — artifact, signature, provenance,
source binding, advisories, dependencies, smoke — carries its own status and the
date it was established, and each has a shelf life: a hash match holds for 90
days, "no advisories" for 7, because disclosures do not wait. `trust` is derived
from that, and evidence is keyed to the artifact including its version, so it is
dropped rather than inherited when the version moves.

A run records only what it examined. A `--no-audit` run writes nothing about
advisories rather than writing "clean".

## Can I make it stricter without remembering seven flags?

`.mcp-vault.policy.json`, resolved from the working directory upwards. It sets
the bar once — `unverified: fail`, `signatures: require`, licence allow/deny
lists, a minimum health score, acceptable trust tiers — and CI and your shell
then enforce the same one. A policy can only raise the bar; an explicit flag
still wins. An unknown key is a hard error, because a policy with a typo that
silently enforces nothing is worse than no policy.

## What do Core / Recommended / Experimental mean?

Servers are scored by a formula:

```
score = min(20, 10·log10(stars+1))   # popularity, capped
      + {40|20|10|0}                  # recency: <30d / <90d / <180d / older
      + 30 if in public registry
      + 15 if install command is documented
      − 10 if license is non-OSI or unknown
```

| Tier | Score | What happens |
|---|---|---|
| Core | 85+ | Recommended by default |
| Recommended | 65–84 | Recommended with a note |
| Experimental | 40–64 | Mentioned only if you ask |
| Deprecated | < 40 | Hidden unless you ask |

---

## How do I actually use it?

```bash
# What does my project need?
npx -y @froggychips/mcp-vault scan --cwd /path/to/project

# Keyword search
mcp-vault scan --query kubernetes

# Install — runs integrity check, then writes .mcp.json
mcp-vault install github-mcp-server
```

Or drop the skill folder into `~/.claude/skills/mcp-ecosystem-intelligence/` and ask Claude naturally: *"What MCP tools should I add for this Next.js project?"*

---

## Does it read my .env values?

Key names only. The scanner uses the regex `/^([A-Z0-9_]+)=/` — it reads `GITHUB_TOKEN=` and stops at the `=`. Values are never captured, stored, or printed. If you find a code path where a value leaks, that's a security bug worth reporting.

---

## Where does `--install` write the config?

By default: `.mcp.json` in your project root (project-scoped). The server is active only in that project, invisible everywhere else.

To install globally (cross-project tools like `mcp-server-memory`):
```bash
mcp-vault install mcp-server-memory --global
```

Global installs go to `~/.claude.json`.

Other hosts work too — `--host cursor`, `--host vscode`, `--host claude-desktop`,
and `--host codex` (which prints a TOML block to paste, because rewriting
someone's TOML without a parser destroys their comments). `--list-hosts` shows
what exists. An existing config is backed up before it is touched, unrelated
keys survive, and a config that exists but does not parse is refused rather than
replaced.

Whatever the host, the command written is the version the gate verified:
`pkg@1.2.3`, `pkg==1.2.3`, `image@sha256:…`. Writing `npx -y pkg` would mean the
thing that runs is not the thing that was checked.

---

## How is the database kept up to date?

A GitHub Actions workflow runs every Monday:
1. Re-fetches hashes from npm/PyPI for all 114 entries
2. Refreshes GitHub metrics (stars, last commit, open issues)
3. Opens a PR — **human review required before merge**

The PR is the only automated path to modify `tools_database.json`. Version bumps are never auto-merged. Reviewers check for unexplained major-version jumps that could indicate a compromised release.

---

## How is this different from the official MCP registry?

The official registry lists what exists (~1000+ entries). This project lists what's worth using (114 entries), verifies the hash didn't change since review, and scores by health. It's a curated shortlist, not a directory.

---

## Can I suggest a new server?

Open an issue. To be added, a server needs: a pinned version, a hash fetchable from a public registry, a working install command, and a health score above 40.

---

## Does this send any data anywhere?

No telemetry. The integrity checker calls public APIs (npm registry, PyPI, OSV.dev) — those calls reveal the package name and version being checked, same as running `npm install` directly.

---

## Where do I report a bug?

[GitHub Issues](https://github.com/froggychips/mcp-skills-vault/issues) or Telegram [@froggychips](https://t.me/froggychips).
