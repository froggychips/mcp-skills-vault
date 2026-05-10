# mcp-skills-vault

Claude Code skills for working with the Model Context Protocol (MCP) ecosystem — discovering MCP servers for a project, scoring them, and installing them safely.

> [!NOTE]
> Built for [Claude Code](https://claude.com/claude-code) skills. Drop a skill folder into `~/.claude/skills/` and Claude will auto-activate it when the user's prompt matches the skill description.

## What's in here

| Skill | Purpose | Status |
|---|---|---|
| [`mcp-ecosystem-intelligence/`](./mcp-ecosystem-intelligence) | Find, score, and install MCP servers. Comes with a seeded **31-tool database** and a supply-chain security scanner. | Ready |
| [`mcp-swift-synthesizer.skill`](./mcp-swift-synthesizer.skill) | Convert MCP server functions into native Swift binaries to cut RAM (Node 150–300 MB → Swift 1–10 MB). | Concept |

## Quick install (Ecosystem Intelligence)

```bash
git clone https://github.com/froggychips/mcp-skills-vault.git
mkdir -p ~/.claude/skills
cp -r mcp-skills-vault/mcp-ecosystem-intelligence ~/.claude/skills/
```

Then ask Claude something like:

> _"Is there an MCP server for ClickHouse I should add to this project?"_
> _"Audit my MCP setup."_
> _"What MCP tools should I install for a Next.js app on Cloudflare?"_

---

## What works today

### Supply-chain security scanner

[`scripts/verify_integrity.cjs`](./mcp-ecosystem-intelligence/scripts/verify_integrity.cjs) — run before any install:

```bash
node mcp-ecosystem-intelligence/scripts/verify_integrity.cjs
```

| Ecosystem | Integrity | Source URL | Install hooks | CVE / advisory |
|---|---|---|---|---|
| npm (`npx -y`) | sha512 SRI from npm | `repository.url` | `pre/post/install` + `prepare` | npm advisory bulk API |
| PyPI (`uvx`) | sha256 of sdist tarball | `project_urls` | n/a | OSV.dev `/v1/querybatch` |
| Docker (`docker run`) | image must be pinned by `@sha256:<digest>` | n/a | n/a | n/a |

Flags:

| Flag | Effect |
|---|---|
| `--update` | Refresh `version` + `pkg_integrity` from registries |
| `--strict` | Treat WARNs (hooks, repo mismatch, unpinned docker) as hard failures |
| `--no-audit` | Skip advisory APIs (offline mode) |

### Health scorer

[`scripts/calculate_health.cjs`](./mcp-ecosystem-intelligence/scripts/calculate_health.cjs) — score any MCP candidate:

```bash
node mcp-ecosystem-intelligence/scripts/calculate_health.cjs \
  <stars> <last_commit_days> <in_registry> <has_install_cmd> <critical_issues> [license]
```

```
score = min(20, 10·log10(stars+1))   # popularity, capped
      + {40|20|10|0}                  # recency: <30d / <90d / <180d / older
      + 30 if in_registry
      + 15 if install_cmd documented
      + 5  if open_issues/10 < 5
      − 10 if license is non-OSI / source-available / Unknown
```

| Score | Tier | Behaviour |
|---|---|---|
| 85+ | Core | recommend by default |
| 65–84 | Recommended | recommend with note |
| 40–64 | Experimental | mention only on ask |
| < 40 | Deprecated | hide unless asked |

### Vetted database

`mcp-ecosystem-intelligence/assets/tools_database.json` — **31 entries** across 17 categories, all with pinned versions, integrity hashes, SPDX license, and `trust` field.

```
browser  database  demo  docs   filesystem  http   infra
memory   meta      observability  payments  pm    reasoning
search   utility   vcs   web-scraping
```

Distribution: **18 Core / 11 Recommended / 2 Experimental**.

Includes the seven official `modelcontextprotocol/servers` (filesystem, fetch, git, memory, sequentialthinking, time, everything) plus vendor-maintained servers (`github`, `microsoft/playwright`, `cloudflare`, `notion`, `sentry`, `stripe`, `neon`, `mongodb`, `redis`, `clickhouse`, `awslabs/mcp`, `context7`, …) and high-quality community entries (`mcp-atlassian`, `firecrawl`, `tavily`, `exa`, `brave`, `kubernetes`, `duckduckgo`, …).

Entry schema:

```jsonc
{
  "name": "pkg-name",
  "category": "database|search|infra|…",
  "install_cmd": "npx -y pkg@1.2.3",   // always pinned
  "source_url": "https://github.com/owner/repo",
  "version": "1.2.3",                  // pinned npm version
  "pkg_integrity": "sha512-…",         // npm dist.integrity
  "trust": "verified",                 // "verified" | "candidate"
  "license": "MIT",                    // SPDX; non-OSI triggers -10 penalty
  "health_score": 105.0,
  "classification": "Core"
}
```

### CI

`.github/workflows/security-scan.yml` runs on every push and weekly:

- **smoke** — `verify_integrity.cjs --no-audit` on every PR / push to master (offline, fast)
- **refresh-hashes** — weekly cron that opens a PR refreshing `version` + `pkg_integrity` from live registries, gated by human review before merge

---

## Roadmap

The following are described in [`SKILL.md`](./mcp-ecosystem-intelligence/SKILL.md) as intended behaviour but are not yet scripted — Claude performs them interactively using available tools (Bash, WebFetch, Read) on each invocation:

| Feature | Status |
|---|---|
| Stack detection from manifests (`package.json`, `pyproject.toml`, …) | Claude-executed, no dedicated script |
| Registry / aggregator / `gh search` discovery pipeline | Claude-executed, no dedicated script |
| Reject heuristics (5-Minute Rule, Bloat, Duplication) | Claude-executed judgment, no dedicated script |
| Formatted recommendation output (terse / verbose) | Claude-generated, no dedicated formatter |
| Direct `~/.claude.json` writer after install consent | Pattern documented in SKILL.md §10, no dedicated script |
| Wrapper generator (CLI/API → MCP boilerplate) | Template exists in `assets/mcp-wrapper-template/`; generator not scripted |

---

## Wrapping a CLI/API as MCP

If discovery returns nothing for a need, use `mcp-ecosystem-intelligence/assets/mcp-wrapper-template/` as a starting point:

```
mcp-wrapper-template/
  server.js       # @modelcontextprotocol/sdk + StdioServerTransport boilerplate
  package.json    # pinned SDK major, node>=18, MIT
```

Replace `{{name}}` and `{{tool}}` placeholders, add tool definitions in the `ListTools` handler, drop the result into `~/.claude/skills/<your-tool>-mcp/` or publish to npm.

---

## Topics

`claude-code` · `claude-skill` · `mcp` · `model-context-protocol` · `mcp-server` · `mcp-tools` · `anthropic` · `ai-agents`

## License

[MIT](./LICENSE)
