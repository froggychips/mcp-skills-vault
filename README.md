# mcp-skills-vault

Claude Code skills for working with the Model Context Protocol (MCP) ecosystem — discovering MCP servers for a project, scoring them, and installing them safely.

> [!NOTE]
> Built for [Claude Code](https://claude.com/claude-code) skills. Drop a skill folder into `~/.claude/skills/` and Claude will auto-activate it when the user's prompt matches the skill description.

## What's in here

| Skill | Purpose | Status |
|---|---|---|
| [`mcp-ecosystem-intelligence/`](./mcp-ecosystem-intelligence) | Find, score, and install MCP servers. Comes with a seeded **30-tool database**. | Ready |
| [`mcp-swift-synthesizer.skill`](./mcp-swift-synthesizer.skill) | Convert MCP server functions into native Swift binaries to cut RAM (Node 150–300 MB → Swift 1–10 MB). Experimental. | Concept |

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

The skill activates by description match. It will:

1. Read your project's manifests (`package.json`, `pyproject.toml`, …) to detect stack.
2. Look up the seeded `tools_database.json` first (30 vetted MCP servers across 14 categories).
3. Fall back to `registry.modelcontextprotocol.io` → aggregators → `gh search` only on cache miss.
4. Score candidates with [`scripts/calculate_health.cjs`](./mcp-ecosystem-intelligence/scripts/calculate_health.cjs).
5. Recommend the best per category, with a copy-pasteable install command.
6. On your consent, install by **directly editing `~/.claude.json`** (avoids `claude mcp add`, which prints bearer tokens to stdout).

## Health Score formula

```
score = min(20, 10·log10(stars+1))   # popularity, capped
      + {40|20|10|0}                  # recency: <30d / <90d / <180d / older
      + 30 if in_registry
      + 15 if install_cmd documented
      + 5  if open_issues/10 < 5
```

Tier mapping (max 110):

| Score | Tier | Behaviour |
|---|---|---|
| 85+ | Core | recommend by default |
| 65–84 | Recommended | recommend with note |
| 40–64 | Experimental | mention only on ask |
| < 40 | Deprecated | hide unless asked |

## Seeded database

`mcp-ecosystem-intelligence/assets/tools_database.json` — **30 entries** across 14 categories:

```
browser  database  demo  docs   filesystem  http   infra
memory   meta      observability  payments  pm    reasoning
search   utility   vcs   web-scraping
```

Distribution: **18 Core / 10 Recommended / 2 Experimental**.

Includes the seven official `modelcontextprotocol/servers` (filesystem, fetch, git, memory, sequentialthinking, time, everything) plus vendor-maintained servers (`github`, `microsoft/playwright`, `cloudflare`, `notion`, `sentry`, `stripe`, `neon`, `mongodb`, `redis`, `clickhouse`, `cloudflare`, `awslabs/mcp`, `context7`, …) and high-quality community entries (`mcp-atlassian`, `firecrawl`, `tavily`, `exa`, `brave`, `kubernetes`, `duckduckgo`, …).

## Wrapping a CLI/API as MCP

If discovery and scoring return nothing for a need, the skill generates a minimal wrapper from `mcp-ecosystem-intelligence/assets/mcp-wrapper-template/`:

```
mcp-wrapper-template/
  server.js       # @modelcontextprotocol/sdk + StdioServerTransport boilerplate
  package.json    # pinned SDK major, node>=18, MIT
```

Replace `{{name}}` and `{{tool}}` placeholders, add tool definitions in the `ListTools` handler, drop the result into `~/.claude/skills/<your-tool>-mcp/` or publish to npm.

## Topics

`claude-code` · `claude-skill` · `mcp` · `model-context-protocol` · `mcp-server` · `mcp-tools` · `anthropic` · `ai-agents`

## License

[MIT](./LICENSE)
