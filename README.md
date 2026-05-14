# mcp-skills-vault

Supply-chain security scanner and vetted database for the MCP ecosystem — verify MCP server integrity before installing, score candidates by health, and get guided recommendations backed by 106 pre-audited entries.

> [!NOTE]
> Built for [Claude Code](https://claude.com/claude-code) skills. Drop a skill folder into `~/.claude/skills/` and Claude will auto-activate it when the user's prompt matches the skill description.

## What's in here

| Skill | Purpose | Status |
|---|---|---|
| [`mcp-ecosystem-intelligence/`](./mcp-ecosystem-intelligence) | Pipeline orchestrator + security scanner + vetted 106-tool database. Scans project stack, matches DB, verifies sha512/sha256/Docker digest integrity, checks advisory APIs, scores candidates by health, writes `.mcp.json`. | Ready |
| [`concepts/`](./concepts/) | Unfinished sketches kept for reference (e.g. `mcp-swift-synthesizer.skill` — Node MCP → Swift binary RAM-cut idea). None of these ship or run in CI. | Not active |

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

### Pipeline orchestrator

[`scripts/orchestrate.cjs`](./mcp-ecosystem-intelligence/scripts/orchestrate.cjs) — the single entry point. Deterministically runs steps 1, 2, 7, 8 of the pipeline so Claude only interprets results.

```bash
# Scan project, match DB, show what to install
node mcp-ecosystem-intelligence/scripts/orchestrate.cjs --cwd /path/to/project

# Keyword search on top of stack detection
node mcp-ecosystem-intelligence/scripts/orchestrate.cjs --query kubernetes

# Install a tool: integrity gate → writes .mcp.json
node mcp-ecosystem-intelligence/scripts/orchestrate.cjs --install github-mcp-server
node mcp-ecosystem-intelligence/scripts/orchestrate.cjs --install mcp-server-memory --global
```

Detects stack from: `package.json`, `pyproject.toml`, `requirements.txt`, `go.mod`, `Cargo.toml`, `docker-compose.yml`, `.env*` (key names only — no value leaks).

### Supply-chain security scanner

[`scripts/verify_integrity.cjs`](./mcp-ecosystem-intelligence/scripts/verify_integrity.cjs) — run before any install:

```bash
node mcp-ecosystem-intelligence/scripts/verify_integrity.cjs
```

| Ecosystem | Integrity | Source URL | Install hooks | CVE / advisory |
|---|---|---|---|---|
| npm (`npx -y`) | sha512 SRI from npm | `repository.url` | `pre/post/install` + `prepare` | npm bulk + OSV.dev + GHSA + Snyk† |
| PyPI (`uvx`) | sha256 of sdist tarball | `project_urls` | n/a | OSV.dev + GHSA + Snyk† |
| Docker (`docker run`) | image must be pinned by `@sha256:<digest>` | n/a | n/a | n/a |

† Snyk active only when `SNYK_TOKEN` env var is set (no public anonymous API). GHSA uses `GITHUB_TOKEN`/`GH_TOKEN` when present to raise its rate limit from 60→5000 req/hr; anonymous works at low volume. Advisories from all feeds are deduplicated by ID before flagging.

Flags:

| Flag | Effect |
|---|---|
| `--update` | Refresh `version` + `pkg_integrity` from registries |
| `--strict` | Treat WARNs (hooks, repo mismatch, unpinned docker) as hard failures |
| `--no-audit` | Skip advisory APIs (offline mode) |

### Docker `@sha256` drift detection

[`scripts/check_docker_drift.cjs`](./mcp-ecosystem-intelligence/scripts/check_docker_drift.cjs) — for every Docker entry, fetches the registry digest for the tracked tag (`tracked_tag` in the entry, default `latest`) via the OCI Distribution Spec and reports drift against the pinned `@sha256:` digest.

```bash
node mcp-ecosystem-intelligence/scripts/check_docker_drift.cjs           # human-readable
node mcp-ecosystem-intelligence/scripts/check_docker_drift.cjs --json    # machine-readable
node mcp-ecosystem-intelligence/scripts/check_docker_drift.cjs --strict  # exit 1 on any drift
```

Drift = upstream rebuilt the tag under a new digest. The weekly CI job (`docker-drift`) fails on any drift so a maintainer reviews the upstream change *before* refreshing the pin — a routine rebuild and a registry hijack look identical from here.

### Discovery pipeline

[`scripts/discover.cjs`](./mcp-ecosystem-intelligence/scripts/discover.cjs) — harvest MCP server candidates from three sources, deduplicate by repo URL, annotate with health metrics from GitHub, score, and emit a candidates JSON ready for manual cherry-pick into `tools_database.json`.

```bash
# Default: all three sources, top-50 candidates, capped at 200 gh api calls
node mcp-ecosystem-intelligence/scripts/discover.cjs --out candidates.json

# Single source / smaller limit
node mcp-ecosystem-intelligence/scripts/discover.cjs --source npm --limit 20 --out candidates.json
```

Sources:

| Source | Endpoint | Notes |
|---|---|---|
| `readme` | `modelcontextprotocol/servers` README | Curated. No `gh` calls. |
| `gh`     | `gh search repos --topic mcp-server / modelcontextprotocol` | Requires `gh auth login`. Topic-tags catch non-MCP projects, filtered out by name/description heuristic. |
| `npm`    | `npm search mcp-server` | Filters to packages with a GitHub `repository` field. |

Annotation uses `gh api repos/<owner>/<repo>` for stars, last commit, license, archive/fork status. Reject heuristics: `<10 stars`, `last_commit > 365 days`, archived, fork, doesn't look like an MCP server in `name`/`description`. Surviving candidates are scored with the same formula as `calculate_health.cjs` and emitted with the same shape as `tools_database.json` entries (minus `pkg_integrity`, which `verify_integrity.cjs --update` fills after manual merge).

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

`mcp-ecosystem-intelligence/assets/tools_database.json` — **106 entries** across ~25 categories, all with pinned versions, integrity hashes (npm sha512 / PyPI sha256 / Docker @sha256), SPDX license, and `trust` field.

```
ai        browser   ci-cd      cms       communication   crm
database  demo      docs       filesystem http            infra
maps      memory    meta       mobile     observability   payments
pm        reasoning search     testing    utility         vcs       web-scraping
```

Distribution: **93 Core / 9 Recommended / 4 Experimental**.

**Verified hand-curated core** (the original 30): the seven official `modelcontextprotocol/servers` (filesystem, fetch, git, memory, sequentialthinking, time, everything) plus vendor-maintained servers (`github`, `microsoft/playwright`, `cloudflare`, `notion`, `sentry`, `stripe`, `neon`, `mongodb`, `redis`, `clickhouse`, `awslabs/mcp`, `context7`, …) and high-quality community entries (`mcp-atlassian`, `firecrawl`, `tavily`, `exa`, `brave`, `kubernetes`, `duckduckgo`, …).

**Candidate batch** (75, added 2026-05): vendor servers harvested via `discover.cjs` from npm + the official servers README, all with `trust: "candidate"` pending human-vetting on usage patterns. Highlights: `@mapbox/mcp-server`, `@azure-devops/mcp`, `@dynatrace-oss/dynatrace-mcp-server`, `@browserstack/mcp-server`, `@salesforce/mcp`, `@postman/postman-mcp-server`, `@eslint/mcp`, `@circleci/mcp-server-circleci`, `argocd-mcp`, …

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
  "classification": "Core",
  "est_tools_count": 10,               // tools injected into context (~200-500 tokens each)
  "toolsets": "--toolsets repos,issues" // how to reduce tool count; null = no native filtering
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
| Registry / aggregator / `gh search` discovery pipeline | [`scripts/discover.cjs`](./mcp-ecosystem-intelligence/scripts/discover.cjs) — done |
| Reject heuristics (5-Minute Rule, Bloat, Duplication) | Claude-executed judgment, no dedicated script |
| Formatted recommendation output (terse / verbose) | Claude-generated, no dedicated formatter |
| Project-scoped `.mcp.json` install (default path) | Pattern documented in SKILL.md §10, no dedicated script |
| `allowedTools` per-project filtering for heavy servers | Pattern documented in SKILL.md §10, no dedicated script |
| Wrapper generator (CLI/API → MCP boilerplate) | [`scripts/generate_wrapper.cjs`](./mcp-ecosystem-intelligence/scripts/generate_wrapper.cjs) — done |

---

## Token cost management

Every active MCP server injects its full tool list into Claude's system prompt (~200–500 tokens per tool). With 106 servers in the DB the spread is wide: `mcp-server-fetch` = 1 tool vs. `gitlab-mcp` = 153 tools.

Three levers, in order of preference:

**1. Native filtering** (server flag / config key) — use the `toolsets` field in the DB:
```bash
# github-mcp: keep only what the project needs
--toolsets repos,issues,pull_requests
# playwright-mcp: drop 56 tools, keep 8
--caps core
# mongodb-mcp: exclude destructive tools
disabledTools: ["dropCollection", "dropDatabase"] in mcp_settings.json
```

**2. Project-scoped `.mcp.json`** (default install target) — server is active only in the repo where `.mcp.json` lives, invisible everywhere else:
```json
{
  "mcpServers": {
    "github": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges",
               "-e", "GITHUB_PERSONAL_ACCESS_TOKEN",
               "--toolsets", "repos,issues",
               "ghcr.io/github/github-mcp-server@sha256:…"],
      "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_TOKEN}" }
    }
  }
}
```

Reserve `~/.claude.json` for truly cross-project servers: `mcp-server-filesystem`, `mcp-server-memory`.

**3. Wrapper (anti-bloat pattern)** — when a vendor server has no native filtering and exposes 50+ tools you don't need, wrap the 3–5 tools you do need in a thin custom MCP server using `assets/mcp-wrapper-template/`. The wrapper replaces the vendor server entirely, keeping context lean.

---

## Wrapping a CLI/API as MCP

When the vendor server has no native filtering and exposes 50+ tools you don't need, generate a thin wrapper that exposes only the 3–5 tools you actually use. Saves ~200–500 tokens per dropped tool.

```bash
# Skeleton wrapper, no tools yet
node mcp-ecosystem-intelligence/scripts/generate_wrapper.cjs \
  --name my-cli-mcp --tool "My CLI" --out ./my-cli-mcp

# Pre-populated with tool definitions from a JSON spec
node mcp-ecosystem-intelligence/scripts/generate_wrapper.cjs \
  --name warehouse-mcp --tool "Internal Warehouse" \
  --tools-file ./tools.json \
  --out ./warehouse-mcp
```

`tools.json` is an array of MCP tool defs (`name` / `description` / `inputSchema`); the generator emits `ListToolsRequestSchema` entries plus `switch`-cases with `required`-arg validation, runs Node's `--check` on the result, and writes a `.mcp.json`-ready README.

Underlying template lives in `mcp-ecosystem-intelligence/assets/mcp-wrapper-template/` if you'd rather edit by hand.

---

## Topics

`claude-code` · `claude-skill` · `mcp` · `model-context-protocol` · `mcp-server` · `mcp-tools` · `anthropic` · `ai-agents`

## License

[MIT](./LICENSE)
