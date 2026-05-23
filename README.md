# mcp-skills-vault

[![npm version](https://img.shields.io/npm/v/@froggychips/mcp-vault.svg)](https://www.npmjs.com/package/@froggychips/mcp-vault)
[![npm downloads](https://img.shields.io/npm/dm/@froggychips/mcp-vault.svg)](https://www.npmjs.com/package/@froggychips/mcp-vault)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Zero deps](https://img.shields.io/badge/runtime%20deps-0-brightgreen.svg)](./PHILOSOPHY.md)
[![Tests](https://img.shields.io/badge/tests-264%20pass-brightgreen.svg)](./tests)

**Homepage:** [mcp.froggychips.xyz](https://mcp.froggychips.xyz) · **npm:** [`@froggychips/mcp-vault`](https://www.npmjs.com/package/@froggychips/mcp-vault)

> **Make MCP boring.** A deterministic registry + integrity scanner for [Model Context Protocol](https://modelcontextprotocol.io) servers, so installing one stops feeling like `curl | bash`.

![demo](./docs/demo.gif)

```text
$ npx -y @froggychips/mcp-vault scan
Stack: Langs: Node | DB: postgres | Infra: aws, teamcity, atlassian
Needs: database, infra, ci-cd, pm

── Recommended ──────────────────────────────────────────────
  Core         mcp-server-neon            10 tools  score 105
  Core         mcp-server-aws             20 tools  score 105
  Core         mcp-server-filesystem      10 tools  score 105
  Core         mcp-server-memory           9 tools  score 105
  Recommended  teamcity-mcp              null tools  score  65

── Heavy — scope before global install ──────────────────────
  Experimental mcp-atlassian             72 tools ⚠  score  55
                 --toolsets jira,confluence

$ npx -y @froggychips/mcp-vault verify --no-audit
…
110 entries checked — 0 failure(s)
```

## Without this vault vs. with it

| | Without | With |
|---|---|---|
| **Discoverability** | search GitHub, hope the README isn't lying | curated DB of **112 entries** with health scores, license, category, est-tools-count |
| **Trust** | unknown publisher, unknown last commit | `trust: verified` per entry, **94/112 (84%)** hand-vetted against a written checklist; the remaining 18 are `trust: "candidate"` held by upstream install hooks (see [Install-Hook Policy](./CONTRIBUTING.md#install-hook-policy)) |
| **Integrity** | `npx -y whatever@latest` runs whatever ships today | sha512/sha256/Docker `@sha256:` pinned + re-verified against the live registry on every check |
| **Vulnerabilities** | `npm audit` after the fact, if you remember | 4 advisory feeds merged: npm bulk + OSV.dev + GHSA + Snyk† — checked *before* the install command is written |
| **Stack matching** | manual reading of awesome-lists | detects 40+ env-key patterns + 14 file paths + docker-compose images → suggests what to install |
| **Offline use** | doesn't | `--no-audit` skips network entirely; hash gate still runs; air-gapped same as networked |
| **Telemetry** | varies | none. Ever. |

† Snyk requires `SNYK_TOKEN` (no public anonymous API).

## Quick start

**As a CLI** — one line, no clone, no global install:

```bash
npx -y @froggychips/mcp-vault scan --cwd ./my-project
npx -y @froggychips/mcp-vault audit --strict
npx -y @froggychips/mcp-vault verify --no-audit
```

Prefer it installed? `npm i -g @froggychips/mcp-vault` then drop the `npx -y` prefix.

**As a Claude Code skill** — drop the bundled skill folder into `~/.claude/skills/` and Claude will pick it up:

```bash
git clone https://github.com/froggychips/mcp-skills-vault.git
mkdir -p ~/.claude/skills
cp -r mcp-skills-vault/mcp-ecosystem-intelligence ~/.claude/skills/
```

**Direct script invocation** — every command also runs without the CLI wrapper, e.g. `node mcp-ecosystem-intelligence/scripts/orchestrate.cjs --cwd /path/to/project`. Flags are identical; the CLI is a thin pass-through.

Zero runtime dependencies. Node built-ins only. One JSON file is the entire database.

Ask Claude something like:

> _"Is there an MCP server for ClickHouse I should add to this project?"_
> _"Audit my MCP setup."_
> _"What MCP tools should I install for a Next.js app on Cloudflare?"_

## Five constraints that shape every decision

- **Offline-first** — the gate the user cares about runs with no network
- **Minimal** — zero runtime deps; supply-chain attack surface = Node's
- **Inspectable** — every entry carries an audit trail; every output has `--json`
- **Deterministic** — same DB, same commit → same recommendation, every time
- **Boring** — supply-chain tooling should not be exciting

Full rationale and the rules each constraint imposes: [PHILOSOPHY.md](./PHILOSOPHY.md).

## What's in here

| | Purpose | Status |
|---|---|---|
| [`mcp-ecosystem-intelligence/`](./mcp-ecosystem-intelligence) | The scanner + DB. Stack detection, integrity verification, advisory feeds, drift detection, candidate discovery, wrapper generator. | Ready |
| [`concepts/`](./concepts/) | Unfinished sketches kept for reference. Nothing here ships or runs in CI. | Not active |

---

## What works today

### Pipeline orchestrator

[`scripts/orchestrate.cjs`](./mcp-ecosystem-intelligence/scripts/orchestrate.cjs) — the single entry point. Deterministically runs steps 1, 2, 7, 8 of the pipeline so Claude only interprets results.

```bash
# Scan project, match DB, show what to install
mcp-vault scan --cwd /path/to/project

# Keyword search on top of stack detection
mcp-vault scan --query kubernetes

# Install a tool: integrity gate → writes .mcp.json
mcp-vault install github-mcp-server
mcp-vault install mcp-server-memory --global
```

Detects stack from: `package.json`, `pyproject.toml`, `requirements.txt`, `go.mod`, `Cargo.toml`, `docker-compose.yml`, `.env*` (key names only — no value leaks).

### Supply-chain security scanner

[`scripts/verify_integrity.cjs`](./mcp-ecosystem-intelligence/scripts/verify_integrity.cjs) — run before any install:

```bash
mcp-vault verify
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
mcp-vault docker-drift           # human-readable
mcp-vault docker-drift --json    # machine-readable
mcp-vault docker-drift --strict  # exit 1 on any drift
```

Drift = upstream rebuilt the tag under a new digest. The weekly CI job (`docker-drift`) fails on any drift so a maintainer reviews the upstream change *before* refreshing the pin — a routine rebuild and a registry hijack look identical from here.

### Behavioural smoke (mcp-eval)

[`scripts/mcp_eval.cjs`](./mcp-ecosystem-intelligence/scripts/mcp_eval.cjs) — closes the "did the artifact actually start?" gap. The integrity gate verifies the *file* you downloaded; this script verifies that spawning the server produces a usable tool surface.

For each DB entry with a recognized install method (`npx -y`, `uvx`, `docker run`), the script spawns the subprocess and runs the canonical JSON-RPC handshake — `initialize` → `notifications/initialized` → `tools/list` — then lints each returned tool's `inputSchema` with a minimal validator (intentionally narrower than full JSON Schema Draft 2020-12; covers only what Claude Code actually reads: `type`, `properties`, `required`, `enum`, `description`, plus nested objects + array items).

```bash
mcp-vault eval                       # smoke all (needs network)
mcp-vault eval --name memory         # one entry, substring match
mcp-vault eval --json --strict       # CI form
mcp-vault eval --no-spawn            # offline self-test
```

Output: `assets/eval_results.json` — `{name, status, boot_ms, list_latency_ms, tool_count, tool_count_db, tool_count_drift, schema_errors[], error_code, checked_at}` per entry, sorted by name for deterministic diffs. Results never flow back into `tools_database.json` — DB stays the source of truth, eval is a separate evidence stream.

Network policy: real smoke needs to fetch packages (`npx` cache miss, `uvx` wheel download, `docker pull`), so it is NOT offline. The CI job (`mcp-eval-smoke`) runs cron-only — never on PRs. The `--no-spawn` flag re-lints existing results without spawning anything; that path IS offline.

What it does NOT validate: behavioural correctness (we don't call any tool), business logic, or security of the server's tool implementations. This is a *smoke* check, not a fitness test.

### Discovery pipeline

[`scripts/discover.cjs`](./mcp-ecosystem-intelligence/scripts/discover.cjs) — harvest MCP server candidates from three sources, deduplicate by repo URL, annotate with health metrics from GitHub, score, and emit a candidates JSON ready for manual cherry-pick into `tools_database.json`.

```bash
# Default: all three sources, top-50 candidates, capped at 200 gh api calls
mcp-vault discover --out candidates.json

# Single source / smaller limit
mcp-vault discover --source npm --limit 20 --out candidates.json
```

Sources:

| Source | Endpoint | Notes |
|---|---|---|
| `readme` | `modelcontextprotocol/servers` README | Curated. No `gh` calls. |
| `gh`     | `gh search repos --topic mcp-server / modelcontextprotocol` | Requires `gh auth login`. Topic-tags catch non-MCP projects, filtered out by name/description heuristic. |
| `npm`    | `npm search mcp-server` | Filters to packages with a GitHub `repository` field. |

Annotation uses `gh api repos/<owner>/<repo>` for stars, last commit, license, archive/fork status. Reject heuristics: `<10 stars`, `last_commit > 365 days`, archived, fork, doesn't look like an MCP server in `name`/`description`. Surviving candidates are scored with the same formula as `calculate_health.cjs` and emitted with the same shape as `tools_database.json` entries (minus `pkg_integrity`, which `verify_integrity.cjs --update` fills after manual merge).

The weekly `discover-candidates` CI job runs this script every Thursday and opens a PR refreshing `mcp-ecosystem-intelligence/assets/discovery/candidates.json`. That file is a living *inbox* — never auto-merged into the DB; a human cherry-picks entries with `trust: "candidate"`.

### Audit installed setup

[`scripts/audit_setup.cjs`](./mcp-ecosystem-intelligence/scripts/audit_setup.cjs) — diff the user's installed MCP servers against the DB. Reads `<cwd>/.mcp.json`, the `mcpServers` key of `~/.claude.json` (and *only* that key — auth tokens live elsewhere in the file), and `<cwd>/.claude/settings.json` (`enabledMcpjsonServers`, `permissions.allow`):

```bash
mcp-vault audit            # human-readable
mcp-vault audit --json     # machine-readable findings
mcp-vault audit --strict   # exit 1 on drift/untrusted/heavy
```

| Finding | Trigger |
|---|---|
| `drift` | installed version differs from DB-pinned version |
| `untrusted` | DB `trust: "candidate"` but actively installed |
| `heavy-unbounded` | `est_tools_count > 15` (or unknown) and no `--toolsets`/`--caps`/`allowedTools`/`enabledMcpjsonServers` scoping |
| `unknown` | installed but not in DB (legitimate custom servers ok — informational) |
| `scope` | global install of a typically project-scoped category (`vcs`/`ci-cd`/`pm`/`infra`) |

Exit codes: `0` clean / info-only · `1` `--strict` triggered · `2` bad invocation. Closes the "Audit my MCP setup" use case without an LLM in the critical path.

### Health scorer

[`scripts/calculate_health.cjs`](./mcp-ecosystem-intelligence/scripts/calculate_health.cjs) — score any MCP candidate:

```bash
mcp-vault health \
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

`mcp-ecosystem-intelligence/assets/tools_database.json` — **112 entries** across ~25 categories, all with pinned versions, integrity hashes (npm sha512 / PyPI sha256 / Docker @sha256), SPDX license, and `trust` field.

```
ai        browser   ci-cd      cms       communication   crm
database  demo      docs       filesystem http            infra
maps      memory    meta       mobile     observability   payments
pm        reasoning search     testing    utility         vcs       web-scraping
```

Distribution: **96 Core / 11 Recommended / 5 Experimental**.

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

`.github/workflows/security-scan.yml` runs six jobs across PRs, pushes, and two weekly crons:

- **unit-tests** — `node --test tests/*.test.cjs` on every PR / push (fast, no network). Covers parser helpers, advisory dedup, drift parsing, signal mapping, eval schema lint. Smoke depends on this.
- **smoke** — `verify_integrity.cjs --no-audit` on every PR / push to master (offline, fast).
- **refresh-hashes** — Monday cron, opens a PR refreshing `version` + `pkg_integrity` from live registries. Human-gated before merge.
- **docker-drift** — Monday cron + manual dispatch. Compares each Docker entry's pinned `@sha256:` against the upstream registry digest; fails the job on any drift so a maintainer reviews before refreshing the pin.
- **discover-candidates** — Thursday cron + manual dispatch. Runs `discover.cjs` against the three sources and opens a PR with a fresh `assets/discovery/candidates.json`. The file is an *inbox* — never auto-merged into `tools_database.json`.
- **mcp-eval-smoke** — Monday cron + manual dispatch. Runs `mcp_eval.cjs --json` against the whole DB, uploads `eval_results.json` as an artifact. Cron-only — needs network to fetch packages. Results never auto-commit to the DB.

---

## Roadmap

The following are described in [`SKILL.md`](./mcp-ecosystem-intelligence/SKILL.md) as intended behaviour but are not yet scripted — Claude performs them interactively using available tools (Bash, WebFetch, Read) on each invocation:

| Feature | Status |
|---|---|
| Stack detection from manifests (`package.json`, `pyproject.toml`, …) | [`orchestrate.cjs detectStack()`](./mcp-ecosystem-intelligence/scripts/orchestrate.cjs) — done |
| Registry / aggregator / `gh search` discovery pipeline | [`scripts/discover.cjs`](./mcp-ecosystem-intelligence/scripts/discover.cjs) — done |
| Reject heuristics (5-Minute Rule, Bloat, Duplication) | Claude-executed judgment, no dedicated script |
| Formatted recommendation output (terse / verbose) | Claude-generated, no dedicated formatter |
| Project-scoped `.mcp.json` install (default path) | [`orchestrate.cjs --install`](./mcp-ecosystem-intelligence/scripts/orchestrate.cjs) — done |
| `allowedTools` per-project filtering for heavy servers | Pattern documented in SKILL.md §10; [`audit_setup.cjs`](./mcp-ecosystem-intelligence/scripts/audit_setup.cjs) flags unscoped heavy servers |
| Audit installed setup (drift / untrusted / heavy / scope) | [`scripts/audit_setup.cjs`](./mcp-ecosystem-intelligence/scripts/audit_setup.cjs) — done |
| Wrapper generator (CLI/API → MCP boilerplate) | [`scripts/generate_wrapper.cjs`](./mcp-ecosystem-intelligence/scripts/generate_wrapper.cjs) — done |

---

## Token cost management

Every active MCP server injects its full tool list into Claude's system prompt (~200–500 tokens per tool). With 112 servers in the DB the spread is wide: `mcp-server-fetch` = 1 tool vs. `gitlab-mcp` = 153 tools.

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
mcp-vault wrap \
  --name my-cli-mcp --tool "My CLI" --out ./my-cli-mcp

# Pre-populated with tool definitions from a JSON spec
mcp-vault wrap \
  --name warehouse-mcp --tool "Internal Warehouse" \
  --tools-file ./tools.json \
  --out ./warehouse-mcp
```

`tools.json` is an array of MCP tool defs (`name` / `description` / `inputSchema`); the generator emits `ListToolsRequestSchema` entries plus `switch`-cases with `required`-arg validation, runs Node's `--check` on the result, and writes a `.mcp.json`-ready README.

Underlying template lives in `mcp-ecosystem-intelligence/assets/mcp-wrapper-template/` if you'd rather edit by hand.

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the entry schema, reject criteria, the triage checklist for promoting `trust: candidate` to `trust: verified`, and the review process for changes to the integrity gate.

Running the suite locally:

```bash
node --test tests/*.test.cjs                                              # unit tests (offline, < 1s)
mcp-vault verify --no-audit   # DB smoke
```

---

## Topics

`claude-code` · `claude-skill` · `mcp` · `model-context-protocol` · `mcp-server` · `mcp-tools` · `anthropic` · `ai-agents`

## License

[MIT](./LICENSE)
