---
name: mcp-ecosystem-intelligence
description: Find, evaluate, and install MCP servers for a project. Use when the user asks "is there an MCP for X", "what MCP tools should I use here", "add MCP server for Y", "audit my MCP setup", "is package Z safe to install", or wants to wrap an existing CLI/API as MCP. Combines a seeded local database, registry-first discovery, a Health Score script, a supply-chain security scanner (sha512/sha256 integrity, install-hook detection, npm advisory + OSV.dev CVE check, Docker digest pinning) gating every install, and a concrete install path via direct edit of ~/.claude.json.
---

# MCP Ecosystem Intelligence

Pragmatic discovery agent for the MCP ecosystem. Optimised for token efficiency: cache-first lookups, scripted scoring, terse output by default.

## Implementation status

Steps marked **[scripted]** have a dedicated script you call via Bash. Steps marked **[Claude]** are executed by Claude using available tools (Read, Bash, WebFetch) — no standalone script exists yet.

```
1. Detect stack         → [scripted] node scripts/orchestrate.cjs --cwd $CWD
2. Cache lookup         → [scripted] included in orchestrate.cjs output
3. Discovery (if miss)  → [Claude]   WebFetch registry + Bash gh search
4. Validate (5 checks)  → [scripted] node scripts/verify_integrity.cjs
5. Score                → [scripted] node scripts/calculate_health.cjs <args>
6. Reject heuristics    → [Claude]   apply 5-Minute / Bloat / Duplication rules
7. Recommend            → [scripted] included in orchestrate.cjs output (with tool count)
8. Install (on consent) → [scripted] node scripts/orchestrate.cjs --install <name>
9. Update DB            → [Claude]   append/update assets/tools_database.json
```

Default output mode is **terse**. The user can ask for "verbose" / "explain" to flip into the long form.

---

## 1. Stack detection (fast scan)

Read the project's manifest files only. Do not exhaustively walk source. Use the Read tool for each file that exists in `$CWD`:

```
package.json          → Node ecosystem, frameworks (next, express, remix, …)
pyproject.toml        → Python deps
requirements.txt      → Python deps (fallback)
go.mod                → Go
Cargo.toml            → Rust
docker-compose.yml    → DBs, queues, side-services
.env / .env.example   → Cloud providers, API surfaces (look for key prefixes)
```

Emit one line before any further output:
`Stack: <langs> | DB: <dbs> | Infra: <cloud/k8s/…> | Needs: <inferred MCP categories>`

Skip files that do not exist — do not error if the directory has none of them.

## 2. Run the orchestrator first

**Always start here.** The orchestrator deterministically handles steps 1, 2, and 7 — stack detection, DB match, and formatted recommendations — in a single fast command:

```bash
# Scan the current project and match the DB
node mcp-ecosystem-intelligence/scripts/orchestrate.cjs --cwd $CWD

# Targeted keyword search (cache miss for a specific need)
node mcp-ecosystem-intelligence/scripts/orchestrate.cjs --cwd $CWD --query <keyword>

# Machine-readable output for programmatic use
node mcp-ecosystem-intelligence/scripts/orchestrate.cjs --cwd $CWD --json

# Install a tool (runs verify_integrity gate, writes .mcp.json)
node mcp-ecosystem-intelligence/scripts/orchestrate.cjs --install <name>
node mcp-ecosystem-intelligence/scripts/orchestrate.cjs --install <name> --global  # → ~/.claude.json
```

If orchestrate.cjs reports a cache miss (no matches) or the user asks about something not in the DB, proceed to step 3 (live discovery). If it prints recommendations, skip steps 3–6 and go straight to user consent → step 8.

### 2a. Audit the installed setup (when the user asks "audit my MCP setup")

For the audit/inspection workflow — "is my current setup drifted, untrusted, or unbounded?" — run the dedicated script instead of walking the DB by hand:

```bash
# Human-readable, grouped by finding category
node mcp-ecosystem-intelligence/scripts/audit_setup.cjs --cwd $CWD

# Machine-readable findings array (for further processing or CI gates)
node mcp-ecosystem-intelligence/scripts/audit_setup.cjs --cwd $CWD --json

# Hard-fail on drift / untrusted / heavy-unbounded — CI-friendly
node mcp-ecosystem-intelligence/scripts/audit_setup.cjs --cwd $CWD --strict
```

Diffs `<cwd>/.mcp.json` and the `mcpServers` key of `~/.claude.json` (NEVER any other key — auth tokens live elsewhere in that file) against `tools_database.json`. Emits findings in five categories: `drift` (version mismatch), `untrusted` (DB candidate in active use), `heavy-unbounded` (≥15 tools with no `--toolsets`/`--caps`/`allowedTools`/`enabledMcpjsonServers` scoping), `unknown` (custom server, informational), and `scope` (vcs/ci-cd/pm/infra category installed globally — usually belongs in project `.mcp.json`).

Exit codes: `0` clean or info-only · `1` strict-mode triggered · `2` bad invocation.

## 3. Discovery (only on cache miss)

Strict tier order. Stop at the first tier that yields a viable candidate.

**Tier 1 — official registry + known vendor servers**

Fetch all registry entries and filter client-side (no server-side search; ~30–300 entries, pagination via `metadata.nextCursor`):

```bash
# Page 1 — returns {servers: [...], metadata: {nextCursor, count}}
# Use WebFetch: https://registry.modelcontextprotocol.io/v0/servers
# Next page (when nextCursor present):
# https://registry.modelcontextprotocol.io/v0/servers?cursor=<nextCursor>
```

Each list item wraps the real entry in `server`. The shape (verified live, 2026-05) is:

```json
{
  "server": {
    "name": "io.github.owner/repo",
    "title": "Human-readable title",
    "description": "...",
    "repository": { "url": "https://github.com/owner/repo", "source": "github" },
    "packages": [
      {
        "registryType": "npm" | "pypi" | "oci",
        "identifier": "@scope/package" | "pypi-name" | "ghcr.io/owner/img",
        "version": "1.2.3"
      }
    ]
  }
}
```

There is **no** `installCommand` field — synthesize it from `packages[0]`:

- `npm`  → `npx -y <identifier>@<version>`
- `pypi` → `uvx <identifier>==<version>`
- `oci`  → `docker run --rm -i <identifier>` (version baked into the tag/digest by the publisher)

If `version` is absent, drop the `@<version>` / `==<version>` suffix. Filter by keyword in `server.title`, `server.description`, `server.name`. Pull the repo URL from `server.repository.url` for downstream `gh api` annotation.

The reference implementation is `scripts/discover.cjs::fromMcpRegistry()` (`parseRegistryPage` does the actual field extraction and synthesis).

Also check the [`modelcontextprotocol/servers`](https://github.com/modelcontextprotocol/servers) monorepo README and vendor-maintained servers linked from there (github, microsoft/playwright, cloudflare, notion, sentry, …). Use WebFetch on those pages if needed.

**Tier 2 — aggregators** (only if Tier 1 empty)

WebFetch PulseMCP (`https://www.pulsemcp.com/servers?search=<keyword>`) or Smithery. Extract name, repo URL, install command.

**Tier 3 — fallback** (only if Tier 1 + 2 empty)

```bash
gh search repos --topic mcp-server <keyword> --limit 10 \
  --json fullName,stargazersCount,pushedAt,description

# Also try npm search
npm search mcp-server-<keyword> --json | jq '.[0:5] | .[] | {name, description, links}'
```

If all tiers return nothing, proceed to §8 (wrapper generation).

## 4. Validation (all five required)

A candidate is **rejected** if any check fails:

1. **Install command** is documented (`npx -y …`, `uvx …`, `pip install …`, `docker run …`).
2. **MCP wiring** is detectable: `server.json` present **or** `@modelcontextprotocol/sdk` / `mcp` (Python) imported in source.
3. **At least one tool** is registered in the server's `ListTools` response (read code or `npx … --help`).
4. **Recent commit**: default branch was pushed within 180 days.
5. **Integrity + source verify** (npm packages only): run the integrity script to confirm the tarball hash and that npm's `repository.url` matches `source_url`. A mismatch is a hard reject — it indicates a typosquatted or hijacked package.

```bash
node mcp-ecosystem-intelligence/scripts/verify_integrity.cjs
# or for a single candidate not yet in the DB:
npm view "<pkg>@<version>" dist.integrity repository.url
```

For packages where npm declares no `repository.url` (some official vendor packages skip this field), verify `source_url` manually against the GitHub page before adding to the DB and document the gap in `notes`.

## 5. Health Score (use the script)

Pull the four metrics with `gh api`, then call the scoring script. Don't eyeball it.

```bash
REPO="owner/name"
META=$(gh api "repos/$REPO")
stars=$(echo "$META"   | jq -r '.stargazers_count')
pushed=$(echo "$META"  | jq -r '.pushed_at')
issues=$(echo "$META"  | jq -r '.open_issues_count')
days=$(( ( $(date -u +%s) - $(date -u -j -f '%Y-%m-%dT%H:%M:%SZ' "$pushed" +%s) ) / 86400 ))
# 'critical_issues' heuristic: open_issues_count / 10 (rough proxy for noise level).
crit=$(( issues / 10 ))
in_registry=true   # true only if listed under registry.modelcontextprotocol.io
license=$(echo "$META" | jq -r '.license // "Unknown"')
node mcp-ecosystem-intelligence/scripts/calculate_health.cjs \
     "$stars" "$days" "$in_registry" true "$crit" "$license"
```

Output:
```json
{ "health_score": 90, "classification": "Core",
  "breakdown": { "popularity": 20, "recency": 20, "registry": 30, "install_cmd": 15, "low_issues": 5 } }
```

Formula (max 110):
```
score = min(20, 10·log10(stars+1))   # popularity, capped
      + {40|20|10|0} by last_commit  # <30d / <90d / <180d / older
      + 30 if in_registry
      + 15 if install_cmd
      + 5  if open_issues/10 < 5
      − 10 if license is non-OSI / source-available / Unknown
```

The license penalty applies to FSL/BSL/SSPL/Elastic-2.0/Commons Clause and similar source-available licenses, plus packages with no published license. OSI-approved permissive (MIT/Apache/BSD/ISC/MPL) and copyleft (GPL/LGPL/AGPL) get no penalty — they're still open source.

Tier mapping (matches `classify()` in `scripts/calculate_health.cjs`):

| Score  | Tier         | Action                |
|--------|--------------|-----------------------|
| 85+    | Core         | recommend by default  |
| 65–84  | Recommended  | recommend with note   |
| 40–64  | Experimental | mention only on ask   |
| < 40   | Deprecated   | hide unless asked     |

## 6. Reject heuristics (taste, not just score)

A high score isn't enough. Before recommending, apply these three rules in order:

**5-Minute Rule** — reject if the tool wraps something Claude can do natively in under 5 minutes with no external dependency. Examples that fail this rule: a server that only does HTTP GET (Claude has WebFetch), one that only runs `cat`/`grep`/`ls` (Claude has Bash + Read). Examples that pass: database drivers, browser automation, authenticated API wrappers with complex auth flows.

**Bloat Check** — reject if the install pulls in a heavy runtime (>100 MB) to expose ≤3 trivial functions. Check with:
```bash
npm pack <pkg> --dry-run 2>/dev/null | grep 'package size'
```

**Duplication Check** — if two candidates cover the same category, keep the one with the higher health score and log the other as rejected with reason "covered by <winner>".

Log every rejection as a one-line entry for the Skipped section of §9 output.

## 7. Database update

`assets/tools_database.json` schema (the seeded file in this repo is the canonical example, 106 entries across ~25 categories):

```json
{
  "tools": [
    {
      "name": "string (kebab-case)",
      "category": "database|search|infra|browser|docs|vcs|...",
      "install_cmd": "single-line shell command with pinned version",
      "source_url": "https://github.com/owner/name",
      "stars": 0,
      "last_commit_days": 0,
      "open_issues": 0,
      "in_registry": true,
      "health_score": 0.0,
      "classification": "Core|Recommended|Experimental|Deprecated",
      "est_tools_count": 10,
      "toolsets": "--flag value  # how to filter; null = no filtering available",
      "last_checked": "YYYY-MM-DD",
      "version": "1.2.3 or null for non-npm",
      "pkg_integrity": "sha512-… or null for non-npm",
      "trust": "verified|candidate",
      "license": "MIT|Apache-2.0|… (SPDX); non-OSI triggers -10 score penalty",
      "notes": "optional, short caveat"
    }
  ]
}
```

**Field semantics:**
- `install_cmd` — always pin to an explicit version (`@1.2.3`), never `@latest`.
- `version` — the pinned npm/PyPI version; `null` for docker or git-URL installs.
- `pkg_integrity` — `dist.integrity` from `npm view <pkg>@<version>` (sha512 of the tarball); `null` for non-npm. Run `node scripts/verify_integrity.cjs --update` to populate or refresh.
- `trust` — `"verified"` means the tarball integrity hash was confirmed against the registry at time of seeding; it does **not** mean the source code was audited. `"candidate"` means the entry was added from live discovery or cannot be fully verified (e.g. git-URL installs). Candidate entries are recommended with a ⚠️ warning rather than silently hidden.
- `est_tools_count` — estimated number of tools the server injects into Claude's context (each tool ~200–500 tokens). Use this to flag heavy servers and guide scoping decisions.
- `toolsets` — string hint describing how to reduce the tool count (CLI flag, config key, or env var). `null` means the server has no native filtering. High `est_tools_count` + `null` toolsets → consider `allowedTools` in `.claude/settings.json` or project-scoped `.mcp.json` instead of global install.

Sorted by `(category, -health_score, name)` for deterministic diffs.

`assets/extensions_database.json` — CLI/API tools without an MCP wrapper, candidates for §8:

```json
{ "extensions": [ { "name": "", "cli_or_api": "", "wrapper_generated": false, "notes": "" } ] }
```

After every discovery+validation cycle, append/update entries in both files. Bump `last_checked`. New entries from discovery always start with `"trust": "candidate"` — upgrade to `"verified"` only after §4 check 5 passes.

## 8. Wrapper generation (only when nothing fits)

Only generate when validation in §4 returned **zero** viable MCP servers for the need. Use `assets/mcp-wrapper-template/` as the starting point:

- `server.js` — replace `{{name}}` and add tool definitions in the `ListTools` handler.
- `package.json` — set `name` and `description`, keep pinned `@modelcontextprotocol/sdk` major.
- Add a one-paragraph README with the install command.

After generation, register the resulting wrapper in `tools_database.json` with `in_registry=false` and re-score.

## 9. Recommendation output

**Default — terse**. One-screen, copy-pasteable. Reuses the user's stack line for context.

```
Stack: Node/Next.js | DB: Postgres | Needs: db, search, deploy

Recommended (Core / Recommended)
  database     mcp-server-neon         npx -y @neondatabase/mcp-server-neon         (score 110, Core, 29 tools)
  search       exa-mcp-server          npx -y exa-mcp-server                         (score 80, Recommended, 5 tools)
  deploy       mcp-server-cloudflare   npx -y @cloudflare/mcp-server-cloudflare      (score 105, Core, 5 tools)

Heavy (use with scoping)
  vcs          github-mcp-server       docker run ghcr.io/github/…                   (score 105, Core, 100 tools ⚠️  --toolsets repos,issues)
  vcs          gitlab-mcp              npx -y @zereight/mcp-gitlab                   (score 80, Recommended, 153 tools ⚠️  no filter — project-scope only)

Skipped
  postgres-mcp           — covered by neon (duplication)
  generic-fetch-wrapper  — 5-Minute Rule (model can curl)
```

Token cost rules:
- ≥ 30 tools → flag with ⚠️ in terse output; show `toolsets` hint if available.
- ≥ 30 tools + `toolsets: null` → recommend project-scope install (`.mcp.json`) rather than global.
- < 10 tools → no flag needed; safe for global install.

**Verbose** — only when asked: include score breakdown, full install snippets, alternates per category.

## 10. Installation (on user consent)

After the user picks tools, follow the three steps below in order. Never skip step 1.

### Step 1 — security scan

```bash
node mcp-ecosystem-intelligence/scripts/verify_integrity.cjs
# Exit 0 = all clear.  Exit 1 = ABORT — do not install until failures are resolved.
```

**What it covers:**

| Ecosystem | Integrity | Source URL | Hooks | Advisories |
|---|---|---|---|---|
| npm (`npx -y`) | sha512 SRI from npm | `repository.url` | `pre/post/install` + `prepare/prepack` | npm advisory bulk API |
| PyPI (`uvx`) | sha256 of sdist | `project_urls` (Source/Homepage/…) | n/a | OSV.dev `/v1/querybatch` |
| Docker (`docker run`) | image must be pinned by `@sha256:…` digest | n/a | n/a | n/a |
| `uvx --from git+…` | not verifiable — SKIPPED | — | — | — |

**Flags:**
| Flag | Effect |
|---|---|
| *(default)* | integrity + advisory check + hook detection |
| `--strict` | treat WARNs (hook, repo mismatch, unpinned docker) as hard failures |
| `--no-audit` | skip advisory APIs (offline/air-gapped environments) |
| `--update` | refresh `version` + `pkg_integrity` fields from registries |

**Interpreting output:**

| Prefix | Meaning | Action |
|---|---|---|
| `OK` | integrity hash matches, no CVEs | proceed |
| `MISS` | no stored hash yet | run `--update` first |
| `HOOK` | npm package has install-time scripts | review the script shown; `prepare: npm run build` is normal TypeScript compilation; postinstall doing network calls or writing outside the package dir is suspicious |
| `WARN` | source URL mismatch, unpinned docker digest, or other reviewable issue | check manually before installing |
| `NOTE` | informational (e.g. registry has no source URL declared) | source verifiable manually only |
| `CVE` | advisory found; high/critical = hard fail | do not install; look for a patched version or alternative |
| `FAIL` | stored hash does not match registry tarball | hard abort — tarball has changed; investigate before proceeding |
| `SKIP` | install method not verifiable (e.g. `uvx --from git+…`) | source-pin manually before adding to DB |

### Step 1b — behavioural smoke (optional, network-bound)

`verify_integrity.cjs` checks the *artifact you got* (hash matches the registry). It does NOT check that the artifact starts and exposes a usable tool surface. `mcp_eval.cjs` closes that gap:

```bash
# Smoke one entry before installing it for real
node mcp-ecosystem-intelligence/scripts/mcp_eval.cjs --name <pkg> --timeout 60000

# Smoke the whole DB (slow; runs in weekly CI)
node mcp-ecosystem-intelligence/scripts/mcp_eval.cjs --json
```

For each entry the script spawns the server, runs `initialize` → `tools/list`, and lints each tool's `inputSchema` (minimal lint: top-level `type: object` + `properties` + `required` consistency + nested object/array types; rejects `$ref`). Pass means the handshake worked. Tool-count drift (`tool_count_drift: true`) means the DB's `est_tools_count` is stale and the recommendation needs a refresh.

This step needs network (npx/uvx fetch the package). For air-gapped flows, skip it — `verify_integrity.cjs` covers the supply-chain side; eval is purely an additional confidence layer. The `--no-spawn` flag lints existing `eval_results.json` without touching the network.

Eval results are written to `assets/eval_results.json` — never back into `tools_database.json`. They're an evidence stream, not a DB mutation.

### Step 2 — choose the install method

**Prefer Docker where an official image exists, pinned by digest.** Use `@sha256:<digest>` rather than `:latest` — the verifier flags any unpinned image with `WARN` (or `FAIL` under `--strict`). Refresh digests with:

```bash
docker manifest inspect <image> | jq -r '.manifests[0].digest // .config.digest'
```

Hardened Docker template:

```bash
docker run -i --rm \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  -e SECRET_VAR \
  ghcr.io/vendor/mcp-server@sha256:<digest>
```

For npm/PyPI servers without an upstream image, the verifier still catches integrity drift via `pkg_integrity`. Whether to additionally wrap them in a generic container is an extra (manual) hardening step — `--read-only` breaks many servers that cache locally, so apply it case-by-case.

### Step 3 — write to `.mcp.json` (project-scoped) or `~/.claude.json` (global)

**Default: project-scoped `.mcp.json`** in the repository root. This keeps the server active only in that project and avoids injecting unused tools into unrelated conversations.

**Use `~/.claude.json` only for servers needed in every project** — typically `mcp-server-filesystem` and `mcp-server-memory`.

Do **not** run `claude mcp add`. The CLI prints the bearer token to stdout, which leaks into transcripts and shell history. Edit files directly instead.

#### Option A — project-scoped `.mcp.json` (default)

Create or update `.mcp.json` in the project root. For heavy servers (≥ 30 tools), add the toolsets flag to `args`:

```json
{
  "mcpServers": {
    "github": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "-e", "GITHUB_PERSONAL_ACCESS_TOKEN",
        "--toolsets", "repos,issues,pull_requests",
        "ghcr.io/github/github-mcp-server@sha256:2ac27ef03461ef2b877031b838a7d1fd7f12b12d4ace7796d8cad91446d55959"
      ],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_TOKEN}"
      }
    }
  }
}
```

Show the user the proposed `.mcp.json` diff before writing. Claude Code picks it up automatically on the next session start.

#### Option B — global `~/.claude.json` (filesystem / memory only)

For truly global servers, edit `~/.claude.json` via Python so secrets never appear on the command line:

```bash
TOKEN_ENV=GITHUB_TOKEN python3 - <<'PY'
import json, os, pathlib, shutil, time
cfg = pathlib.Path.home() / ".claude.json"
shutil.copy(cfg, str(cfg) + f".bak.{int(time.time())}")
data = json.loads(cfg.read_text())
data.setdefault("mcpServers", {})["filesystem"] = {
    "command": "npx",
    "args": ["-y", "@modelcontextprotocol/server-filesystem@2026.1.14", os.environ["HOME"]],
}
cfg.write_text(json.dumps(data, indent=2))
print("Done. Restart Claude Code to pick up the new server.")
PY
```

Always:
- Back up `~/.claude.json` before writing (shown above).
- Read secrets from environment variables, never from CLI arguments.
- Show the user a diff of the proposed change before applying.

#### Option C — `allowedTools` for servers without native filtering

If a server has `est_tools_count ≥ 30` and `toolsets: null` (e.g. gitlab-mcp, mcp-atlassian), and project-scoping alone isn't enough, restrict visible tools in `.claude/settings.json`:

```json
{
  "allowedTools": [
    "mcp__gitlab__create_merge_request",
    "mcp__gitlab__list_issues",
    "mcp__gitlab__get_pipeline_status"
  ]
}
```

Tool names follow the pattern `mcp__<server-name>__<tool-name>`. List only what the project actually needs.

## Operating principles

- **Cache-first**: every step starts with `tools_database.json`.
- **Script the score**: `calculate_health.cjs` is the source of truth, not vibes.
- **Strict validation**: all five §4 checks must pass.
- **Taste filter**: §6 heuristics override raw score.
- **Terse output**: §9 default. Verbose on request.
- **No token leaks**: §10 path always.
- **Scan before install**: `verify_integrity.cjs` exit 0 is a hard prerequisite.
