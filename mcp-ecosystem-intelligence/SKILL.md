---
name: mcp-ecosystem-intelligence
description: Find, evaluate, and install MCP servers for a project. Use when the user asks "is there an MCP for X", "what MCP tools should I use here", "add MCP server for Y", "audit my MCP setup", "is package Z safe to install", or wants to wrap an existing CLI/API as MCP. Combines a seeded local database, registry-first discovery, a Health Score script, a supply-chain security scanner (sha512/sha256 integrity, install-hook detection, npm advisory + OSV.dev CVE check, Docker digest pinning) gating every install, and a concrete install path via direct edit of ~/.claude.json.
---

# MCP Ecosystem Intelligence

Pragmatic discovery agent for the MCP ecosystem. Optimised for token efficiency: cache-first lookups, scripted scoring, terse output by default.

## TL;DR runbook

```
1. Detect stack         → from manifests in $CWD (package.json, pyproject.toml, …)
2. Cache lookup         → assets/tools_database.json keyed by need
3. Discovery (if miss)  → registry → vendor official → community
4. Validate (5 checks)  → install cmd, MCP SDK, ListTools, recent commit, integrity
5. Score                → node scripts/calculate_health.cjs <args>
6. Reject heuristics    → 5-Minute Rule, Bloat, Duplication
7. Recommend            → grouped by category, sorted by score
8. Install (on consent) → verify integrity, then edit ~/.claude.json (NOT `claude mcp add`)
9. Update DB            → append to assets/tools_database.json
```

Default output mode is **terse**. The user can ask for "verbose" / "explain" to flip into the long form.

---

## 1. Stack detection (fast scan)

Read the project's manifest files only. Do not exhaustively walk source.

| File                    | Signals                       |
|-------------------------|-------------------------------|
| `package.json`          | Node ecosystem, frameworks    |
| `pyproject.toml`/`requirements.txt` | Python deps         |
| `go.mod`, `Cargo.toml`  | Go / Rust                     |
| `docker-compose.yml`    | DBs, queues, side services    |
| `.env*`                 | Cloud providers, API surfaces |

Emit one line: `Stack: <langs> | DB: <dbs> | Infra: <cloud/k8s/…> | Needs: <inferred MCP categories>`.

## 2. Cache first

Always read `assets/tools_database.json` before any network call.

```bash
jq '.tools[] | select(.classification!="Deprecated") | {name,install_cmd,classification}' \
   mcp-ecosystem-intelligence/assets/tools_database.json
```

If a cached entry covers the user's need and `last_checked` is within 30 days, return it immediately. Skip steps 3–6.

## 3. Discovery (only on cache miss)

Strict tier order. Stop at the first tier that yields a viable candidate.

- **Tier 1 — official registry**: `https://registry.modelcontextprotocol.io`, the [`modelcontextprotocol/servers`](https://github.com/modelcontextprotocol/servers) monorepo, and vendor-maintained servers linked from there (github, microsoft/playwright, cloudflare, notion, sentry, …).
- **Tier 2 — aggregators**: PulseMCP, Smithery, MetaMCP. Use only if Tier 1 has nothing.
- **Tier 3 — fallback**: `gh search repos 'topic:mcp-server <keyword>'`, npm/PyPI search.

```bash
gh search repos --topic mcp-server <keyword> --limit 10 \
  --json fullName,stargazersCount,pushedAt,description
```

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
node mcp-ecosystem-intelligence/scripts/calculate_health.cjs \
     "$stars" "$days" "$in_registry" true "$crit"
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
```

Tier mapping (matches `classify()` in `scripts/calculate_health.cjs`):

| Score  | Tier         | Action                |
|--------|--------------|-----------------------|
| 85+    | Core         | recommend by default  |
| 65–84  | Recommended  | recommend with note   |
| 40–64  | Experimental | mention only on ask   |
| < 40   | Deprecated   | hide unless asked     |

## 6. Reject heuristics (taste, not just score)

A high score isn't enough — also reject when:

- **5-Minute Rule** — the tool wraps something the model can do natively in <5 min (e.g. `cat`/`grep`/HTTP GET).
- **Bloat Check** — a 200MB framework is being pulled in to expose three trivial functions.
- **Duplication Check** — already an accepted MCP in the same category with a higher score; keep the winner.

Log every rejection with a one-line reason (used in the final output, see §9).

## 7. Database update

`assets/tools_database.json` schema (the seeded file in this repo is the canonical example, 31 entries across 14 categories):

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
      "last_checked": "YYYY-MM-DD",
      "version": "1.2.3 or null for non-npm",
      "pkg_integrity": "sha512-… or null for non-npm",
      "trust": "verified|candidate",
      "notes": "optional, short caveat"
    }
  ]
}
```

**Field semantics:**
- `install_cmd` — always pin to an explicit version (`@1.2.3`), never `@latest`.
- `version` — the pinned npm/PyPI version; `null` for docker or git-URL installs.
- `pkg_integrity` — `dist.integrity` from `npm view <pkg>@<version>` (sha512 of the tarball); `null` for non-npm. Run `node scripts/verify_integrity.cjs --update` to populate or refresh.
- `trust` — `"verified"` for entries in the seeded DB (manually reviewed); `"candidate"` for entries added from live discovery. Only `"verified"` entries are recommended by default; `"candidate"` entries require explicit user opt-in.

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
  database     mcp-server-neon         npx -y @neondatabase/mcp-server-neon         (score 92, Core)
  search       brave-search-mcp        npx -y brave-search-mcp                       (score 71, Recommended)
  deploy       mcp-server-cloudflare   npx -y @cloudflare/mcp-server-cloudflare      (score 88, Core)

Skipped
  postgres-mcp           — covered by neon (duplication)
  generic-fetch-wrapper  — 5-Minute Rule (model can curl)
```

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

### Step 3 — write to `~/.claude.json`

Install by **directly editing `~/.claude.json`** rather than running `claude mcp add`. The CLI prints the bearer token to stdout, which leaks into transcripts and shell history; an in-place edit doesn't.

Pattern (Python so secrets never appear on the command line):

```bash
TOKEN_ENV=GITHUB_TOKEN python3 - <<'PY'
import json, os, pathlib, shutil, time
cfg = pathlib.Path.home() / ".claude.json"
shutil.copy(cfg, str(cfg) + f".bak.{int(time.time())}")
data = json.loads(cfg.read_text())
data.setdefault("mcpServers", {})["github"] = {
    "command": "docker",
    "args": ["run", "-i", "--rm",
             "--cap-drop", "ALL",
             "--security-opt", "no-new-privileges",
             "-e", "GITHUB_PERSONAL_ACCESS_TOKEN",
             "ghcr.io/github/github-mcp-server@sha256:2ac27ef03461ef2b877031b838a7d1fd7f12b12d4ace7796d8cad91446d55959"],
    "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": os.environ["GITHUB_TOKEN"]},
}
cfg.write_text(json.dumps(data, indent=2))
print("Done. Restart Claude Code to pick up the new server.")
PY
```

Always:
- Back up `~/.claude.json` before writing (shown above).
- Read secrets from environment variables, never from CLI arguments.
- Show the user a diff of the proposed change before applying.

## Operating principles

- **Cache-first**: every step starts with `tools_database.json`.
- **Script the score**: `calculate_health.cjs` is the source of truth, not vibes.
- **Strict validation**: all five §4 checks must pass.
- **Taste filter**: §6 heuristics override raw score.
- **Terse output**: §9 default. Verbose on request.
- **No token leaks**: §10 path always.
- **Scan before install**: `verify_integrity.cjs` exit 0 is a hard prerequisite.
