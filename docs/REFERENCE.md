# Command reference

`mcp-vault <command> --help` is the authority for every flag; this page says
what each command is for and what it does that is not obvious from the flag
list. Commands are grouped by who runs them.

Common to the deciding commands: `--json` (machine-readable, a schema id per
[COMPATIBILITY.md](COMPATIBILITY.md)), `--strict` (warnings fail too),
`--fail-on deny|unknown|warn`, `--as-of <date>` where the command judges stored
evidence, and exit codes `0` / `1` / `2` ([how it decides](HOW-IT-DECIDES.md)).

- [Checking a repository: `check`](#checking-a-repository-check)
- [Your machine: `status`, `audit`, `secrets`, `verify --installed`, `budget`, `doctor`](#your-machine)
- [Freezing what runs: `lock`, `approve`, `sbom`](#freezing-what-runs)
- [Known servers: `list`, `scan`, `explain`, `install`, `upgrade`](#known-servers)
- [The integrity gate: `verify`](#the-integrity-gate-verify)
- [Evidence about servers: `availability`, `identity`, `posture`, `capabilities`, `tool-scan`, `eval`, drift](#evidence-about-servers)
- [Trust in the DB itself: `signature`, `audits`](#trust-in-the-db-itself)
- [Publishing: `badge`, `site-registry`, `export-registry`, `registry-ingest`](#publishing)
- [Maintainer tools: `discover`, `refresh`, `health`, `wrap`](#maintainer-tools)

---

## Checking a repository: `check`

```bash
mcp-vault check                                  # .mcp.json, .vscode/mcp.json, .cursor/mcp.json here
mcp-vault check path/to/.mcp.json other/mcp.json # exactly these files
mcp-vault check --fail-on unknown --sarif > mcp-vault.sarif
```

One pass over the project-scoped MCP configs, one decision per finding, one
exit code. It reads exactly the files given (or the three defaults) and
nothing from the home directory, so the answer does not depend on whose
machine runs it. This is what the [GitHub Action](GITHUB_ACTION.md) and the
pre-commit hook run.

What it checks, per configured server:

| Finding family | What it means |
|---|---|
| `config/unpinned-launch` | no exact version: none, `@latest`, a range (`^1.2`, `>=1.2`, `~=1.2`; only `==X` pins on PyPI) |
| `config/launch-source-override` | the package comes from somewhere else than the public registry: `--registry`, `--userconfig`, a uv index, `--find-links`, `npm_config_registry` / `UV_INDEX_URL` in the server's env, … Reported as `unknown`, never checked against the public registry as if it came from there |
| `pin/*`, `verify/*` | a launch of a known server compared with the vault's pin (another version → `unknown`, no stored hash for it); not in the vault → `unknown`. With `--online`, the registry's hash, install hooks and the advisory feeds too |
| `secrets/*` | a credential in plain text in `env`, `args`, `headers` or `url` — deny. The value is never printed |
| `lookalike/*` | a name shaped like a vault entry: typo, homoglyph, scope swap, affix |
| `flows/*`, `shadowing/*` | what the servers of one config can do together (toxic flows, tool shadowing) |
| `tool-scan/*` | stored tool-description scans for servers the eval has seen (the snapshot shipped with 0.16.0 carries none yet; run `tool-scan` on a captured `tools/list`) |
| `org/*`, `policy/*` | your policy file, if any |

Launches are read the way their runner reads them: `npx` options in any order
(`--yes`, `-q`, `--`, `-p pkg bin`, several `-p`), `npm exec`, `pnpx` /
`pnpm dlx`, `bunx`, `yarn dlx`, `uvx` (`--from pkg==1 bin`), `uv tool run`,
`pipx run`. Every `-p` package is checked, not only the binary's. An option it
does not know is reported as such, never guessed past.

A **remote server** (`"url": …`) ships no artifact, so there is nothing to pin
or hash: it is checked for secrets in its URL and headers and for flows, and
is otherwise `unknown` ("trust is in the endpoint"). Under `--fail-on unknown`
— the Action's default — that fails; set `fail-on: error` if your configs use
remote servers on purpose.

Offline by default. `--online` adds the live registries and advisory feeds.
`--json` is `mcp-vault/findings@1`; `--sarif` puts each result on the config
line it is about.

---

## Your machine

### `status`

```bash
npx -y @froggychips/mcp-vault status
```

One screen over every host config on this machine (Claude Code project and
user scope, Claude Desktop, Cursor, VS Code, Codex) and the current project:
what is installed, which servers the vault knows and on which version, how old
the evidence is, the context cost, toxic flows, and a short list of what blocks
and what is worth knowing. No network calls; every claim says it comes from
stored evidence. Exit `1` when something installed must not run (gone, yanked,
wrong bytes, a recorded advisory, a plain-text credential); `--strict` also
fails on drift, unvetted servers and stale evidence. Servers are matched by
**what they launch**, not by the name in your config, and a version nobody
verified gets no tier at all.

### `audit`

Diffs the installed servers (`<cwd>/.mcp.json`, the `mcpServers` maps of
`~/.claude.json` — and only those keys — and `<cwd>/.claude/settings.json`)
against the DB:

| Category | Trigger |
|---|---|
| `drift` | installed version differs from the DB pin |
| `untrusted` | DB `trust: candidate` but installed |
| `heavy-unbounded` | more than 15 tools (measured where the eval measured it, else the DB estimate; unknown counts too) and no scoping (`--toolsets`, `--caps`, `allowedTools`, `enabledMcpjsonServers`) |
| `unknown` | not in the DB (custom servers are fine — informational) |
| `scope` | a project-scoped category (`vcs`, `ci-cd`, `pm`, `infra`) installed globally |
| `secret` | a plain-text credential (see `secrets`) |
| `lookalike`, `toxic-flow`, `tool-shadowing` | as in `check` |

A plain-text secret fails by default; everything else fails under `--strict`.

### `secrets`

```bash
mcp-vault secrets                 # exit 1 if anything is found
mcp-vault secrets --fix-suggest   # a suggested edit per finding; nothing is changed
mcp-vault secrets --explain       # the decision trace, rule → finding
mcp-vault secrets --sarif
```

Reads the server maps of every host config (never the rest of
`~/.claude.json`) and reports credentials in `env`, `args`, `headers` and
`url`: known formats (GitHub, GitLab, AWS, Slack, OpenAI, Anthropic, Stripe,
Google, JWT, PEM keys, database URLs with a password, Bearer tokens, tokens in a
query string) and literal high-entropy values under credential-named keys. A
`${VAR}` / `${env:VAR}` / `${input:id}` reference is not a finding.

**The value is never printed** — not in text, JSON, SARIF or the trace: a
finding is the type, file, key path, length and a masked prefix of at most
four characters (only a format's public prefix, like `ghp_`). A config tracked
by git is severity `high` — the value is in history, so rotate it. The
suggested fix uses the reference syntax each host documents (`${VAR}` in
`.mcp.json`, `${env:NAME}` in Cursor, `inputs` + `${input:id}` in VS Code,
`env_vars` / `env_http_headers` in Codex) and says so where a host documents
none.

### `verify --installed`

`verify --installed` checks what the local hosts launch instead of the DB;
`verify --config <path>…` checks exactly the named files. Unpinned launches,
servers not in the vault and remote endpoints are each reported as what they
are. Combine with `--offline` to use stored evidence only.

### `budget`

```bash
mcp-vault budget                        # what your configured servers cost
mcp-vault budget --budget 25            # exit 1 over 25% of the window
mcp-vault eval --installed --unsafe --results /tmp/eval.json && mcp-vault budget --results /tmp/eval.json
```

Every active server injects its tool list into the model's context on every
request. `budget` totals that per server and says where each number came from:
`measured` (a real `tools/list` payload, bytes ÷ 4), an estimate from a tool
count, or `unknown` (counted as unknown, never as zero). Where the DB knows how
to narrow a server (`toolsets`), it says so. A policy ceiling
(`maxContextTokens` / `maxContextPercent`) is also enforced by `install`
(`--allow-over-budget` to override).

### `doctor`

Node version, optional `gh` / Docker / `uvx`, and whether the project and
global Claude Code configs exist and parse. Never prints token values.

---

## Freezing what runs

### `lock`

```bash
mcp-vault lock               # write mcp.lock.json for this project's configured servers
mcp-vault lock --check       # resolve again and diff (exit 1 on drift)
mcp-vault lock --vendor      # npm ci the locked tree; nothing resolves at launch
```

`npx -y server@1.2.3` pins the root, not its tree: npm re-resolves the
dependencies at every start. The lockfile records npm's own lockfile per
server, the artifact identity and the tool-surface fingerprint. `--check`
separates ordinary dependency movement from what an upgrade does not explain:
the same version with different bytes, a tree that gained an install script, a
tool surface that changed while the artifact did not.

### `approve`

With `toolApproval: "require"` in the policy, a new or changed tool blocks
until `mcp-vault approve <server> [--tool X]` records it in `mcp.lock.json`.
The output shows which tools changed, in description or schema. `--dry-run`
shows what is pending.

### `sbom`

```bash
mcp-vault sbom --out sbom.json                    # the whole DB
mcp-vault sbom --installed --deps --out sbom.json # what this project runs, with transitive packages
```

CycloneDX 1.6. What CycloneDX has no field for is carried as `mcp-vault:`
properties: the tier, each evidence dimension with its date, which dimensions
have aged out, the behavioural status, the tool-surface hash, and for
transitive packages whether they run code at install time.

---

## Known servers

### `list` and `scan`

```bash
mcp-vault list --category database --tier Recommended
mcp-vault scan --cwd ./my-project              # detect the stack, suggest servers
mcp-vault scan --query kubernetes
```

`scan` reads `package.json`, `pyproject.toml`, `requirements.txt`, `go.mod`,
`Cargo.toml`, `docker-compose.yml` and `.env*` (key names only, never values),
and reports per entry three separate axes: **health** (is it maintained),
**trust** (what is established about the artifact) and **fit** (does it match
this project). Trust gates; health and fit rank — a blocking trust verdict is
never outweighed by the other two. Each stack signal carries its source and a
confidence (`detected` from a declared dependency, `inferred` from, say, an
`.env` key name).

### `explain <name>`

The evidence with dates, the policy in force, every rule with its outcome and
the rule that decided it. See [How it decides](HOW-IT-DECIDES.md#seeing-a-decision-explain).

### `install <name>`

```bash
mcp-vault install --list-hosts
mcp-vault install <name>                         # Claude Code, project (./.mcp.json)
mcp-vault install <name> --global                # Claude Code, user (~/.claude.json)
mcp-vault install <name> --host cursor           # ./.cursor/mcp.json
mcp-vault install <name> --host vscode           # ./.vscode/mcp.json (`servers` key)
mcp-vault install <name> --host claude-desktop --scope user
mcp-vault install <name> --host codex            # prints a TOML block to paste
```

Runs the integrity gate with `--fail-unverified`, then writes the version the
gate verified (`pkg@1.2.3`, `pkg==1.2.3`, `image@sha256:…`); an unpinned
command needs `--allow-unpinned`. A name that is not in the vault but looks like
an entry is refused (`--allow-lookalike <name>` if it is yours). An existing
config is backed up first, unrelated keys are left alone, and a config that
does not parse is never overwritten. Codex keeps TOML, which cannot be
rewritten safely without a TOML parser, so `install` prints the lines to paste.

### `upgrade`

```bash
mcp-vault upgrade --entry chrome-devtools-mcp
```

For a pin with advisories against it, computes the shortest version that
clears **all** of them (OSV's `fixed` versions), then checks that candidate too
— a recommendation onto a version with a different advisory would be worse
than none. An advisory with no published fix stays in the output. Asks OSV
live; there is no `--as-of`.

---

## The integrity gate: `verify`

```bash
mcp-vault verify --offline                 # stored pins and stored evidence, no network
mcp-vault verify                           # live registries + advisory feeds
mcp-vault verify --deep --deps             # hash the bytes, check the dependency tree
mcp-vault verify --entry playwright-mcp --json
```

| Ecosystem | Integrity | Source | Install hooks | Advisories |
|---|---|---|---|---|
| npm (`npx`) | sha512 SRI; registry signature on every run | `repository.url` | `pre/post/install`, `prepare` | npm bulk, OSV.dev, GHSA, Snyk† |
| PyPI (`uvx`) | sha256 of the sdist | `project_urls` | — | OSV.dev, GHSA, Snyk† |
| Docker | must be pinned by `@sha256:` | — | — | — |

† Snyk only with `SNYK_TOKEN`. GHSA uses `GITHUB_TOKEN` / `GH_TOKEN` when set
(60 → 5000 requests/hour). Advisories from all feeds are deduplicated by id.

| Flag | Effect |
|---|---|
| `--offline` | no network: stored pins and stored evidence (a recorded advisory or a yanked release fails) |
| `--no-audit` | skip the advisory feeds; still check live registry metadata |
| `--deep` | download each artifact and hash it locally instead of trusting the registry's own metadata; Docker digests are checked by hashing the manifest |
| `--deps` | resolve each npm tree (`npm install --package-lock-only --ignore-scripts`; nothing is installed or run) and check transitive install scripts and every package against OSV |
| `--fail-dep-advisories` | a high/critical advisory anywhere in the tree fails |
| `--require-signatures` / `--require-provenance` | an npm release without a registry signature / provenance attestation fails |
| `--fail-unverified` / `--strict` / `--fail-on` | thresholds ([how it decides](HOW-IT-DECIDES.md#thresholds---fail-on-and---strict)) |
| `--fail-families <a,b>` | only these rule families fail the run, e.g. `integrity,pin,oci,verify,policy` for "is the DB consistent" |
| `--entry <name>` | one DB entry |
| `--installed` / `--config <path>…` | what your hosts launch / exactly these files, instead of the DB |
| `--policy <path>` / `--no-policy` / `--show-policy` | which policy applies, or print it |
| `--update` | refresh `version` and `pkg_integrity` from the registries (maintainers) |
| `--record-evidence` | write what this run established into the DB, dated per dimension (maintainers) |
| `--sarif` | SARIF 2.1.0, each finding on its `tools_database.json` line |

Anything the gate could not compare reports `UNVERIFIED`, never `OK` — "the
feed was down" is not "the pin is good". Provenance is `bound` only when npm's
own registry key signed a statement whose subject digest is this artifact;
the Fulcio chain and Rekor inclusion are not validated, and the output says so
([SECURITY.md](../SECURITY.md#what-bound-means-for-provenance)).

---

## Evidence about servers

These commands produce the evidence the DB stores. Most need the network;
`--write` records the result in the DB (maintainers).

| Command | Question | Notes |
|---|---|---|
| `availability` | is the package still published, and still the same thing? | `gone`, `version-gone`, `yanked`, `deprecated`, `relocated`. An unpublished name is claimable by someone else. A feed that did not answer is never recorded. `--repos` also asks GitHub whether the repo moved |
| `identity` | who published it? | cross-checks the [official MCP registry](https://registry.modelcontextprotocol.io), whose namespaces are ownership-verified. Unlisted is not a finding |
| `posture` | how is the upstream repository run? | OpenSSF Scorecard via deps.dev, check by check, not the 0–10 average. Coverage is a few percent; the rest read "no report" |
| `capabilities` | what can the package do, and what did it gain since the last version? | reads the npm tarball in memory; every match has a file and line; absence is never recorded |
| `tool-scan [file]` | what do the tool descriptions tell the model? | rule table (`--rules`) over names, descriptions, parameter descriptions and enums: hidden Unicode (decoded), bidi/zero-width controls, ANSI escapes, "ignore previous instructions", `<IMPORTANT>`, credential and MCP-config paths, references to other tools, encoded blobs, catch-all parameters. Offline over a captured `tools/list`, or over the scans `eval` stored (rule, tool and location only — never the text) |
| `eval` | does it start? | handshake + `tools/list` + schema lint. Spawning is default-deny: `--sandbox` (jailed container, preferred) or `--unsafe` (on the host). `--no-spawn` re-lints stored results offline. `--installed` evaluates your own configured servers |
| `docker-drift` | did the upstream tag move to a new digest? | `--write` moves the pins for review as a diff; a routine rebuild and a registry hijack look the same from here |
| `license-drift` | did a dependency relicense (MIT → BSL / SSPL)? | `--strict` fails on an OSI → restrictive move |

Toxic flows (used by `check`, `status`, `audit`, `explain`): each configured
server — and each tool, where the eval stored its surface — is labelled
`untrusted_content`, `private_data`, `public_sink` or `destructive`, each label
with its evidence. A host session holding the first three (the [lethal
trifecta](https://invariantlabs.ai/blog/toxic-flow-analysis)), including one
server alone, is flagged, and so is untrusted content next to a destructive
tool; also two servers exposing the same tool name, and a description that
names another server's tool. A server with no DB entry and no stored surface is
`flows/no-data` — unknown, never clean.

Lookalike names (used by `check`, `audit`, `install`, `explain`): a name not in
the DB is compared with every entry's name, npm/PyPI package and image —
Damerau-Levenshtein with a length-dependent threshold, homoglyphs (Cyrillic,
`0/o`, `1/l`, `rn/m`), separators, PEP 503, dropped / added / misspelled /
foreign npm scopes, a swapped registry, and added affixes (`-mcp`, `-server`,
`-official`, `-js`). A publisher's own unscoped package is not a dropped-scope
copy (a short table, `PUBLISHER_UNSCOPED` in
[`lib/lookalike.cjs`](../mcp-ecosystem-intelligence/scripts/lib/lookalike.cjs),
says which ones are).

---

## Trust in the DB itself

### `signature`

Checks `tools_database.json` against its Ed25519 signature and the shipped
keyring, as every command does before reading the DB. Details:
[SECURITY.md](../SECURITY.md#signed-db).

### `audits`

```bash
mcp-vault audits add <entry> --criteria safe-to-run --who "Me <me@example.org>"
mcp-vault audits export --out audits.json   # signed with $MCP_VAULT_AUDIT_KEY
mcp-vault audits fetch                      # the only network step
mcp-vault audits check                      # offline, re-verifies the lock
```

Audits in the [cargo-vet](https://mozilla.github.io/cargo-vet/importing-audits.html)
model: who checked which package, version and integrity, against which
criterion. Imports are listed in `.mcp-vault.imports.json` with the source's
public key, fetched only on request, kept in `.mcp-vault.imports.lock.json`,
and not transitive. An imported audit shows in `explain`'s trace and never
changes `trust` or a decision.

---

## Publishing

| Command | What it writes |
|---|---|
| `badge <name>` | a README snippet for a "vetted by mcp-vault" badge and what it says today. The badge goes grey (`stale`) when the evidence it rests on ages out and red (`blocked`) when the entry's decision is deny |
| `site-registry` | `registry.html` / `registry.json`, every entry's badge and evidence page, and the sub-registry export, under `--out` (default `docs/site`) for `--base-url` |
| `export-registry` | the DB as a static [sub-registry](https://modelcontextprotocol.io/registry/registry-aggregators#acting-as-a-subregistry) of the official MCP Registry (read API v0.1, every endpoint also as a `.json` twin), with the vault's evidence and decision under `_meta["xyz.froggychips.mcp/vault"]`. A denied, Deprecated or unpinned entry is not exported. `--check` exits 1 if the tree on disk is stale |
| `registry-ingest` | `--fetch --out <file>` saves a snapshot of the official registry (the only networked step); `--snapshot <file>` then reports, offline, DB entries whose server or pinned version was deprecated or deleted upstream, and listed servers the DB lacks. It never edits the DB |

A static host cannot honour `search`, `cursor`, `limit` and friends: every
list request gets the whole list. The public site,
[mcp.froggychips.xyz](https://mcp.froggychips.xyz), is built in a separate
repository from the released npm package.

---

## Maintainer tools

| Command | Purpose |
|---|---|
| `discover` | harvest candidates from the official servers README, `gh search`, npm, PyPI, the official registry or a saved snapshot (`--source`); dedupe, score, and write an inbox (`--out`) a person cherry-picks from. Never edits the DB |
| `refresh` | refresh GitHub metrics (stars, last commit, open issues) and recompute `health_score`; a dry run unless `--write`. Versions and hashes are refreshed by `verify --update` |
| `health <stars> <days> <has_install> <issues> [license]` | the maintenance heuristic: popularity (capped), recency, a documented install command, issue noise, a non-OSI licence penalty. It names no tier |
| `wrap --name <n> --out <dir> [--tools-file f]` | generate a minimal MCP server that wraps a CLI or API, exposing only the tools you list — the fix for a vendor server with 50+ tools and no native filtering |

The bundled Claude Code skill (`mcp-ecosystem-intelligence/`, copy it into
`~/.claude/skills/`) drives the same scripts from a conversation; see its
[SKILL.md](../mcp-ecosystem-intelligence/SKILL.md).
