# Compatibility promise

This document says what will not change without a major version bump, and —
just as importantly — what will. It takes effect at **1.0.0**. Until then the
rules below are what we already try to follow, but a pre-1.0 minor release may
break any of them if it has to; the changelog will say so.

The short version: **the machine-readable surface is the contract. Everything
a human reads is not.**

---

## What is covered

### 1. Command names and their meaning

Every command listed in `mcp-vault --help` keeps its name and keeps answering
the same question. Adding a command is a minor release. Renaming or removing
one is major; an alias for the old name stays for one full major cycle.

### 2. Exit codes

Every command uses the same three:

| Code | Meaning |
|---|---|
| `0` | the question was answered and the answer is "no finding" |
| `1` | the question was answered and there is a finding — a failing gate, a denied decision, a difference from the lockfile, an exceeded budget |
| `2` | the question was not answered: bad arguments, missing entry, unreadable input |

The distinction between `1` and `2` is the part that matters in CI, and it is
the one this project cares most about getting right: **`2` never means "clean"**.
A check that could not run must not exit `0`, and a check that ran and found
nothing must not exit `2`.

Which *conditions* produce a `1` can become stricter only behind a flag
(`--strict`, `--fail-*`). Making a default stricter — something that exited `0`
yesterday exiting `1` today with the same arguments — is a major release.

### 3. `--json` payloads

Every JSON document this tool writes carries a schema identifier of the form
`mcp-vault/<name>@<major>`:

| Identifier | Written by |
|---|---|
| `mcp-vault/audit@1` | `mcp-vault audit --json` |
| `mcp-vault/availability@1` | `mcp-vault availability --json` |
| `mcp-vault/capabilities@1` | `assets/capabilities.json` (the stored scan) |
| `mcp-vault/capability-scan@1` | `mcp-vault capabilities --json` |
| `mcp-vault/decision@1` | `mcp-vault explain --json` |
| `mcp-vault/doctor@1` | `mcp-vault doctor --json` |
| `mcp-vault/entries@1` | `mcp-vault list --json` |
| `mcp-vault/identity@1` | `mcp-vault identity --json` |
| `mcp-vault/lock@1` | `mcp.lock.json` |
| `mcp-vault/lock-check@1` | `mcp-vault lock --check --json` |
| `mcp-vault/lock-vendor@1` | `mcp-vault lock --vendor --json` |
| `mcp-vault/lock-write@1` | `mcp-vault lock --json` |
| `mcp-vault/policy@1` | `.mcp-vault.policy.json` (read, not written) |
| `mcp-vault/posture@1` | `mcp-vault posture --json` |
| `mcp-vault/status@1` | `mcp-vault status --json` |
| `mcp-vault/token-budget@1` | `mcp-vault budget --json` |
| `mcp-vault/upgrade-plan@1` | `mcp-vault upgrade --json` |
| `mcp-vault/verify-report@1` | `mcp-vault verify --json` |

Within one schema major:

- **fields are added, never removed or retyped.** A consumer reading `.state`
  today reads the same `.state`, of the same type, after any 1.x release.
- **a field's set of values may grow.** New states appear — that is how a
  measurement gets more precise. Parse defensively: an unrecognised state is
  not an error, and is certainly not a pass.
- **`null` keeps meaning "not established".** It is never swapped for a
  default, a `false`, or an empty string. This is the single rule the whole
  project is built on and it will not be traded for a tidier schema.

Removing a field, changing its type, or changing what an existing value means
bumps the schema to `@2`. When that happens, `@1` keeps being written for at
least one full minor release alongside `@2`, selected by a flag, and the
changelog names the migration.

### 4. The shipped data files

`tools_database.json`, `eval_results.json` and `capabilities.json` ship inside
the npm package, and their *shape* is covered by the same additive rule.

Their *contents* are not. Entries are added and removed, versions move, scores
change, and an entry that verified last week can be `Deprecated` today. That is
the point of the thing. Do not pin behaviour to a particular entry being
present, to its tier, or to the size of the DB.

### 5. The policy file

`.mcp-vault.policy.json` keeps working. Rules are added over time; an existing
rule keeps its name and its meaning, and a policy file written against 1.0.0
will still be understood by every 1.x. A rule whose inputs are missing
evaluates to `unknown`, never to `allow` and never to `deny` — same rule as
`null` above.

---

## What is *not* covered

- **Human-readable output.** Tables, colours, wording, column order, ordering
  of rows, the summary lines at the end. If you are parsing stdout, use
  `--json`; it exists so that this text can stay free to improve.
- **The JavaScript modules.** `package.json` declares no `main` and no
  `exports`: `scripts/` and `scripts/lib/` are implementation, not an API.
  They are shipped so the CLI runs and so the code can be read, not to be
  `require`d. They change without notice.
- **The numbers.** `health_score` is a heuristic and its formula will keep
  moving. The tier (`Core` / `Recommended` / `Experimental` / `Deprecated`) is
  derived from evidence at read time and will change as evidence does — that
  is the feature. Neither is a stable identifier for anything.
- **Network behaviour.** Which registries are queried, in what order, with what
  concurrency and timeouts. A registry that changes its API is not a breaking
  change in this tool.
- **Evidence values over time.** `verify` exiting `1` tomorrow on an entry that
  passed today is the tool working. Only the *format* of that answer is
  promised, never the answer.
- **Anything under `docs/site/`.** It is generated.

---

## Version rules

| Change | Release |
|---|---|
| new command, new flag, new field in a JSON payload, new state in an existing field | minor |
| new entries in the DB, refreshed evidence, new advisories, tier movement | patch |
| bug fix that makes an answer *more* honest — a check that wrongly passed now fails | patch, and the changelog says so loudly |
| a default becoming stricter, so the same invocation now exits `1` | major |
| removing or renaming a command or a flag | major |
| removing or retyping a field, or changing what an existing value means | major, and the schema id bumps |
| dropping a Node version that upstream still supports | major |
| dropping a Node version upstream has already end-of-lifed | minor, announced one minor in advance |

A fix that makes the tool refuse something it used to allow is a patch when the
old behaviour was a bug — this project would rather break a pipeline than keep
telling it that an unverified artifact is fine. Those releases are marked
`SECURITY` in the changelog and say exactly which check changed.

---

## What 1.0.0 does not mean

It does not mean the evidence is complete. Coverage is partial and stated
per-dimension, per-entry, with dates; `unknown` appears throughout and is
supposed to.

It does not mean anything here has been audited, that a `Core` entry is safe to
run, or that a verified artifact is trustworthy code. This tool establishes
*which bytes* you are about to run and *what has been checked about them*. What
those bytes do when they run is a different question, and only the behavioural
eval touches it — in a sandbox, briefly, once a week.

It means the interface is stable enough to build on, and that we will tell you
before it moves.
