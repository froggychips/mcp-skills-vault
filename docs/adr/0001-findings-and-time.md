# ADR 0001 — One findings model, one place that decides, time as an input

Status: accepted · 2026-09-30 · supersedes nothing · affects every command that
prints a verdict

## Context

Nine feature PRs are open (#119 badges, #120 action, #121 signing/audits, #122
secrets, #123 flows/shadowing, #124 tool-scan, #125 lookalike, #126
sub-registry export, #127 org policy). Each one invented its own finding shape,
its own schema id (about fifteen new ones between them), its own SARIF, and its
own way into `status` / `audit` / `explain` / policy. #127 alone evaluates org
rules in `verify` *and* in `explain`, mapping `unknown` to a level differently
in each. `docs/COMPATIBILITY.md` freezes every schema id at 1.0, so whatever
ships first becomes permanent.

Separately, library code read the wall clock as a default argument
(`now = Date.now()`). Two tests went red a week after the evidence they read
did, with no commit behind the failure (#116), and no run could be replayed to
say what the gate would have answered on a given day.

## Decision

### 1. Determinism has a formula

    result = f(db, evidence, policy, asOf, rules_version)      (+ imported audits, #121)

Every input is named, and `asOf` is one of them. `rules_version` is the
package version (the rules are code). Two runs with equal inputs print equal
bytes; every `--json` document says which `asOf` it used.

### 2. Three layers

| Layer | What it is | Shape |
|---|---|---|
| **Observation** | a dated fact — today's evidence dimension | `id, subject, artifact_id, dimension, status, observed_at, confirmed_at, ttl_days, expires_at, source` |
| **Finding** | what a rule concludes from observations | `id, rule, subject, scope, severity, confidence, state, refs[], message` |
| **Decision** | policy × findings | `subject, effect, decided_by, as_of, fails, fail_on, unanswered, findings[], rules[]` |

- `rule` is `<family>/<rule>` (`advisories/known-vulnerability`,
  `secrets/aws-access-key`, `tool-scan/unicode-tags`).
- `subject` is typed, and its id is derived, never supplied:
  `artifact` → `entry@version+integrity` · `tool` → `server/tool` ·
  `host-config` → `path:line` · `setup` → `host` · `name` → `ecosystem:name`
  (the fifth is for #125: a name that is not an artifact yet).
- `severity` ∈ critical/high/medium/low/info; `confidence` ∈ high/medium/low
  (#122's format/heuristic, #123's high/low, #125's high/medium all map).
- **A Finding carries no policy effect.** The constructor rejects `effect`,
  `outcome`, `decision`, `level`.
- **"No data" is not "clean"**, formally: `state` ∈ `observed | not-run |
  no-data | stale`. Only `observed` is a statement about the subject; the rest
  are statements about us and decide to `unknown`, never `allow`.
- `expires_at` is the first instant an observation is stale — the same
  boundary `staleDimensions` draws (tested at the edges).

### 3. One place decides

- `decide(findings, policy, asOf, { subjects, facts, failOn })` in
  `lib/finding.cjs` is **the only function that computes an effect**
  (allow/warn/deny/unknown) and `decided_by`. Worst effect wins
  (deny > unknown > warn > allow); `decided_by` is the first rule in table
  order that produced it.
- The rules are rows of one table, `lib/policy_rules.cjs`, each with a stable
  id that is what `decided_by` says. The ids of the open PRs are reserved there
  now (`org/*`, `flows/*`, `shadowing/*`, `tool-scan/*`, `lookalike/*`,
  `secrets/*`) so each lands as a row, not as a branch in a command.
- **`--strict` and friends are parameters, not command logic.** Flags tighten
  the effective policy; the exit threshold `fail_on` (`deny` → `unknown` with
  `--fail-unverified` → `warn` with `--strict`) is part of it. A caller may
  narrow the question (`explain` asks `failOn: 'deny'`, as it always has).
- **Loading policy is one function**, `loadEffectivePolicy(startDir, { flags,
  noPolicy })`: the file(s), then flags, normalised and deep-frozen. `decide`
  refuses a policy that is not frozen.
- `facts` are what a rule may read that is not a finding (the entry's licence
  / health / trust, stored evidence, trust score, behaviour, budget, live gate
  status). A findings@1 document carries its `policy` and `facts`, so
  `decide(doc.findings, doc.policy, doc.as_of, …)` reproduces `doc.decisions`
  from the document alone — which is what the consistency test checks.

Commands render Decisions; they do not decide. In this PR `verify` (and so
`install`, which trusts verify's exit code) and `explain` do; the rest are
listed in `tests/decision_consistency.test.cjs` as legacy deciders with their
migration step, and a new command that is not classified fails that test.

### 4. Time

- The clock is read in one place, `lib/clock.cjs`. A CLI entry point reads it
  once (`asOfFromArgv`) or takes `--as-of YYYY-MM-DD | ISO-8601-with-zone`,
  and passes the instant down. Library functions that decide take it as a
  required argument and throw a pointed `TypeError` without it.
- **Decision time and observation time are different things.** `asOf` is
  replayable. When a check *looked* is not: observers (`availability`,
  `identity`, `eval`, `lock`, …) stamp with `readWallClock()`, and
  `--record-evidence` / `install` refuse `--as-of`, because a replayed instant
  must never date a real observation or approve a real install. Durations
  (`performance.now()`), cache TTLs, timeouts and backup filenames are
  measurements and stay on the clock, each allowlisted with its reason in
  `tests/no_wall_clock.test.cjs`, which fails on any new read.
- Default is the wall clock: `verify` answers about now, as before. Snapshot
  semantics are for tests, docs and reproduction.

## Migration

**Compatibility.** Every released schema keeps its bytes. `verify-report@1`,
its SARIF and text, `decision@1` (explain) and every other document are
unchanged except for additive fields: `as_of` everywhere a decision is made,
and `findings` (`mcp-vault/findings@1`) in `verify --json` and `explain --json`.
Checked on the shipped DB before/after at the same instant: explain for all 114
entries × 3 policies, verify offline × 4 flag sets × 3 policies — identical
apart from the additions. The legacy tags, SARIF rule ids and `failures`
counters stay until a major allows `@2`; `lib/legacy_tags.cjs` says what each
tag means as a finding.

**verify, step 2.** Processors still count `failures`; the exit code is the
decision's, compared with the counters, and a disagreement fails closed and is
printed. Next: processors emit typed findings only (`verify/check-failed`
split per check), counters and flag-dependent FAIL-vs-NOTE tags become a
rendering of the Decision, and the comparison goes. The first split is in:
the docker cross-check from #117 (install_cmd and pkg_integrity naming
different digests) is `integrity/docker-pin-mismatch`, observed and high, so
`finding/severity` refuses it in every mode, `--offline` included.

**The nine PRs** — one schema, `mcp-vault/findings@1`, instead of fifteen; the
new commands keep a thin schema of their own only for data that is not a
finding (a badge, a manifest):

| PR | Moves onto the model |
|---|---|
| #119 badges | badge state = a view of the entry's Decision + `observationState`; `finding-reports` → findings@1 |
| #120 action | `toSarif(findings)` (host-config subject = file + line) replaces `locate`; job summary renders Decisions |
| #121 signing/audits | audits → Observations (`source: audit:<key>`); signature check → findings `db/signature-*` on a file subject |
| #122 secrets | findings `secrets/<rule>`, host-config subject, `confidence` as is; its SARIF → `toSarif` |
| #123 flows/shadowing | findings `flows/*`, `shadowing/*` on `setup`/`tool`; `toxicFlows`/`toolShadowing` become rows |
| #124 tool-scan | findings `tool-scan/<rule>` on `tool` (location in the subject); scores' `-100` → a row |
| #125 lookalike | findings `lookalike/<technique>` on a `name` subject; the `LOOKALIKE` tag → legacy_tags |
| #126 export | `tier_holds_until` = min `expires_at`; `as_of` from `--as-of` via lib/clock |
| #127 org policy | see below |

## Policy migration (#127)

#127 is the PR that most needs this, and the one that most conflicts with it:
`evaluateOrg` returns `{rule, outcome}` and is called separately from `verify`
(unknown→warn) and from `explain` (unknown kept), its `RANK` duplicates the one
in `lib/policy_rules.cjs`, `evaluateOrg` reads `Date.now()`, `approve()`
defaults to `new Date()`, and its explain `decided_by` is an *object* where
this ADR makes it a rule id string.

**Merge this first, then rebase #127 onto it.** The reverse order would put
org rules into two commands as branches, which is exactly what is being
removed, and would freeze an object-shaped `decided_by`. #127 then needs to:

1. Implement each `org/*` row reserved in `lib/policy_rules.cjs` —
   `evaluate(ctx)` over `ctx.facts` (`subjectFacts` becomes a facts producer)
   — and delete `evaluateOrg`'s call sites in `verify` and `explain`.
2. Import `RANK` / `stricter` from `lib/policy_rules.cjs`; move `mergeStricter`
   and the org layering behind `loadEffectivePolicy` (it already goes through
   `loadPolicy`), so layers + flags are merged once and frozen.
3. Take `asOf` explicitly in `evaluateOrg`'s successors and in `approve()`
   (`approved_at` is an observation → `readWallClock()`).
4. Keep `decided_by` a string; `source`/`index` go into the rule outcome's
   `detail`/trace.
5. `approve` and `lock --check` emit findings (`org/tool-approval` on the
   server) and exit via `decide()`.

The remaining legacy deciders (`status`, `audit`, `lock --check`, `budget`,
`doctor` and the drift checks) move the same way, one PR each, by removing
their entry from the legacy list in the consistency test.
