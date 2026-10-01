# How mcp-vault decides

Every command that gives a verdict — `check`, `verify`, `status`, `audit`,
`explain`, `secrets`, `tool-scan`, `lock --check`, `approve`, and the
maintenance commands — reaches it the same way:

```
observations ─► findings ─► decide(findings, policy, asOf) ─► decisions ─► exit code
```

The design record is [ADR 0001](adr/0001-findings-and-time.md); this page is
the short version.

## Findings

A **finding** is what one rule concluded about one subject. It has a rule id
(`<family>/<rule>`, for example `config/unpinned-launch`,
`secrets/connection-string`, `lookalike/doubled-letter`, `flows/lethal-trifecta`),
a typed subject (an artifact, a tool, a config line `path:line`, a host
session, a name), a severity, a confidence, and a **state**:

| State | Meaning |
|---|---|
| `observed` | the check ran and saw this — the only state that is a statement about the subject |
| `not-run` | the check did not run |
| `no-data` | the check ran and had nothing to look at |
| `stale` | what it looked at has aged past its shelf life |

The last three are statements about the tool, not about your config, and none
of them is "clean". **No data is not a pass.**

A finding carries no effect. Whether it blocks is not its call.

## decide()

`decide()` in [`lib/finding.cjs`](../mcp-ecosystem-intelligence/scripts/lib/finding.cjs)
is the only function in the project that computes an effect. It runs the rows
of one rule table,
[`lib/policy_rules.cjs`](../mcp-ecosystem-intelligence/scripts/lib/policy_rules.cjs),
over the findings of each subject and the effective policy, and returns one
**decision** per subject:

- `effect` — `allow`, `warn`, `deny` or `unknown`. The worst one wins, in the
  order `deny` > `unknown` > `warn` > `allow`: "nobody looked" is not a
  softer answer than "somebody looked and did not like it".
- `decided_by` — the rule that produced that effect.
- `fails` — whether it fails the run at the threshold in force (`fail_on`).

Because there is one table and one function, two commands looking at the same
subject cannot disagree: `explain <name>` exits as `verify --entry <name>`
does on the same DB, policy, flags and `--as-of`, and the Action's job summary
and SARIF only render decisions they did not make.

## Thresholds: `--fail-on` and `--strict`

`fail_on` says which effects fail the run:

| `--fail-on` | Fails on | Same as |
|---|---|---|
| `deny` (default for `check`) | a deny: plain-text secret, hash mismatch, recorded advisory, yanked release, policy violation | |
| `unknown` | also anything that could not be checked: not in the vault, a version the vault never verified, a remote server, an overridden package source; in the DB mode, aged-out evidence | `--fail-unverified` |
| `warn` | also warnings: unpinned launch, lookalike name, a risky combination of servers | `--strict` |

The GitHub Action and the pre-commit hook default to `unknown`. A policy file
can raise the threshold; a flag can raise it further; nothing lowers it.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | answered, nothing fails at the threshold |
| `1` | answered, and something fails |
| `2` | not answered: unreadable config or policy, bad arguments, nothing could be attempted |

`2` never means clean. A real finding outranks an unreadable input: if one
config is broken and another has a plain-text secret, the exit is `1`, and
both are reported. Details per command: [COMPATIBILITY.md](COMPATIBILITY.md#2-exit-codes).

## Time is an input: `--as-of`

Evidence has a shelf life — a hash match holds for 90 days, "no advisories"
and "still published" for 7 — so the same DB gives a different answer on a
later day. Rather than read the clock somewhere deep inside, the instant is an
argument:

```
result = f(db, evidence, policy, asOf, rules_version)
```

The clock is read once, at the command's entry point, or given with `--as-of
2026-10-01` / `--as-of 2026-10-01T12:00:00Z`. Every `--json` document records
the `as_of` and `rules_version` it was produced with, plus the policy and
facts it was decided on, so the decisions can be recomputed from the document
alone. The same inputs at the same `--as-of` print the same bytes; that is
what makes the examples in this documentation reproducible.

`--as-of` replays stored evidence only. Commands that look at the network
(`verify` without `--offline`, `check --online`) or write something
(`--record-evidence`, `install`) refuse it: a replayed date may judge old
evidence, never date a new observation or approve an install.

## Two modes: a config line, and the DB

The same rules run over two kinds of subject, and they differ in one place:
what an **aged-out claim of absence** means.

| | DB mode | Config mode |
|---|---|---|
| Commands | `verify` over the DB, `explain` | `check`, `verify --config`, the Action, the pre-commit hook |
| Subject | a vault entry | a config line that launches something |
| Matching | — | by **what it launches** (package identity; the version compared separately). The config key is a label; only the lookalike check reads it, as a claim |
| A recorded problem (yanked, advisory, hash mismatch) | deny, at any age | deny, at any age — for the exact release the vault recorded it against |
| "Nothing found" past its shelf life (advisories, availability) | `unknown` — fails at `--fail-on unknown` | **context**: an `i vault evidence … is N days old` line (`evidence/vault-age`); it never sets the effect or the exit code |
| A clean known server | `trust/ok` | `trust/ok` |

`status` sits between the two: it matches what your hosts launch the way config
mode does, and reports aged-out evidence as a warning that fails under
`--strict`, because its question is "what on this machine needs attention".

Why the difference. A found problem does not age out: a release that was
yanked stays yanked. But "no advisories as of the day the DB was built" is a
statement about the vault release the Action or hook is pinned to, not about
your config. Held to `--fail-on unknown` (the Action's default), it would fail
every repository using known servers a week after each vault release, for
nothing anyone in that repository changed. So in config mode the age is said —
no data is not clean — but not decided on; `check --online` re-observes it
live. In DB mode the question *is* "how current is this vault's record", so the
age decides.

Measured on the same DB at `--as-of 2026-10-20`, 19 days after the evidence:
`verify --offline --fail-unverified` exits `1` (108 entries unverified), while
`check --fail-on unknown` on a config launching `@playwright/mcp@0.0.75`
exits `0` and prints `i vault evidence for @playwright/mcp@0.0.75 is 19 days
old (advisories, availability) — the result above uses what was last seen`.

## Seeing a decision: `explain`

```text
$ mcp-vault explain mcp-server-aws --as-of 2026-10-01T12:00:00Z
DENIED  mcp-server-aws  pypi:awslabs.core-mcp-server@1.0.27
policy: none found — defaults in force · as of 2026-10-01T12:00:00.000Z

  ? availability    yanked (2026-10-01)
  ✓ artifact        verified (2026-10-01)
  ✓ source_binding  verified (2026-10-01)
  ? registry        unlisted (2026-10-01)
  ✓ repository_posture clean (2026-10-01)
  ✓ advisories      clean (2026-10-01)
  · signature       never checked
  …

  trust 70/100 (block)   health 75   behaviour never-started
  did not complete a handshake in a clean sandbox (CRASH, exit 1)

Rules:
  ✗ trust/availability             availability is yanked (as of 2026-10-01)
  ✓ policy/unverified              artifact: verified (as of 2026-10-01) (context)
  ! behaviour/never-started        did not complete a handshake in a clean sandbox (CRASH, exit 1) (context)

Blocking: trust/availability
Decided by trust/availability
…
```

<sub>Exit `1`. Lines about the configured set on the machine that ran it, and
the full trace, are cut. Rules marked `(context)` are shown and decide nothing:
the exit code is the gate's.</sub>

Replayed at `--as-of 2026-10-20T12:00:00Z`, the same entry is still denied by
`trust/availability` (`yanked (19d old, shelf life 7d)`): a found problem does
not age out. `advisories clean` has aged out by then and adds
`finding/incomplete` — `unknown`, which in this (DB) mode fails at
`--fail-on unknown`.

`--json` prints the decision record (`mcp-vault/decision@1`); `--record
<file>` appends it as one JSON line — "allowed on this date, under this policy,
on this evidence" is what gets asked six months later.

## Policy

`.mcp-vault.policy.json` (nearest file at or above the working directory, or
`--policy <file>`) sets the bar once for CI and for everyone's shell. Every
key is optional; an unknown key is an error, because a policy with a typo that
silently enforces nothing reads as a bar being enforced. Example:
[`.mcp-vault.policy.example.json`](../.mcp-vault.policy.example.json).

```json
{
  "unverified": "fail",
  "unpinnedLaunch": "fail",
  "toxicFlows": "warn",
  "toolShadowing": "warn",
  "signatures": "require",
  "licenses": { "deny": ["BUSL-1.1", "SSPL-1.0"] }
}
```

`unpinnedLaunch`, `toxicFlows` and `toolShadowing` take `fail` | `warn` |
`allow` (default `warn`, which fails only under `--strict`).

### Organisation policy

An organisation keeps one policy with an allowlist, and projects inherit it
with `"extends": "<path>"` (or `MCP_VAULT_ORG_POLICY` on managed machines).
Example: [`.mcp-vault.org-policy.example.json`](../.mcp-vault.org-policy.example.json).

```json
{
  "default": "deny",
  "allow": [{ "npmScope": "@modelcontextprotocol" }, { "githubOwner": "microsoft" },
            { "artifact": "npm:@acme/mcp@2.3.1", "integrity": "sha512-…" }],
  "deny": [{ "entry": "mcp-server-everything" }],
  "minTier": "Recommended",
  "requireEvidence": { "signature": 90, "advisories": 7 },
  "denyCapabilities": ["shell"],
  "toolApproval": "require"
}
```

- An allow list means default deny, including for servers the vault DB does
  not know; a deny rule outranks every allow.
- A project file can only tighten the organisation's; a looser value is a
  policy error (exit `2`).
- With `toolApproval: "require"`, a new or changed tool blocks until
  `mcp-vault approve <server> [--tool X]` records it in `mcp.lock.json`. An
  approval is for the artifact it was made on.
- The rules are the `org/*` rows of the same table, so `check`, `verify`,
  `install`, `explain`, `lock --check` and `approve` answer alike; the
  decision's detail names the file and the list position that matched.

`mcp-vault verify --show-policy` prints the policy in force and where it came
from.
