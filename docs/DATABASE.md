# The vault DB

`mcp-ecosystem-intelligence/assets/tools_database.json` is a curated list of
known MCP servers with pinned versions, hashes and dated evidence. It is an
**extra signal** for `mcp-vault check`, not the core of it: a launch of a
server the DB knows is compared with the version the vault verified (and,
with `--online`, with the registry's hash and the advisory feeds), and
`status` / `explain` apply the stored evidence below; a server the DB does not know still gets
every other check (unpinned launch, overridden source, plain-text secrets,
lookalike names, toxic flows), and is reported as *not in the vault* —
`unknown`, never clean.

This page describes the data. The numbers in it are checked against the DB by
[`tests/docs_numbers.test.cjs`](../tests/docs_numbers.test.cjs), against a dated
snapshot: the date is the newest `checked_at` in the DB, so a refresh of the
evidence without a refresh of this page fails the test.

## What is in it

**112 entries** across ~26 categories, all with a pinned version, an integrity
hash (npm sha512 / PyPI sha256 / Docker `@sha256`), an SPDX licence and a
derived `trust` value.

```
ai        browser   ci-cd      cms       communication   crm
database  demo      docs       filesystem http            infra
maps      memory    meta       mobile     observability   payments
pm        reasoning search     streaming  testing         utility
vcs       web-scraping
```

`mcp-vault list` shows them (`--category`, `--tier`, `--trust`, `--query`,
`--json`).

## Tiers

The tier is derived from evidence when anything reads the DB
([`lib/tiers.cjs`](../mcp-ecosystem-intelligence/scripts/lib/tiers.cjs)); it is
not stored and not a threshold on `health_score`.

| Tier | What was established |
|---|---|
| Core | the artifact is verified, the evidence is about this artifact, and a run of **that pinned reference** started and listed tools |
| Recommended | the artifact is verified and current; either nothing watched it run, or what watched it cannot be tied to this artifact |
| Experimental | too little is known — a required check never happened, a claim aged out, or the stored evidence is about a different artifact than this entry now installs |
| Deprecated | do not install — nothing to install, bytes that are not the bytes we verified, or an advisory against this version |

Distribution as of 2026-10-01 (the date of the newest evidence in the DB): **0 Core / 110 Recommended / 1 Experimental / 1 Deprecated**.
All evidence was refreshed that day. The Deprecated entry is `mcp-server-aws`
(its pinned release is yanked); the Experimental one is `linear-mcp-server`
(its repository disagrees with the one npm declares). That is a snapshot, not
today's split: `availability` and `advisories` have a seven-day shelf life, so
a week later most entries read Experimental until the next refresh even though
no commit touched them. `mcp-vault list` and `mcp-vault status` classify
against now, or against `--as-of`.

**Core is empty, and that is the tier working.** No row in the eval snapshot
yet records *which artifact it launched*, and a pass for `x@1` is not a
statement about `x@2`. The eval now pins before launching and records the
artifact id; an entry it cannot pin records none. Core is also deliberately
narrower than "we know these bytes ran": the eval launches `pkg@1.2.3` and does
not re-hash what the registry handed it, so Core says the reference was
pinned, verified, and seen to run.

Behaviour promotes but never demotes. The sandbox runs with an empty
environment, so servers that need an API key exit 1; recording that as a fact
about the server would read a check that did not happen as a check that
failed.

## Trust as dated evidence

`trust` is computed, not typed. `verify --record-evidence` writes each
dimension with the date it was established:

```json
"trust_evidence": {
  "artifact_id": "npm:@mapbox/mcp-server@0.11.0",
  "dimensions": {
    "artifact":       { "status": "verified", "checked_at": "2026-10-01", "method": "deep-hash" },
    "signature":      { "status": "verified", "checked_at": "2026-10-01", "keyid": "SHA256:…" },
    "source_binding": { "status": "verified", "checked_at": "2026-10-01" }
  }
}
```

Evidence is keyed to the artifact id including the version, so it is dropped
rather than inherited when the version moves. A run records only what it
examined: a `--no-audit` run writes nothing about advisories rather than
writing "clean". Each dimension has its own shelf life (advisories and
availability 7 days, a hash 90), overridable with `maxEvidenceAgeDays`;
evidence past it is `unknown`, never "still verified".

Derived trust: **110 verified / 0 candidate / 2 unverified** as of 2026-10-01.
The two unverified are the yanked release (`mcp-server-aws`) and the
repository mismatch (`linear-mcp-server`).

What the stored evidence says, per dimension (2026-10-01):

```
availability   present 104, deprecated 4, yanked 1
artifact       verified 112
signature      verified 99, absent 1
provenance     bound 46, absent 54
source_binding verified 99, unverified 9, mismatch 1
registry       listed 11, unlisted 101
advisories     clean 108, advisories-present 1
dependencies   advisories-present 1
posture        clean 1, weak 3        (Scorecard covers 4 of 112 repositories)
```

`advisories-present` is an advisory below the failing severity
(`chrome-devtools-mcp`, two MODERATE ones; `mcp-vault upgrade` gives the
version that clears them) and, in the dependency tree, `@mondaydotcomorg/monday-api-mcp`.
Every entry's `install_cmd` is pinned to an exact version or digest; a test
asserts it.

The npm registry signature is checked for each of the DB's 100 npm entries on
every live run; provenance is `bound` only when npm's own key signed a
statement whose subject digest is this artifact (see
[SECURITY.md](../SECURITY.md#what-bound-means-for-provenance)).

The offline gate over the whole DB, replayed at that date:

```text
$ mcp-vault verify --offline --as-of 2026-10-01T12:00:00Z
…
FAIL  mcp-server-aws@1.0.27 (PyPI offline pin present for awslabs.core-mcp-server)
        [FAIL] stored evidence: availability: yanked (observed 2026-10-01)
…
112 entries checked — 1 failure(s)
```

## Who published it (official registry)

The [official MCP registry](https://registry.modelcontextprotocol.io) verifies
namespace ownership at publish (`io.github.<owner>/…` requires authenticating
as that account). `mcp-vault identity` cross-checks the DB against it.
11 entries are listed as of 2026-10-01 and all of them agree; a verified namespace under a
different owner would be the finding. Being unlisted is not a finding — listing
is opt-in.

## Does it run (behavioural eval)

`mcp-vault eval --sandbox` spawns each entry in a jailed container
(`--cap-drop ALL`, read-only rootfs, non-root, memory/pid caps, install hooks
off) and runs `initialize` → `tools/list`. A `docker run` entry is rebuilt
from its pinned digest under the jail's own flags; the entry's flags are
discarded.

40 of the 111 entries with a runnable launch command complete a handshake in a clean container; 39 of them list at least one tool, listing 1,021 tools between them, ≈294k tokens of `tools/list` payload if every one were enabled at once. The rest fail for their own reasons — 60 crash, 7 time out, 2 want network access, 1 wants credentials, 1 needs an argument. 7 entries report a tool count that differs from the DB's (`tool_count_drift`), which is a reviewer's decision, not an automatic correction.

Each passing run records a tool-surface fingerprint (each tool's description
and input schema hashed separately — hashes only) and the identity of what ran,
so a later run can say whether a changed surface came with a new artifact or
without one (*unexplained*).

## What the packages can do (capabilities)

`mcp-vault capabilities` reads each npm tarball in memory and records, with a
file and line, what the package is able to do. Across the scanned package
versions:

```
env_access  91    shell           38    dynamic_code      16
network     79    install_script  33    dynamic_require    8
fs_read     63    fs_write        42    credential_paths   5
```

31 of those packages can both run other programs and reach the network. 20 of
106 ship at least one minified file, where a pattern scan can show presence
and nothing else. `found` is a fact; absence is never recorded. A capability
that appears in a new version is a finding; one that disappears is not an
improvement. PyPI and Docker entries report `unsupported`.

## Context cost

Every active server injects its tool list into the model's context. With 112 servers in the DB the spread is wide: `mcp-server-fetch` = 1 tool vs. `gitlab-mcp` = 153 tools. `mcp-vault budget` totals what your configured
servers cost, saying for each number whether it was measured or estimated; the
`toolsets` field says how to narrow a server where it supports that.

## Entry schema

```jsonc
{
  "name": "pkg-name",
  "category": "database",
  "install_cmd": "npx -y pkg@1.2.3",     // pinned
  "source_url": "https://github.com/owner/repo",
  "version": "1.2.3",
  "pkg_integrity": "sha512-…",           // npm sha512 / PyPI sha256; Docker pins by digest
  "trust": "verified",                   // derived from trust_evidence
  "license": "MIT",                      // SPDX
  "health_score": 75,                    // maintenance heuristic, not a tier
  "est_tools_count": 10,
  "toolsets": "--toolsets repos,issues", // how to reduce the tool count; null = none
  "trust_evidence": { "artifact_id": "npm:pkg@1.2.3", "dimensions": { } }
}
```

`health_score` answers one question — is this project maintained — from
stars, recency, a documented install command, open issues and a licence
penalty (`mcp-vault health`). It names no tier.

## How it is kept current

A weekly job refreshes versions and hashes from the registries, re-verifies
with `--deep --record-evidence`, runs `availability`, `identity`, `posture` and
`capabilities`, and opens **one human-reviewed PR**. Nothing is auto-merged:
that PR is the only gate between a registry publishing something and this DB
accepting it. Discovery (`mcp-vault discover`) writes an inbox of candidates
that a person cherry-picks. How to add or promote an entry:
[CONTRIBUTING.md](../CONTRIBUTING.md).
