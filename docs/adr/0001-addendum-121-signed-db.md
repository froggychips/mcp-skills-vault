# ADR 0001, addendum for #121 — the signed DB and audits on the findings model

Status: accepted · 2026-09-30 · extends [ADR 0001](0001-findings-and-time.md)

## Signature check

`lib/db_signature.cjs` turns one check of a DB file into findings on a
`host-config` subject (a file, no line; path relative to the package root):

| Finding | State · severity | When |
|---|---|---|
| `db/signature-verified` | observed · info | canonical bytes match the `.sig`, key in the keyring and inside its window |
| `db/signature-absent` | observed · medium | no `.sig` next to the DB |
| `db/signature-invalid` | observed · high | malformed, unknown/revoked key, key out of window, tampered bytes, unreadable DB |
| `db/signature-not-configured` | not-run · info | the keyring is empty |
| `db/signature-keyring-invalid` | observed · critical | the keyring cannot be read |

The row `db/signature` (lib/policy_rules.cjs) decides them. It *claims* the
`db/signature-` family: `finding/severity` and `finding/incomplete` skip a
claimed finding, so the development override can turn a refusal into a
warning without the generic severity row turning it back. It reads three
facts: `required`, `context`, `allow_unsigned`.

| Finding | required (package) | not required (git checkout) | + `--allow-unsigned-db` |
|---|---|---|---|
| verified | allow | allow | allow |
| absent | **deny** | allow | warn |
| invalid | deny | deny | warn |
| not-configured | unknown | unknown | unknown |
| keyring-invalid | deny | deny | deny |

The wrapper (`bin/mcp-vault.cjs`) and `mcp-vault signature` both call
`decide()` and render the Decision; `signature --json` is the findings@1
document. `--strict` / `--fail-unverified` tighten `fail_on` as everywhere
(so `signature --strict` fails on anything but verified). The check does not
depend on the instant — key windows are compared with the signed date — so
the wrapper passes `readWallClock()` only to date the document.

## Where a signature is required (owner decision)

Mandatory **only for the installed npm package**, not for a git checkout
(development, CI, every PR that touches the DB): signing happens at release,
so a checkout never has a `.sig`, and refusing there broke every CLI step run
from one.

The signal is a `.git` entry — directory, or the file a worktree has — **at
the package root itself** (`signatureContext`). Chosen over a release marker
file because:

- npm never packs `.git` (npm-packlist ignores it unconditionally, whatever
  `files` or `.npmignore` say), so no tarball, `npm install` or `npx` can carry
  or produce it. A marker, by contrast, is a file that `--ignore-scripts`, a
  hand-made `npm pack` or a forgotten step can leave out — and a missing marker
  would have to mean "not required", i.e. fail open.
- It is checked at the package root, never by walking up, so a package
  installed under a project that has its own `.git` is still a package.
- The default is the strict answer. Only a positive development signal relaxes
  it; a copy, a source zip or an image built without `.git` requires the
  signature.
- Creating `.git` inside an installed package takes write access to the code
  that performs the check: not a weaker boundary than the code itself.

Only a *missing* signature depends on the context. A present `.sig` must
verify everywhere, and an unreadable keyring refuses everywhere.
`MCP_VAULT_REQUIRE_SIGNED_DB=1` makes a checkout behave like a package; it can
only tighten. `release.yml` packs the tarball, unpacks it where there is no
`.git`, and runs `mcp-vault signature --strict` from there before
`npm publish`.

## Audits

An audit (local, or imported and verified against the key in the config) is
an **Observation** on the entry's artifact subject — `dimension`
`audit/<source>/<who>`, `status` the accepted criteria, `observed_at` the
audit date, `source` `audit:local` or `audit:<key id>` — and an
`audits/recorded` finding (observed, info) that refers to it, so `explain`'s
trace shows rule → finding → dated observation. The `audits/recorded` row only
ever says `allow`: worst effect wins, so an audit can be seen in every
decision and lifts none. It never enters `trust_evidence.dimensions`, so
`deriveTrust` / `trustScore` cannot see it.

The import check (`audits fetch`, `audits check`) is findings per configured
source (`name` subject `audit-source:<name>`): `audits/import-verified`,
`audits/import-unverified`, `audits/import-not-fetched` (not-run), decided by
the `audits/import` row (claims `audits/import-`; anything but verified
refuses, as `check` always did). Their `--json` is findings@1.

## Schema ids

Removed (they duplicated findings@1; 1.0 is not out): `mcp-vault/signature-check@1`,
`mcp-vault/audit-imports@1`. Kept, because they are data rather than findings:
`audit-add@1`, `audit-export@1` (the signed bundle), `audit-list@1`,
`audits@1` and `imports-lock@1` (files), `keygen@1`, `sign@1`.
