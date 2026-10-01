# Security Policy

## Reporting a vulnerability

Please report privately — do **not** open a public GitHub issue for security
matters.

- **Telegram:** [@froggychips](https://t.me/froggychips)
- **Email:** big@froggychips.xyz

Include reproduction steps, what you expected and what happened, and the
version or commit SHA you tested. A bypass of a check — something that should
fail and passes — is treated as the most serious class of bug here.

## Supported versions

| Version | Supported |
|---|---|
| latest 0.16.x on npm, and `master` | yes |
| anything older | no — upgrade |

Before 1.0 there are no backports. The vault DB that ships with a version is
signed and fixed; newer data comes with a newer release.

## Signed DB

`tools_database.json` decides what `install` writes and what `check` compares
a launch against, so the CLI checks an Ed25519 signature over it before any
command reads it (`bin/mcp-vault.cjs` → `lib/db_signature.cjs`), offline, with
Node's own `crypto`.

- **What is signed:** the DB's canonical JSON (sorted keys, no whitespace,
  UTF-8 — `lib/signing.cjs`), so line endings or re-indentation neither break a
  signature nor hide a change. `tools_database.json.sig` carries the key id,
  the algorithm, the sha256 of the canonical bytes and the signing date, all
  inside the signed message. It is made at release and is not in git.
- **Who may sign:** the keys in
  [`assets/trusted_keys.json`](mcp-ecosystem-intelligence/assets/trusted_keys.json),
  shipped in the package. Today that is one release key, **`92cf62804f86a312`**,
  valid from 2026-09-30. Rotation: add the new key with `valid_from`, give the
  old one `valid_until`; `revoked: true` verifies nothing whatever date is
  claimed.
- **Where it is required:**

  | How you run it | DB check |
  |---|---|
  | the npm package (`npx`, `npm i -g`, the Action with `version:`) | **strict**: a missing, malformed, unknown-key, revoked or out-of-window signature, or changed content → the command does not run |
  | a git checkout (development, CI of this repo) | a missing `.sig` is allowed; one that is present must verify. `MCP_VAULT_REQUIRE_SIGNED_DB=1` makes a checkout strict |
  | the GitHub Action in its default mode (its own checkout) | GitHub unpacks `uses:` without `.git` and without the release `.sig`, so the action allows a missing signature for that step only. The DB is the bytes of the commit `uses:` names, exactly as the code that checks it is: **the SHA pin is the integrity**. Pin `uses:` to a full SHA; the action warns otherwise |

  The signal for "checkout" is a `.git` entry **at the package root itself**:
  npm never packs `.git`, so no tarball can produce it, and creating it inside
  an installed package takes write access to the code that runs the check.
- **Forks and copies without `.git`:** `--allow-unsigned-db` or
  `MCP_VAULT_ALLOW_UNSIGNED_DB=1` turn the refusal into a warning printed on
  every run.
- **One place decides:** the check is findings (`db/signature-verified`,
  `-absent`, `-invalid`, `-not-configured`, `-keyring-invalid`) decided by the
  `db/signature` row of the rule table
  ([ADR 0001](docs/adr/0001-findings-and-time.md),
  [addendum](docs/adr/0001-addendum-121-signed-db.md)).
  `mcp-vault signature --json` prints that document.

What it does not cover: the keyring ships in the same tarball as the code, so
someone who can rewrite the package can rewrite the keyring. The signature
protects the DB wherever it travels without that code — a mirror, a copy passed
with `--db`, a vendored file — and ties it to a key the maintainer holds.

### Release key (maintainer)

```bash
node mcp-ecosystem-intelligence/scripts/sign_db.cjs --keygen ~/mcp-vault-release.pem
node mcp-ecosystem-intelligence/scripts/sign_db.cjs --public-entry --key-file ~/mcp-vault-release.pem
gh secret set MCP_VAULT_SIGNING_KEY < ~/mcp-vault-release.pem
```

`release.yml` runs `sign_db.cjs --release`, which refuses to publish without
the secret or with a key the keyring does not list, then packs the tarball,
unpacks it where there is no `.git`, and runs `mcp-vault signature --strict`
there before `npm publish`. Keep an offline copy of the private key; never
commit it.

## Provenance of this package

`release.yml` publishes with `npm publish --provenance` and refuses to publish
without an attestation unless a maintainer dispatches it with
`allow_unprovenanced`.

**No published version so far has a provenance attestation.** npm accepts a
provenance bundle only from a GitHub-hosted runner, and hosted runners do not
start on this account (a billing lock), so 0.14.0, 0.14.1, 0.15.1 and 0.15.2
went out through the override, on purpose and in the open; 0.12.0 predates the
requirement. 0.15.0 was never published (the registry goes 0.14.1 → 0.15.1).
Every version does carry npm's registry signature over `name@version:integrity`
(`npm audit signatures` verifies it); what is absent is `dist.attestations`,
and `npm view @froggychips/mcp-vault@<version> dist.attestations` shows that
plainly.

The override path signs the statement before npm rejects it, so three sigstore
log entries describe tarballs without an attestation attached:
0.15.0 ([2883447939](https://search.sigstore.dev/?logIndex=2883447939), never
published), 0.15.1 ([2931732566](https://search.sigstore.dev/?logIndex=2931732566))
and 0.15.2 ([2932476094](https://search.sigstore.dev/?logIndex=2932476094)).
Provenance returns when a hosted runner starts; the publish job needs no
change. Until then the DB signature above is the integrity statement this
project can make about its own data.

## What `bound` means for provenance

For the servers it checks, `verify` reports a server's provenance as `bound` when **all** of these hold:

1. npm's own registry signing key — the key `dist.signatures` is checked
   against — signed a DSSE statement whose subject digest is the artifact this
   run verified;
2. a signing certificate in the bundle names the repository the DB records
   (the Fulcio SAN `https://github.com/<owner>/<repo>/<workflow>@<ref>`);
3. the builder is a GitHub Actions runner, matched anchored.

Not validated: the Fulcio certificate chain and the Rekor inclusion proof.
Anyone can mint a certificate with any SAN, so (2) is a *claim about* a
repository; that is why (1) must rest on npm's key. A statement verified only
against the bundle's own certificate reaches `claimed`, not `bound`. Nothing
here establishes that the code is benign.

## Threat model

### In scope

- A config that `check` / the Action passes although it launches an unpinned,
  lookalike or source-overridden server, or holds a plaintext secret.
- A check that did not run being reported as one that passed — the recurring
  bug shape in this kind of tool (a registry timeout counted as OK, a feed
  outage read as "no advisories").
- A tampered entry in `tools_database.json` leading `install` to write a
  tampered command into a config.
- A secret value from a host config appearing in any output.
- Code execution through crafted input: a config, a DB entry, a policy file.
- This repository's CI shipping a poisoned DB refresh without review.

### Out of scope

- Vulnerabilities in the MCP servers themselves (report to their maintainers).
- What a server does at runtime. mcp-vault reads configs and metadata before
  anything runs; it is not a sandbox and not a runtime monitor.
- A local user who can already write to the installed package or the DB.
- A malicious release published under a version number after its hash was
  pinned: the hash pins bytes, it does not audit them.

## CI isolation model

GitHub-hosted runners do not start on this account, so every job of this
repository runs on one self-hosted machine, and isolation happens inside it:

| Input | Where it runs |
|---|---|
| PR-authored code (tests, scripts) | container: `--network none`, repo mounted read-only, `--cap-drop ALL`, `no-new-privileges`, no docker socket |
| PR-authored data (`tools_database.json`) | evaluated by **base-commit** code; every docker launch is rebuilt from its pinned digest, so flags in an entry cannot reach the host |
| Third-party MCP servers | always `eval --sandbox`; `--unsafe` is never used in CI |
| Our own code (push, cron) | directly on the runner |

Outputs go under `RUNNER_TEMP`, never inside the checkout (a PR can commit a
path as a symlink). [`tests/ci_manifest.test.cjs`](tests/ci_manifest.test.cjs)
asserts these properties per step, plus SHA-pinned actions, no `curl | sh` and
a timeout on every job. The weekly DB refresh opens a PR and is never
auto-merged; that PR is the only automated path into the DB.

Repository settings this relies on: default `GITHUB_TOKEN` permission read;
fork pull requests need maintainer approval before any workflow runs (for a
`pull_request` event GitHub uses the workflow file *from the PR*, so the
manifest test is a regression check, not a boundary); SHA pinning required for
actions. CodeQL runs as advanced setup (`javascript-typescript` and `actions`,
`security-extended`) on the self-hosted runner, because the default setup only
runs on hosted runners.
