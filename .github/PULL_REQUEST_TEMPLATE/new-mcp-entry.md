<!--
Use this template for PRs that add a new entry to tools_database.json.
For promoting candidate → verified, use chore: promote <name> to trust:verified
and tick the checklist from CONTRIBUTING.md instead.
-->

## Server

- **Name:** `<pkg-name>`
- **Category:** `<category>` (see CONTRIBUTING.md for valid values)
- **Source:** <https://github.com/owner/repo>
- **Trust on entry:** `candidate`
- **One-line purpose:** _what does it do?_

## Why this server

_What gap in the existing DB does this fill? Why this server vs alternatives in the same category?_

## Health snapshot at submission

- Stars: …
- Last commit: … days ago
- Open issues: …
- License: …
- `health_score`: … (from `calculate_health.cjs`)
- `classification`: …

## Author checks

- [ ] `install_cmd` is pinned to an explicit version (npm/PyPI) or `@sha256:` digest (Docker)
- [ ] Ran `verify_integrity.cjs --update` — `version` and `pkg_integrity` are populated
- [ ] Ran `verify_integrity.cjs --no-audit` — exits 0
- [ ] Ran `verify_integrity.cjs` (full audit) — no HIGH/CRITICAL CVEs, or any flagged ones are listed below
- [ ] Entry uses the schema from CONTRIBUTING.md (no missing required fields)
- [ ] Not a duplicate of an existing entry (different name but same `source_url` counts as a duplicate)

## Reviewer-visible concerns

_Anything that should make a reviewer slow down. Examples: install hooks, non-OSI license, unfamiliar publisher, server requires a paid account, large `est_tools_count` without a `toolsets` mitigation._

If you spotted CVEs in the full audit but think the entry is still worth adding: explain why here.

## Out of scope for this PR

_Things that intentionally are not done here — e.g. "promotion to `verified` will be a separate PR after we use it for a week."_
