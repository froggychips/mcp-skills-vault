# Philosophy

The rules every change in this repository is held to. They are not
aspirations: a PR that breaks one is rejected however useful the feature is.

## 1. Offline-first

The check people put in CI runs with no network. `mcp-vault check`, the
GitHub Action and the pre-commit hook make no network call unless asked
(`--online`, `offline: false`): the configs are compared with the pins in the
vault DB shipped with that version. Network checks (live registry metadata,
advisory feeds) are an **additive** layer — they can make an answer stricter,
never looser. An air-gapped runner gets the same exit code as a connected one.

## 2. Zero runtime dependencies

Node built-ins only (`fs`, `https`, `child_process`, `path`, `crypto`). No
build step, no bundler, no transpiler. The supply-chain surface of a
supply-chain checker is exactly Node's, and `git clone` + `node
bin/mcp-vault.cjs` runs the same code `npx` does — which is also why the
GitHub Action can run its own checkout and install nothing.

## 3. Deterministic

The answer is a function of its inputs, and time is one of them:

```
result = f(db, evidence, policy, asOf, rules_version)
```

- `db` — the vault DB the version ships with;
- `evidence` — dated observations, each with a shelf life (a hash match holds
  for 90 days, "no advisories" for 7);
- `policy` — the effective `.mcp-vault.policy.json`, organisation policy
  included;
- `asOf` — the instant the evidence is judged at: read once from the clock at
  the command's entry point, or given with `--as-of`. Nothing below the entry
  point reads the clock (`tests/no_wall_clock.test.cjs`);
- `rules_version` — the version of the rule table, i.e. of the package.

Every `--json` document records `as_of`, `rules_version`, the policy and the
facts it was decided on, so its decisions can be recomputed from the document
alone. The same inputs print the same bytes. No randomness, no LLM in the
decision path: the bundled Claude skill is a *consumer* of this output.

## 4. One logic of decisions

Detectors produce **findings**; exactly one function, `decide()` in
[`lib/finding.cjs`](mcp-ecosystem-intelligence/scripts/lib/finding.cjs), turns
findings and policy into decisions, using one rule table
([`lib/policy_rules.cjs`](mcp-ecosystem-intelligence/scripts/lib/policy_rules.cjs)).
`check`, `verify`, `explain`, `status`, `audit`, the Action's job summary and
SARIF are views of those decisions. Two commands cannot disagree about the
same subject, because neither of them decides — see
[ADR 0001](docs/adr/0001-findings-and-time.md).

## 5. Fail closed; no data is not clean

A check that did not run must never look like a check that passed.

- A finding has a state: `observed`, `not-run`, `no-data`, `stale`. Only
  `observed` is a statement about the subject. The others decide to
  `unknown` — never `allow`.
- `unknown` outranks `warn`: "nobody looked" is not softer than "somebody
  looked and did not like it".
- `null` means "not established". It is never replaced by a default, a
  `false` or an empty string.
- Exit `2` means "could not answer" and never "clean". A real finding outranks
  an unreadable input.
- An unknown policy key is an error: a typo that silently enforces nothing is
  worse than no policy.

## 6. Inspectable, and no telemetry

Every output is human-readable by default and machine-readable with `--json`
(and SARIF where it lands on a line). Every DB entry carries its dated evidence;
every change to the DB is a reviewed commit. No telemetry, no remote-fetched
code, no plugins: what is in the repository is what runs. That also means the
project cannot see who uses it — the only signal is a person saying so.

## 7. Boring

Supply-chain tooling should be the thing you forget exists between releases.
A feature earns its place by reducing what a user has to think about, not by
adding capability: `--strict` is a feature; an `--ai-suggest-fixes` would not
be. A change that adds configuration, steps or decisions per PR pays for it.

---

Anything competing on excitement is a different product.
