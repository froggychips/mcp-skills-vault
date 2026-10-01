# Changelog

## [0.16.0](https://github.com/froggychips/mcp-skills-vault/compare/v0.15.2...v0.16.0) (2026-10-01)


### ⚠ BREAKING CHANGES

* **status:** the verdict is a view of one Decision
* **audit:** `findings` is the findings@1 document; every category decided once
* **verify:** `verify --offline` (and `npm run verify` without the new flag) exits 1 when the DB records a found problem for an entry's pinned version — a known advisory, a yanked or unpublished release — as `explain` already did. Stale claims of absence are `unknown` and fail only under --fail-unverified / `unverified: fail`. Use `--fail-families integrity,pin,oci,verify,policy` to ask only whether the DB is consistent.
* **explain:** `explain <name>` can now exit 1 where it exited 0: when the decision fails at the effective policy's fail_on without being a deny (stale or missing evidence under `unverified: fail` / --fail-unverified, warnings under --strict). It exits as `verify --entry <name>` does for the same inputs.

### Features

* **action:** GitHub Action and pre-commit hook over a repo's MCP configs ([1777084](https://github.com/froggychips/mcp-skills-vault/commit/1777084d933fdd9a12ea5dca866893661dfad194))
* **action:** GitHub Action and pre-commit hook over a repo's MCP configs ([d6d23ae](https://github.com/froggychips/mcp-skills-vault/commit/d6d23ae331f8ee72e5c607109bcbd457653d495b))
* **action:** run mcp-vault check in the Action and the pre-commit hook ([724a3d5](https://github.com/froggychips/mcp-skills-vault/commit/724a3d5ed4b6de3486436f171a591968cd59aa4a))
* ADR step 3 — every deciding command exits via decide() ([35cd357](https://github.com/froggychips/mcp-skills-vault/commit/35cd3573e78bb9360976b1049026efb8d1848b78))
* **audit:** `findings` is the findings@1 document; every category decided once ([540a13b](https://github.com/froggychips/mcp-skills-vault/commit/540a13b61094816def7803b21b07b041e3713adb))
* **audits:** signed, non-transitive audit imports (cargo-vet model) ([a84bf05](https://github.com/froggychips/mcp-skills-vault/commit/a84bf0597389223f479cb799e76eb239d17592e4))
* **availability:** exit via decide() in mode observe ([ea4fa90](https://github.com/froggychips/mcp-skills-vault/commit/ea4fa90c56c76d2fadd81087e2fc7fe6fdd64ab9))
* **badges:** vetted-by badges that go grey when the evidence ages ([898f759](https://github.com/froggychips/mcp-skills-vault/commit/898f7596cb5b1925377c599c995f020872b5b12f))
* **badges:** vetted-by badges that go grey when the evidence ages ([4a3a125](https://github.com/froggychips/mcp-skills-vault/commit/4a3a1254a29329aa096f89201d5e50ed5e6c5f6f))
* **budget:** --budget is a policy ceiling, decided by budget/over ([131d4ee](https://github.com/froggychips/mcp-skills-vault/commit/131d4ee84d5dce581913948fa682a97b41a37da5))
* **capabilities:** exit via decide() in mode observe ([c19877e](https://github.com/froggychips/mcp-skills-vault/commit/c19877eed46de004773f45699988ffe110edbbf5))
* **check:** mcp-vault check — the repo's MCP configs in one pass ([95f7266](https://github.com/froggychips/mcp-skills-vault/commit/95f7266f18518f009d16e0affa89459e59fdb20c))
* **decide:** rows and modes for a command's own run ([6e1c02d](https://github.com/froggychips/mcp-skills-vault/commit/6e1c02d26a79e689aa41ef91d212f049dceb3098))
* **docker-drift:** exit via decide() in mode observe ([6fca7d0](https://github.com/froggychips/mcp-skills-vault/commit/6fca7d07d8ef59ddde6e84dc64205916d4975d6f))
* **doctor:** exit via decide() — the checks are environment/* findings ([ab8200e](https://github.com/froggychips/mcp-skills-vault/commit/ab8200eb2a46002f976b17647e9ed5799783dc00))
* **eval:** exit via decide() in mode observe ([f8a4c9f](https://github.com/froggychips/mcp-skills-vault/commit/f8a4c9fd0f5bfe10c16323c13412b84dd52de538))
* **findings:** one model, one place that decides — verify and explain on it ([8722eae](https://github.com/froggychips/mcp-skills-vault/commit/8722eaedd417cb44b8e43c6b75aa0c4c53bc4d9b))
* **findings:** the docker pin cross-check from [#117](https://github.com/froggychips/mcp-skills-vault/issues/117) is a typed finding ([75c66b7](https://github.com/froggychips/mcp-skills-vault/commit/75c66b7ebb1264d77886c6bba18a9b6021c0ebce))
* **identity:** exit via decide() in mode observe ([5073c9d](https://github.com/froggychips/mcp-skills-vault/commit/5073c9d64f0b56da94e0886164ddee3994d52e5b))
* **license-drift:** exit via decide() in mode observe ([6207550](https://github.com/froggychips/mcp-skills-vault/commit/620755007633266c3e5ac8c38f3b7707937eb1f9))
* **lookalike:** flag typosquat and lookalike names of vault entries ([562a6b4](https://github.com/froggychips/mcp-skills-vault/commit/562a6b4c2d366b1275572f051a06612278936f8e))
* **lookalike:** flag typosquat and lookalike names of vault entries ([f5ee981](https://github.com/froggychips/mcp-skills-vault/commit/f5ee981e528ab9236c3b9cdc15d89f3a1ab15b0a))
* mcp-vault check — the repo's MCP configs in one pass (Action + pre-commit) ([1fd180e](https://github.com/froggychips/mcp-skills-vault/commit/1fd180e95fa0c76983e55f572f312756fc8f227d))
* one findings model, one place that decides, time as an input (ADR 0001) ([92913dc](https://github.com/froggychips/mcp-skills-vault/commit/92913dce1ccf5a9e2e655c91621dd36aa1037ff8))
* **policy:** org allowlist/denylist, inherited policy, per-tool approval ([5a8ecd3](https://github.com/froggychips/mcp-skills-vault/commit/5a8ecd35c21c5524b7b2a5ad521f094fcb2eb9d5))
* **policy:** org allowlist/denylist, inherited policy, per-tool approval ([406d5fc](https://github.com/froggychips/mcp-skills-vault/commit/406d5fcb8936003238a1ef943f61c260b4b96240))
* **posture:** exit via decide() in mode observe ([f66126a](https://github.com/froggychips/mcp-skills-vault/commit/f66126a43896b52a38deae746676d771e40991d6))
* **registry:** export to any site root (--out, --base-url), .json twins, nothing committed ([0d1a024](https://github.com/froggychips/mcp-skills-vault/commit/0d1a024a510f2ee009e2ddf4b8644f306efb25df))
* **registry:** serve the vault as a static MCP sub-registry, and ingest the official one ([5d3611a](https://github.com/froggychips/mcp-skills-vault/commit/5d3611a0e6836f2afa719d9e34b5649a80911f5d))
* **registry:** the vault as a static MCP sub-registry, and an official-registry ingest ([f19780a](https://github.com/froggychips/mcp-skills-vault/commit/f19780aadda826272404f55462ef14f2aed789f3))
* **secrets:** find plain-text secrets in MCP host configs ([a3d61a5](https://github.com/froggychips/mcp-skills-vault/commit/a3d61a5f666f3088606ebf89082f122f7df2e216))
* **secrets:** find plain-text secrets in MCP host configs ([6403bc5](https://github.com/froggychips/mcp-skills-vault/commit/6403bc543af04c144efa3cdc72dbb8a166f5eee0))
* **setup:** toxic flows and tool shadowing across the configured set ([27422d9](https://github.com/froggychips/mcp-skills-vault/commit/27422d95793e2db9ac878b853dd73f9fcb140307))
* **setup:** toxic flows and tool shadowing across the configured set ([ed099d4](https://github.com/froggychips/mcp-skills-vault/commit/ed099d4fd466acb00493ce8e029aec9749277be7))
* signed DB and signed, non-transitive audit imports ([e696eb9](https://github.com/froggychips/mcp-skills-vault/commit/e696eb9f5b672c8e9040330515f47bf65a3808ee))
* **signing:** Ed25519-signed DB, checked before the CLI reads it ([77fa907](https://github.com/froggychips/mcp-skills-vault/commit/77fa907857158c7d5a4aab6b1c063ff3b82383a5))
* **status:** one line pointing to the issue tracker (no data collected) ([41df118](https://github.com/froggychips/mcp-skills-vault/commit/41df118760a5ab62a81312acade034ac845ab535))
* **status:** the verdict is a view of one Decision ([ce55522](https://github.com/froggychips/mcp-skills-vault/commit/ce5552297bc82c5667564434bfdbeeb429b99989))
* **time:** the clock is read once, and --as-of replays it ([23fbbe6](https://github.com/froggychips/mcp-skills-vault/commit/23fbbe626ba1ca01d5732bafeb36b0a7a2cbfa3c))
* **tool-scan:** read tool descriptions and schemas for poisoning patterns ([abbfe8e](https://github.com/froggychips/mcp-skills-vault/commit/abbfe8efbbe097b188703137ff85eb682f3018d8))
* **tool-scan:** tool poisoning in descriptions and schemas, by rule ([265a028](https://github.com/froggychips/mcp-skills-vault/commit/265a0284da47776090ef677a7f988f6e618e0f8d))
* **upgrade:** exit via decide() in mode observe ([3d28cde](https://github.com/froggychips/mcp-skills-vault/commit/3d28cde8b86eda31903cb283810bfffea96e9fb2))
* **verify:** config/unpinned-launch — a finding about the config, not the DB ([dfa0796](https://github.com/froggychips/mcp-skills-vault/commit/dfa07960a46cac4fde2f8952377b8133d91cf165))


### Bug Fixes

* **action:** a failing config no longer ends the verify step before it reports ([eefc42f](https://github.com/froggychips/mcp-skills-vault/commit/eefc42f5ef043ea19521e29a7341c0bac6e47a66))
* **action:** a failing config no longer ends the verify step before it reports ([45573a9](https://github.com/froggychips/mcp-skills-vault/commit/45573a9c5a0ff31136b91e05b9041d543957b1b1))
* **action:** refuse a version: that predates check, with exit 2 ([c78c0cd](https://github.com/froggychips/mcp-skills-vault/commit/c78c0cd41e1f30526923aad18efa7bdcc191877a))
* **action:** run from its own unpacked checkout — the SHA pin is the DB's integrity ([ad476cf](https://github.com/froggychips/mcp-skills-vault/commit/ad476cf3654beb09c0f8a25fe39a9b16c6e814c8))
* **approve:** load and validate the policy before writing mcp.lock.json ([683a5a3](https://github.com/froggychips/mcp-skills-vault/commit/683a5a38d83359b834acb92e168a45b273fa969f))
* **audit:** the same release spelled another way is not drift ([23f259a](https://github.com/froggychips/mcp-skills-vault/commit/23f259a158a815e57c8bab0d6ed9f5fd449f4ee3))
* **check:** a secret's fix line in one sentence when the host has no reference syntax ([aadbdf6](https://github.com/froggychips/mcp-skills-vault/commit/aadbdf6fd2625bbfb5124664f552cead6d93cd06))
* **check:** apply the vault's stored evidence to a configured server ([bb86be6](https://github.com/froggychips/mcp-skills-vault/commit/bb86be655fa8a3ec410dd050e227235dea96ccd0))
* **check:** decide a shared line in gate mode; keep checking partly broken configs ([7a72e7a](https://github.com/froggychips/mcp-skills-vault/commit/7a72e7a6ca33acc71f03ca8b6b0c114d0597f68e))
* **check:** match a configured server to its vault entry by what it launches ([bc5644a](https://github.com/froggychips/mcp-skills-vault/commit/bc5644a8025bb39b0ec8089847793a50cb2dabc6))
* **check:** one text line per cause for unpinned and overridden launches ([a59feb0](https://github.com/froggychips/mcp-skills-vault/commit/a59feb07ce1e1d9f24afa29e7abd43d0faf47b3f))
* **check:** say how old the vault's record is, as context only ([29083c5](https://github.com/froggychips/mcp-skills-vault/commit/29083c5449b03661fb57f48982fdb02548ce8932))
* **ci:** escape backslashes before pipes in the refresh summary table ([f4c6346](https://github.com/froggychips/mcp-skills-vault/commit/f4c6346235cb4f14c16b7bbdec15eca3e7dd66c1))
* **ci:** judge changed-entry smoke against the base line, not absolute status ([65b4322](https://github.com/froggychips/mcp-skills-vault/commit/65b43228ea40eb282c43781a3622497f409ba26c))
* **ci:** judge changed-entry smoke against the base line, not absolute status ([ec03f02](https://github.com/froggychips/mcp-skills-vault/commit/ec03f0248d8217432881cda8f72056b6315fdfdf))
* **ci:** the weekly refresh records its findings instead of dying on them ([41aa877](https://github.com/froggychips/mcp-skills-vault/commit/41aa877b269292e6ac53b2b72bd7ba620f13c349))
* **ci:** weekly refresh records findings as evidence instead of failing; eval artifact, license-drift, integration tests ([6430d55](https://github.com/froggychips/mcp-skills-vault/commit/6430d5592443b9b2a4b414e4688724ba0f0ea50f))
* **cli:** help leads with check and status; refresh says what it refreshes ([517dea4](https://github.com/froggychips/mcp-skills-vault/commit/517dea4bf96ff8709337822ba27aca87fc518808))
* **db:** clear seven vulnerable pins, drop an unpublished name, record three non-OSI licences ([6a080c3](https://github.com/froggychips/mcp-skills-vault/commit/6a080c3bee7598aa20ddbe05f84295af5d5d9fb6))
* **db:** drop @taazkareem/clickup-mcp-server — proprietary licence, not inspectable ([8928a7f](https://github.com/froggychips/mcp-skills-vault/commit/8928a7fdf2094033ab29d0fcf5d9e88d27f5eff3))
* **db:** monday-api-mcp — renamed source repo, pin 3.3.1 in install_cmd ([2e4014a](https://github.com/froggychips/mcp-skills-vault/commit/2e4014affb7cef4cd5314c9d6bbdfdcf7ba8608c))
* **db:** move seven vulnerable pins to the shortest version that clears every advisory ([669108e](https://github.com/froggychips/mcp-skills-vault/commit/669108e8be472466d07c89905a8d0b1e3294df24))
* **db:** pin install_cmd to the verified version for 72 npm entries ([63d6533](https://github.com/froggychips/mcp-skills-vault/commit/63d6533f83c0b2e29b122c10602d726bb649610d))
* **db:** pin mcp-redis and [@yoda](https://github.com/yoda).digital/gitlab-mcp-server to registry releases ([326c5c3](https://github.com/froggychips/mcp-skills-vault/commit/326c5c395b8ab4f9e2ec248afb3524ba00a56769))
* **db:** pin mcp-redis and [@yoda](https://github.com/yoda).digital/gitlab-mcp-server to registry releases ([7c4a1c5](https://github.com/froggychips/mcp-skills-vault/commit/7c4a1c59cf76693aef3dd47ea61d4d50e2bab1ca))
* **db:** record the non-OSI licences three entries actually ship under ([98345fc](https://github.com/froggychips/mcp-skills-vault/commit/98345fce8a2c7aaf8ef62d374186e8e3c93b27c6))
* **db:** remove @diskd-ai/email-mcp, an unpublished and claimable name ([703c76a](https://github.com/froggychips/mcp-skills-vault/commit/703c76ae3aadbcc628974d8c7641d7ea8ef3fc80))
* **decide:** explain exits as verify does — context rows never decide ([da463ba](https://github.com/froggychips/mcp-skills-vault/commit/da463ba48c21f4bfc36173f3ff6c00add8c91417))
* **docker-drift:** fail --write when a drift cannot be applied ([28d1979](https://github.com/froggychips/mcp-skills-vault/commit/28d1979ec4c8e4dfb2b5c9dd10a63dc5870e3f0b))
* **docker-drift:** pkg_integrity moves with install_cmd, and verify checks they agree ([cc6b943](https://github.com/froggychips/mcp-skills-vault/commit/cc6b943d42ab2d3686b7fa1c382c626030f20668))
* **docker-drift:** pkg_integrity moves with install_cmd, and verify checks they agree ([15394b0](https://github.com/froggychips/mcp-skills-vault/commit/15394b0cac0ac97afa81634bfcb117bb6556f830))
* **explain:** exit at the policy's fail_on, as verify does ([791a7a4](https://github.com/froggychips/mcp-skills-vault/commit/791a7a4375b7ec50e9b313f81f181823e007f158))
* **installed:** read registry launches the way their runner does ([ac48f11](https://github.com/froggychips/mcp-skills-vault/commit/ac48f1112081d6bc5f4d93fa661172c2941cef43))
* **license-drift:** read PEP 639 license_expression before the legacy PyPI fields ([7e9e995](https://github.com/froggychips/mcp-skills-vault/commit/7e9e99548ead7162b176703c26f707b60e7e3aab))
* **lookalike:** a bare name is not asked for tool approval; explain holds it to fail_on ([c1ad59c](https://github.com/froggychips/mcp-skills-vault/commit/c1ad59c40297cb147ab6f7751c112f425dda29dd))
* **lookalike:** a publisher's own unscoped package is not a dropped-scope copy ([c6435b1](https://github.com/froggychips/mcp-skills-vault/commit/c6435b1743968796df2ab758ce2672365bcf3a93))
* **lookalike:** a vault-named key is held to its entry's package ([5708518](https://github.com/froggychips/mcp-skills-vault/commit/5708518b81b2699d11a8024e50fda25a95027819))
* master red after [#128](https://github.com/froggychips/mcp-skills-vault/issues/128)–[#130](https://github.com/froggychips/mcp-skills-vault/issues/130) landed together ([e1adb2d](https://github.com/froggychips/mcp-skills-vault/commit/e1adb2d6daa8948acbe26beb0ba83a3464f0e7cd))
* **parse:** unsure means unknown with a reason — source overrides, every -p, PyPI ranges ([510c4fd](https://github.com/froggychips/mcp-skills-vault/commit/510c4fd3d0bd7828320bc85a7510b13542917a2f))
* pre-commit hook runs on its rev; check matches by artifact and applies stored evidence ([be02738](https://github.com/froggychips/mcp-skills-vault/commit/be027384e96a0e52d2fc3128ad10d12c12d4f5e0))
* **pre-commit:** run the hook on the DB its rev pins ([cd799ab](https://github.com/froggychips/mcp-skills-vault/commit/cd799abd0c6f414d98b73e7021db80d5a7cadde3))
* read real-world MCP configs (npx options, -p, pnpx/bunx/uvx), playwright lookalike, config/unpinned-launch ([09cff4b](https://github.com/froggychips/mcp-skills-vault/commit/09cff4b5de2397a94da9b33d63834311ac943dbb))
* **registry:** the export is the vault's statement, not the working directory's policy ([59b9ea1](https://github.com/froggychips/mcp-skills-vault/commit/59b9ea10bd898cd53d84bae9dc20136e8753b6ed))
* review findings on the stack (explain/verify parity, --fail-families fail-open, README walkthroughs) ([fdaf0a6](https://github.com/froggychips/mcp-skills-vault/commit/fdaf0a62eb7a1ae55ea0be1306246b9b6422bd61))
* **site,docs:** follow [#129](https://github.com/froggychips/mcp-skills-vault/issues/129)'s docker digests into docs/site and the README ([0764942](https://github.com/froggychips/mcp-skills-vault/commit/076494214f9b8bde505a543ca01478f25c243b88))
* **site:** regenerate registry for pinned entries; test that docs/site matches the DB ([71580b2](https://github.com/froggychips/mcp-skills-vault/commit/71580b218d2c61b67da620040d2a576f0a06f65a))
* source_binding by GitHub slug, monday-api-mcp rename, pin every DB install_cmd ([17e7359](https://github.com/froggychips/mcp-skills-vault/commit/17e7359f3de80b9400adf2f195bb57346b174183))
* **tests:** orchestrate integration tests asserted a stale DB and a stale calendar ([fc17e2f](https://github.com/froggychips/mcp-skills-vault/commit/fc17e2f7cf3f221e9cca7c3fab328b2d6895da31))
* **tests:** two tests read the wall clock and went red a week after the evidence did ([f121976](https://github.com/froggychips/mcp-skills-vault/commit/f121976e203744e1ca0b0a1d93a799def075817a))
* **tests:** two tests read the wall clock and went red a week after the evidence did ([8f78ea8](https://github.com/froggychips/mcp-skills-vault/commit/8f78ea8ce4101f1630e5627897d4926ddb39bb4a))
* **time:** a replay reads the record as it stood, and never dates a live look ([25deea7](https://github.com/froggychips/mcp-skills-vault/commit/25deea717c387aff1e34cffb207316430b4dc0c2))
* **tool-scan:** name the incomplete status in the trust weights ([680044a](https://github.com/froggychips/mcp-skills-vault/commit/680044a1f30981e4efa10e94343617b564e3411f))
* **verify:** --fail-families without a usable value is a usage error (exit 2) ([d026186](https://github.com/froggychips/mcp-skills-vault/commit/d026186b3073c6e361c03ec5b0abe150a60f601f))
* **verify-summary:** judge freshness at an explicit asOf, not Date.now() ([c33e736](https://github.com/froggychips/mcp-skills-vault/commit/c33e736cfa3dda09aa69008cd0b5a49f3edf40aa))
* **verify:** an entry's failure count is its Decision's, trust outcomes included ([e2a1def](https://github.com/froggychips/mcp-skills-vault/commit/e2a1def60cfe9faba5ca1f0fa800117f7327f415))
* **verify:** compare source_binding by GitHub slug, one URL normaliser ([185ecb7](https://github.com/froggychips/mcp-skills-vault/commit/185ecb7eea341208cfcee40740bef448c74837de))
* **verify:** re-pin on --update, follow GitHub rename redirects, aliases in provenance ([c34d65a](https://github.com/froggychips/mcp-skills-vault/commit/c34d65a2d60fd6a979d271cafa26c529cbdd6a7f))
* **verify:** the offline gate applies stored evidence, as explain does ([a016f4e](https://github.com/froggychips/mcp-skills-vault/commit/a016f4ed18269a6cde61df5c3ba208cd9612324e))


### Refactors

* **badges:** badge state is a view of the entry's Decision (ADR 0001) ([f713f73](https://github.com/froggychips/mcp-skills-vault/commit/f713f7358d91240e6eb766550d24bbf3fb72354c))
* **policy:** org rules are rows of the one table, decided by decide() ([9d4b1a9](https://github.com/froggychips/mcp-skills-vault/commit/9d4b1a906c2f301f5a279e05c387e99b7f5a0d8c))
* **registry:** export and ingest decide through decide() (ADR 0001) ([6629283](https://github.com/froggychips/mcp-skills-vault/commit/662928393193352ad73e80be54738a9e3330f814))
* **secrets:** report through findings@1 and decide() (ADR 0001) ([697f174](https://github.com/froggychips/mcp-skills-vault/commit/697f1741151e383170d414ffa84373cbaa65221e))
* share the feedback line and the outcome class ([18a52d7](https://github.com/froggychips/mcp-skills-vault/commit/18a52d7987516fd049a9bfba8abf06338722823e))
* **signing,audits:** migrate to the findings model (ADR 0001) ([13ed6e4](https://github.com/froggychips/mcp-skills-vault/commit/13ed6e4b27de7ee350449c8de0344e5cf97ff02c))


### Documentation

* **adr:** 0001 — one findings model, one place that decides, time as an input ([4b1d328](https://github.com/froggychips/mcp-skills-vault/commit/4b1d3289ef9bd0b1ede030b40712e3d499c46e99))
* **eval:** --fail-tool-scan under --strict also fails on medium ([b19faf2](https://github.com/froggychips/mcp-skills-vault/commit/b19faf2f94248c6b72014ef02398fd89f2388d7d))
* explain answers what the gate answers; the rest is context ([ec058d1](https://github.com/froggychips/mcp-skills-vault/commit/ec058d1899ccb486d990c3a06062af922c38d814))
* follow [#142](https://github.com/froggychips/mcp-skills-vault/issues/142)-[#144](https://github.com/froggychips/mcp-skills-vault/issues/144) — evidence of 2026-10-01, artifact matching, stale as context, pre-commit rev ([d3da42a](https://github.com/froggychips/mcp-skills-vault/commit/d3da42abbf52f902c4668fd03d8e29839da60dc1))
* **readme:** recompute tested figures for the 2026-10-01 evidence ([1f67d65](https://github.com/froggychips/mcp-skills-vault/commit/1f67d657c7dab522bdff105b6fb3eb9884c393a4))
* **readme:** walkthroughs from real runs on the re-pinned DB ([53cc3d7](https://github.com/froggychips/mcp-skills-vault/commit/53cc3d77908c805fa1df08536458d7cee2a5ec98))
* record ADR step 3 and the pre-1.0 --json / exit changes ([cdc6698](https://github.com/froggychips/mcp-skills-vault/commit/cdc6698cbe687e9c8cb17a04bd5a91380ca76ff2))
* restate the README figures for the 2026-09-30 snapshot ([9214cbc](https://github.com/froggychips/mcp-skills-vault/commit/9214cbc2ea3f200595d62efab7fac03f638c969d))
* rewrite the documentation around check, the Action and pre-commit for 0.16.0 ([81cac5e](https://github.com/froggychips/mcp-skills-vault/commit/81cac5eaa5134cbd59e86090d93513a94e344ad8))
* rewrite the documentation around check, the Action and pre-commit for 0.16.0 ([3a83352](https://github.com/froggychips/mcp-skills-vault/commit/3a83352eb5ec25c1db518e63a90d312e5775edd1))
* **security:** 0.15.2, and the sigstore statements as a table ([247ddec](https://github.com/froggychips/mcp-skills-vault/commit/247ddecc937fe403306706d21bbe7518af0f0017))
* **security:** the gate and the lock are different dates ([3f94e89](https://github.com/froggychips/mcp-skills-vault/commit/3f94e896e88ef553166e00e5930c87b65e10be55))


### Tests

* **action:** run the Action's steps on a staged DB at a fixed instant ([756fce1](https://github.com/froggychips/mcp-skills-vault/commit/756fce1a99f455e630d5c05af60215896a8ba07a))
* **audits:** read the key through the descriptor its mode was checked on ([51183b7](https://github.com/froggychips/mcp-skills-vault/commit/51183b77ad71744faeb8c2557557331d9255ca1f))
* **check:** decide over a staged DB at an explicit instant, not today's data ([1632b42](https://github.com/froggychips/mcp-skills-vault/commit/1632b421dc55ca27c3e7d09f0f2eb66bb69e1d8b))
* **consistency:** explain's set findings ([#123](https://github.com/froggychips/mcp-skills-vault/issues/123)) are not verify's; compare the artifact part ([8dec888](https://github.com/froggychips/mcp-skills-vault/commit/8dec8888716d2314b454cba2d376019b9634076b))
* **consistency:** explain's tool-scan fact ([#124](https://github.com/froggychips/mcp-skills-vault/issues/124)) is not verify's either ([a19da26](https://github.com/froggychips/mcp-skills-vault/commit/a19da26277a0a8985ceb6df15be6c86740ee0bd3))
* **db:** every registry entry launches the exact version it verified ([3d35b17](https://github.com/froggychips/mcp-skills-vault/commit/3d35b17dcaa8526cb1f654a996f0d79219895946))
* **decide:** the consistency test covers every deciding command ([e9ed113](https://github.com/froggychips/mcp-skills-vault/commit/e9ed113477c687508659e06cc9c29287233af15e))
* **docs:** date README tier/trust figures and check the date against the DB ([3cb38c9](https://github.com/froggychips/mcp-skills-vault/commit/3cb38c9a7f2924faa116e6ea419a3c528bddbe69))
* **smoke:** skip the git-backed CLI test where git is absent ([4da6edd](https://github.com/froggychips/mcp-skills-vault/commit/4da6edde399ac9a69c516ffc6d649b6024e5b1e7))
* the gate over 18 synthetic configs in launch shapes seen in the wild ([1813ceb](https://github.com/froggychips/mcp-skills-vault/commit/1813ceb61edee494dcfdb7d34ea1515a58e84d62))


### CI

* **smoke:** ask the seeded-DB smoke its own question with --fail-families ([2346583](https://github.com/froggychips/mcp-skills-vault/commit/234658357ade6460c8e72ccd7f3ac02b4a091acf))

## [0.15.2](https://github.com/froggychips/mcp-skills-vault/compare/v0.15.1...v0.15.2) (2026-09-24)


### Bug Fixes

* **license-drift:** a name that is gone has no licence to fail on ([1145d87](https://github.com/froggychips/mcp-skills-vault/commit/1145d8733985f034054a8b3fd628d66087cfd0d0))
* **license-drift:** a recorded gone expires, because the name does not stay free ([77ba157](https://github.com/froggychips/mcp-skills-vault/commit/77ba157c4e46687641bbe063fca8858f1e17dfd3))


### Documentation

* **security:** 0.15.1 shipped unprovenanced, and what sigstore holds about it ([4985bd7](https://github.com/froggychips/mcp-skills-vault/commit/4985bd721c8ebc3683b834cf261a356ffdccca3c))

## [0.15.1](https://github.com/froggychips/mcp-skills-vault/compare/v0.15.0...v0.15.1) (2026-09-21)


### Bug Fixes

* **cache:** an unusable cache is no cache, not a failed scan ([5cebf86](https://github.com/froggychips/mcp-skills-vault/commit/5cebf864d47d976d7e692483d6e6b4939437fcd9))
* **ci:** npm refuses provenance from a self-hosted runner ([c0fedd2](https://github.com/froggychips/mcp-skills-vault/commit/c0fedd253222aa5076beb19eb861260a1c516174))
* **ci:** the documented way out of a billing lock cannot need a hosted runner ([f1e731c](https://github.com/froggychips/mcp-skills-vault/commit/f1e731c78c6cff484411d8a8c6d35f390c798a71))
* the cache's last resort was a path every user on the machine could guess ([6eb35ad](https://github.com/froggychips/mcp-skills-vault/commit/6eb35ad7714ea4e7d2ee34c4827e81f5c80e877a))

## [0.15.0](https://github.com/froggychips/mcp-skills-vault/compare/v0.14.1...v0.15.0) (2026-09-18)


### ⚠ BREAKING CHANGES

* `mcp-vault health` takes 4 positional arguments, not 5, and returns no `classification`. DB entries no longer carry `classification`, `in_registry` or `last_checked`.

### Features

* derive the tier from evidence, and write down what 1.0.0 promises ([886e342](https://github.com/froggychips/mcp-skills-vault/commit/886e342154abb2265461c75d628e1c9af2113f31))
* one entry command, on one screen ([dc97416](https://github.com/froggychips/mcp-skills-vault/commit/dc974168cf0943eefa2e87e3b2119b092ddb1096))


### Bug Fixes

* a broken installer of my own making, and eight more review findings ([87c5fe1](https://github.com/froggychips/mcp-skills-vault/commit/87c5fe183e5cacdd4cde9e5813573a486c4f818f))
* a tools/list with no tools array was a passing zero-tool measurement ([ea7b37d](https://github.com/froggychips/mcp-skills-vault/commit/ea7b37d39dde3dd3dade7604812c4ea2e32633f9))
* fifth pass — a local version label is not a bag of numbers ([53914d2](https://github.com/froggychips/mcp-skills-vault/commit/53914d2efb801a7ebf7a5f47c78097497adb8ec5))
* nine more from the second review pass, seven of them P1 ([27ffe41](https://github.com/froggychips/mcp-skills-vault/commit/27ffe412a6c3604c5c062ef98f787a7992dbd00e))
* stat-then-read is a check-then-use race (CodeQL js/file-system-race) ([1290171](https://github.com/froggychips/mcp-skills-vault/commit/1290171a48fc97cc5af7d7ade77b895d04f69953))
* ten findings from review, four of them P1 ([9657872](https://github.com/froggychips/mcp-skills-vault/commit/96578722bf315e88b487d0712c3c73889813f6a1))
* third review pass — the eval was recording an artifact it had not launched ([d4e1a33](https://github.com/froggychips/mcp-skills-vault/commit/d4e1a33d354d294971822fb6b28c3b3ade64751e))


### Documentation

* measure adoption honestly, and stop building until three people have used it ([961c5ae](https://github.com/froggychips/mcp-skills-vault/commit/961c5ae96fa2fd772f004245dfa18a7faad214c5))

## [0.14.1](https://github.com/froggychips/mcp-skills-vault/compare/v0.14.0...v0.14.1) (2026-09-18)


### Bug Fixes

* **explain:** a rule about a check that never ran is unknown, not a denial ([7aaf9d6](https://github.com/froggychips/mcp-skills-vault/commit/7aaf9d6dedcbff652512fd357ffb86d135560d1f))
* **explain:** a rule about a check that never ran is unknown, not a denial ([464c99e](https://github.com/froggychips/mcp-skills-vault/commit/464c99e1262038f410fd12f44b6c960b96ba3bc4))


### Documentation

* **security:** record that 0.14.0 shipped without provenance, and why ([fa72be4](https://github.com/froggychips/mcp-skills-vault/commit/fa72be45dd4c4acf0eabd2623561f9455f5abc58))

## [0.14.0](https://github.com/froggychips/mcp-skills-vault/compare/v0.13.0...v0.14.0) (2026-09-17)


### Features

* **availability:** detect packages that are gone, yanked, deprecated or relocated ([09747cb](https://github.com/froggychips/mcp-skills-vault/commit/09747cbbff86dec87c776055bae14876c79a5506))
* **budget:** add up what the configured servers cost in context ([2d58872](https://github.com/froggychips/mcp-skills-vault/commit/2d58872f07c4ceacdda61a79200c97487cf96063))
* **budget:** enforce a context ceiling where the decision actually happens ([bf7b449](https://github.com/froggychips/mcp-skills-vault/commit/bf7b449c9b27b096e1c1d6f252b6d661fa9797e6))
* **capabilities:** what a package can do, and what it gained since last time ([6fbefea](https://github.com/froggychips/mcp-skills-vault/commit/6fbefea3f8330bcc62e0702fb29e90feab37456d))
* **docker-drift:** turn drift into a pull request, not a red job ([3d6816f](https://github.com/froggychips/mcp-skills-vault/commit/3d6816f255bdd31f862795932e10525b0e921248))
* **eval:** ship the behavioural evidence, don't just upload it ([67a3987](https://github.com/froggychips/mcp-skills-vault/commit/67a3987626fafa7524528f3a52bf7c9ee66c027e))
* **install:** write any host's config, not just Claude Code's ([35cb55f](https://github.com/froggychips/mcp-skills-vault/commit/35cb55f4818778e096b31e674e49326f1b220827))
* **lock:** mcp.lock.json — freeze the verified tree, fingerprint the tool surface ([7ca0d38](https://github.com/froggychips/mcp-skills-vault/commit/7ca0d3898566e930b9bd9d3036da1a221d9d1ba1))
* registry identity, repository posture, `explain` — and a dead advisory feed ([aece39c](https://github.com/froggychips/mcp-skills-vault/commit/aece39cfa2846b9d4c2572c65eb340e3a5ad7a41))
* **release:** publish with provenance, and refuse to ship without it ([927ffd7](https://github.com/froggychips/mcp-skills-vault/commit/927ffd7f37c924745c59e6e7e967b1853c71fcd7))
* **sbom:** CycloneDX export, and CodeQL where it can actually run ([fe43b30](https://github.com/froggychips/mcp-skills-vault/commit/fe43b30c396429b642c85e903bfaef91a38d21e2))
* **scan:** separate health, trust and fit; give every stack signal a source ([a264d32](https://github.com/froggychips/mcp-skills-vault/commit/a264d32da1577324e3e3949e2055603e3f854778))
* trust from evidence — availability, identity, capabilities, surface, lock, upgrade, explain ([387385f](https://github.com/froggychips/mcp-skills-vault/commit/387385fe136ccfc2cdd5aad2ae0ef6b1a16c546b))
* **trust:** bind provenance to the artifact, and let behaviour cap a recommendation ([e3243d4](https://github.com/froggychips/mcp-skills-vault/commit/e3243d44807a6b308a10c24cd620ec18427032bf))
* typed artifact/launch model, and trust as dated evidence ([1e3ee8c](https://github.com/froggychips/mcp-skills-vault/commit/1e3ee8c3f7b21867f12a814557982cf97fe089aa))
* **upgrade:** the shortest version that clears the advisories, computed not guessed ([4c8eb4d](https://github.com/froggychips/mcp-skills-vault/commit/4c8eb4dcf697f124238758c33c571a61540837ab))
* **verify:** --deep hashes the artifact instead of trusting the registry ([fbcd708](https://github.com/froggychips/mcp-skills-vault/commit/fbcd708e91a1004d40a6afde17754077004e7369))
* **verify:** --deps checks the dependency tree, not just the package ([1575ffa](https://github.com/froggychips/mcp-skills-vault/commit/1575ffacc07325b31af45d76951fdbe0f2661003))
* **verify:** --installed checks what the hosts actually launch ([2bcd2ea](https://github.com/froggychips/mcp-skills-vault/commit/2bcd2eaea4ec3827022a174806f2a2aa2d360c5d))
* **verify:** --json and --sarif, so the gate stops speaking only prose ([13bf893](https://github.com/froggychips/mcp-skills-vault/commit/13bf89397ff1846ebc06e338bd0e0f6d6f709b46))
* **verify:** .mcp-vault.policy.json, so the bar is written down once ([188315d](https://github.com/froggychips/mcp-skills-vault/commit/188315da907280399dcea15cab4e3f7d01f300fb))
* **verify:** check npm registry signatures, read provenance claims ([e35f033](https://github.com/froggychips/mcp-skills-vault/commit/e35f0335a6843137dba6810ff11f8709d1d5dd51))
* **verify:** fail closed on anything the gate could not check ([3150c24](https://github.com/froggychips/mcp-skills-vault/commit/3150c249323062ab024f8f83129de87404075fa7))


### Bug Fixes

* **capabilities:** coverage that one side never recorded is unknown, not a change ([2101cf4](https://github.com/froggychips/mcp-skills-vault/commit/2101cf4b5c11e7d3a029f176961c97684af070fc))
* **ci:** check the npm credential before cutting a release, cap job runtime ([d85759b](https://github.com/froggychips/mcp-skills-vault/commit/d85759bff632e17bf6659460eaef856346c70229))
* **ci:** find the docker socket a launchd runner cannot see ([e92b659](https://github.com/froggychips/mcp-skills-vault/commit/e92b659c27f1187023dc3e1b11b29ed77e76df99))
* **ci:** say plainly when the isolation is unavailable ([e2b37e0](https://github.com/froggychips/mcp-skills-vault/commit/e2b37e075bdff861c2e6746717fea75a1eb5ebd3))
* **ci:** stop running untrusted code on the runner that keeps everything ([f50141d](https://github.com/froggychips/mcp-skills-vault/commit/f50141d3ba399e83750db62200e95aab127d9c25))
* **cli:** argv-form child processes, and flush stdout before exiting ([b9e4e54](https://github.com/froggychips/mcp-skills-vault/commit/b9e4e54a746e770d667d4302659f03687af298dd))
* close a fifth review pass — the sandbox claim, identity, and the socket ([fd870e4](https://github.com/froggychips/mcp-skills-vault/commit/fd870e4f4cfcaf2362264af6f7dbe1bf8e0eaea3))
* close a fourth review pass — ten more, several in the fixes themselves ([d40fc04](https://github.com/froggychips/mcp-skills-vault/commit/d40fc04d7dd6b7512781cb585f91d3736fd432e7))
* close the fifteen defects a second review pass found ([523607d](https://github.com/froggychips/mcp-skills-vault/commit/523607d910999798ef55cc090de7f9e68c77b5be))
* **drift:** both drift gates reported green while checking nothing ([f9e19fd](https://github.com/froggychips/mcp-skills-vault/commit/f9e19fda6cd6f7319c68507394875b91e3140bac))
* **eval:** --no-spawn must not reach the live smoke ([85e8dc8](https://github.com/froggychips/mcp-skills-vault/commit/85e8dc8657b800d6a38901d99197adf9dd5ca42c))
* **eval:** a dead sandbox is not a crashed server ([5192188](https://github.com/froggychips/mcp-skills-vault/commit/5192188705da8b093b0a6f82f650e23449613407))
* **eval:** pace the container starts, and retry a stumbling daemon once ([4be82cf](https://github.com/froggychips/mcp-skills-vault/commit/4be82cf827ec145e1b8cf014544c04b7cdf89d4d))
* **evidence:** build it from typed check results, not from report prose ([2acfd28](https://github.com/froggychips/mcp-skills-vault/commit/2acfd28b5b98e9eb1ff4dbffbf7d5556eeff9986))
* **install:** write the version the gate actually verified ([c1ff034](https://github.com/froggychips/mcp-skills-vault/commit/c1ff034c1e88481245f64e10ad6f0299d8b4bd24))
* **sandbox:** mount the package caches exec, or nothing can run in the jail ([b23caae](https://github.com/froggychips/mcp-skills-vault/commit/b23caaef20d1f308f0a1a160638746be9a3ca35e))
* sixteen defects from review, most of them a comparison that looked like a proof ([1d55ade](https://github.com/froggychips/mcp-skills-vault/commit/1d55ade1fdd38c3e88c5ed0d436d53332f885018))
* **surface:** attribute a drift to an artifact, or admit it cannot be ([f4c5665](https://github.com/froggychips/mcp-skills-vault/commit/f4c5665cd5db5e0e2fde75527e1ead8ee9d0cc46))
* the five CodeQL alerts, which is advanced setup paying for itself in one run ([3a16def](https://github.com/froggychips/mcp-skills-vault/commit/3a16def416a7d9c41891f673772fac41da77b46c))
* **upgrade:** a registry outage is not "no fix available" ([31c398b](https://github.com/froggychips/mcp-skills-vault/commit/31c398b72d8b35df19d0748d4fa4519efd73c1c4))


### Performance

* **verify:** a full registry pass in seconds, not minutes ([6424957](https://github.com/froggychips/mcp-skills-vault/commit/64249578377ae158223848ff68abba8cfe503a4d))


### Refactors

* one anchored definition of what a repository URL names ([00db5e2](https://github.com/froggychips/mcp-skills-vault/commit/00db5e2b53e5a98fd4272243dec5baec53d5f9f0))


### Documentation

* --entry, --fail-unverified, and what install writes now ([7f3fb3f](https://github.com/froggychips/mcp-skills-vault/commit/7f3fb3ff0e72451834fd7996b03c18c45b606ec5))
* bring the documentation up to what the code now does ([950f3fc](https://github.com/froggychips/mcp-skills-vault/commit/950f3fc4ff7ecddbde4caf6f5bd979051d11d762))
* **ci:** note why a base checkout cannot see an action the PR adds ([e232c3f](https://github.com/froggychips/mcp-skills-vault/commit/e232c3f3f68c242216b49a5001e22d38a054a0fb))
* **cli:** --host, --scope and --list-hosts in the CLI help ([a276d89](https://github.com/froggychips/mcp-skills-vault/commit/a276d896690b34f563734f087ed110f3362cc4ab))
* host targets for install, and measuring the token surface ([0d98822](https://github.com/froggychips/mcp-skills-vault/commit/0d9882295e4d938ffb7dc8d3900411fdfbd459ca))
* **security:** write down the CI isolation model, including its limit ([efc3b2f](https://github.com/froggychips/mcp-skills-vault/commit/efc3b2fa9f1cec4367c53a382863decba41dbdb0))
* **security:** write down the repository settings the automation depends on ([407bce1](https://github.com/froggychips/mcp-skills-vault/commit/407bce1c4aa29dbc34f26596e3b3e0e9c4c05394))
* **site:** the install walk-through covers explain, upgrade and lock ([5712745](https://github.com/froggychips/mcp-skills-vault/commit/5712745279bea64158d9993b52b05959112d623c))
* the new checks, the numbers behind them, and CI that collects the evidence ([966e8df](https://github.com/froggychips/mcp-skills-vault/commit/966e8df2f8b6a733c0c336cf4e93b31a9b09fef5))
* the provenance counts are a tested claim, and the policy example explains `bound` ([43c8a90](https://github.com/froggychips/mcp-skills-vault/commit/43c8a90db5f84d3e8fd574a830387929ba719018))
* the tests badge follows the suite (730) ([fce136a](https://github.com/froggychips/mcp-skills-vault/commit/fce136ae2d45c821e48e337314c491ba93c7c4c4))


### Tests

* check the documented numbers against the data, and fix the three that were wrong ([fb1914b](https://github.com/froggychips/mcp-skills-vault/commit/fb1914befbde1007f085d61ae38aacb49fc79730))

## [0.13.0](https://github.com/froggychips/mcp-skills-vault/compare/v0.12.0...v0.13.0) (2026-07-31)


### Features

* **ops:** CI deadman that runs outside CI ([81bddba](https://github.com/froggychips/mcp-skills-vault/commit/81bddbaf7b38d4d39a0fe72ca2fb55a12b688d80))


### Bug Fixes

* **discover:** break ranking ties on name so the inbox stops reshuffling ([dbb364e](https://github.com/froggychips/mcp-skills-vault/commit/dbb364e261bd578e66970cdf7ddc7bb1e38cbc2e))
* **docker:** talk to registry-1.docker.io, not to the docker.io namespace ([b45be3a](https://github.com/froggychips/mcp-skills-vault/commit/b45be3afec37f623ccd547890a3862d26d6b63ce))
* **eval:** survive a missing launcher instead of taking the run down ([60c3535](https://github.com/froggychips/mcp-skills-vault/commit/60c353573f70c2e096738d1117fa7a356c9fedc7))
* flush stdout before exiting, so verdicts and JSON aren't truncated ([d197806](https://github.com/froggychips/mcp-skills-vault/commit/d197806786f3fda51fbaf6bd542cf9da7a2d8d7e))
* **license:** classify Eclipse, SPDX expressions and npm's non-SPDX values ([f6fba34](https://github.com/froggychips/mcp-skills-vault/commit/f6fba3448d9ff545b1dab8c37d662b437d640560))
* **release:** run release-please in manifest mode so the version actually bumps ([9b83db9](https://github.com/froggychips/mcp-skills-vault/commit/9b83db9c5c98718c1a92a91e1f51f26820ac78be))
* **scores:** preflight on API reachability, not on `gh auth status` ([de60457](https://github.com/froggychips/mcp-skills-vault/commit/de604576fc504eedad5c812340bc4d4019893b9e))


### Documentation

* sync all .md to 114 entries / 20-76-18 tiers / sandboxed eval / 285 tests ([#66](https://github.com/froggychips/mcp-skills-vault/issues/66)) ([e2a64f4](https://github.com/froggychips/mcp-skills-vault/commit/e2a64f4cc26f08e50b361ef018f6921b7b8439a1))


### Build

* **deps:** bump actions/checkout from 6 to 7 ([#68](https://github.com/froggychips/mcp-skills-vault/issues/68)) ([6a2ecc8](https://github.com/froggychips/mcp-skills-vault/commit/6a2ecc81ce2a69486e0ac5d42be419abcf454f7a))
* **deps:** bump actions/setup-node from 6 to 7 ([de7ebf6](https://github.com/froggychips/mcp-skills-vault/commit/de7ebf6418b98a07e47a99923f087f5945538973))


### CI

* deadman for the self-hosted runner ([15513f2](https://github.com/froggychips/mcp-skills-vault/commit/15513f2c384abad0f5ea9e4cdebd6d808a246246))
* give refresh-hashes a GITHUB_TOKEN instead of the maintainer's keyring ([e593a4b](https://github.com/froggychips/mcp-skills-vault/commit/e593a4b4a775e10ac7fd5f63d7d2e1e14e5d4d68))
* move npm-publish + mcp-eval-pr to self-hosted (no github-hosted runners) ([#67](https://github.com/froggychips/mcp-skills-vault/issues/67)) ([8be08dd](https://github.com/froggychips/mcp-skills-vault/commit/8be08dd4a7bd76e23d5f61b4ab73612bec2223f7))
* park the deadman — this account has no GitHub-hosted minutes ([6bb13e2](https://github.com/froggychips/mcp-skills-vault/commit/6bb13e29f270ff6ee5c0c27c0eb8c99bea049d83))
* smoke the weekly refresh PR, which the pull_request gate can't see ([d4c71c0](https://github.com/froggychips/mcp-skills-vault/commit/d4c71c051073906dffd0306e95ec1032304c2a9b))

## [0.12.0](https://github.com/froggychips/mcp-skills-vault/compare/v0.11.0...v0.12.0) (2026-06-20)


### Features

* **eval:** sandboxed PR-time behavioural smoke + shared stdio core ([#64](https://github.com/froggychips/mcp-skills-vault/issues/64)) ([22df78d](https://github.com/froggychips/mcp-skills-vault/commit/22df78df44a83080991683c2aeb7f58307fd3c12))

## [0.11.0](https://github.com/froggychips/mcp-skills-vault/compare/v0.10.1...v0.11.0) (2026-06-20)


### Features

* **db:** promote anytype-mcp + touchdesigner-mcp-server from discovery ([#62](https://github.com/froggychips/mcp-skills-vault/issues/62)) ([dc96b35](https://github.com/froggychips/mcp-skills-vault/commit/dc96b35cd4eeab32a9535aeda4154b03c1afd98c))

## [0.10.1](https://github.com/froggychips/mcp-skills-vault/compare/v0.10.0...v0.10.1) (2026-06-05)


### Bug Fixes

* **verify_integrity:** fail closed on unreachable advisory feeds ([#60](https://github.com/froggychips/mcp-skills-vault/issues/60)) ([5718ceb](https://github.com/froggychips/mcp-skills-vault/commit/5718ceb9719d09fae2e4a428a042de208c1ab20a))

## [0.10.0](https://github.com/froggychips/mcp-skills-vault/compare/v0.9.0...v0.10.0) (2026-05-24)


### Features

* add `mcp-vault doctor` local readiness checks for Node, `gh`, Docker, `uvx`, and Claude MCP configs
* add true offline `verify --offline` mode and clarify that `--no-audit` only skips advisory APIs
* add public registry generator (`mcp-vault site-registry`) for `tools_database.json`

## [0.9.0](https://github.com/froggychips/mcp-skills-vault/compare/v0.8.0...v0.9.0) (2026-05-23)


### Features

* mcp-vault list command + actionable install error ([#54](https://github.com/froggychips/mcp-skills-vault/issues/54)) ([2a44975](https://github.com/froggychips/mcp-skills-vault/commit/2a449758da11a7a74aa47dcdca884aa0dac31631))

## [0.8.0](https://github.com/froggychips/mcp-skills-vault/compare/v0.7.0...v0.8.0) (2026-05-23)


### Features

* mcp-vault CLI + npm-publishable package ([#50](https://github.com/froggychips/mcp-skills-vault/issues/50)) ([9c1f9a0](https://github.com/froggychips/mcp-skills-vault/commit/9c1f9a05d16618c033e8d62acaa004fd367b42b1))

## [0.7.0](https://github.com/froggychips/mcp-skills-vault/compare/v0.6.0...v0.7.0) (2026-05-22)


### Features

* audit_setup.cjs — diff installed MCP servers against DB ([#43](https://github.com/froggychips/mcp-skills-vault/issues/43)) ([d4c110b](https://github.com/froggychips/mcp-skills-vault/commit/d4c110be277cbc14d78dcb80a585bd981084fada))
* check_license_drift.cjs — flag MIT→BSL/SSPL relicensing ([#46](https://github.com/froggychips/mcp-skills-vault/issues/46)) ([73b0a04](https://github.com/froggychips/mcp-skills-vault/commit/73b0a042ca98988e529ec5c309deed4acb3e0366))
* **detectStack:** Swift/JVM/Ruby/PHP/.NET manifests + Jira/Atlassian env signals ([#45](https://github.com/froggychips/mcp-skills-vault/issues/45)) ([4513aff](https://github.com/froggychips/mcp-skills-vault/commit/4513aff52c8d057eed1e586e79442c1c0960d10e))
* **discover:** MCP registry + PyPI candidate sources ([#42](https://github.com/froggychips/mcp-skills-vault/issues/42)) ([7bd16f7](https://github.com/froggychips/mcp-skills-vault/commit/7bd16f7bb1b905fa204414bdc87f790d3cb9ccff))

## [0.6.0](https://github.com/froggychips/mcp-skills-vault/compare/v0.5.0...v0.6.0) (2026-05-22)


### Features

* mcp_eval.cjs — behavioural smoke (handshake + tools/list + schema lint) ([#35](https://github.com/froggychips/mcp-skills-vault/issues/35)) ([1f87364](https://github.com/froggychips/mcp-skills-vault/commit/1f873646c2142acb0eeb35c716b1fbee1fe8a88f))

## [0.5.0](https://github.com/froggychips/mcp-skills-vault/compare/v0.4.0...v0.5.0) (2026-05-17)


### Features

* issue template for new MCP server proposals ([#30](https://github.com/froggychips/mcp-skills-vault/issues/30)) ([6a47c5c](https://github.com/froggychips/mcp-skills-vault/commit/6a47c5c31f2214848922cdec6b80824e451b544b))

## [0.4.0](https://github.com/froggychips/mcp-skills-vault/compare/v0.3.0...v0.4.0) (2026-05-14)


### Features

* **db:** add 6 MCPs closing WO/infra gaps from PR [#21](https://github.com/froggychips/mcp-skills-vault/issues/21) signal coverage ([#22](https://github.com/froggychips/mcp-skills-vault/issues/22)) ([35e37ff](https://github.com/froggychips/mcp-skills-vault/commit/35e37ff368f350f773c985d5bdd6ce3ea688d38b))
* **detectStack:** WO/infra signal coverage + SIGNAL_TO_TOOLS expansion ([#21](https://github.com/froggychips/mcp-skills-vault/issues/21)) ([eb367f8](https://github.com/froggychips/mcp-skills-vault/commit/eb367f80aced6c5de91182eb11bc8840188d6041))
