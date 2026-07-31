# Changelog

## [0.13.0](https://github.com/froggychips/mcp-skills-vault/compare/v0.12.0...v0.13.0) (2026-07-31)


### Features

* **ops:** CI deadman that runs outside CI ([81bddba](https://github.com/froggychips/mcp-skills-vault/commit/81bddbaf7b38d4d39a0fe72ca2fb55a12b688d80))
* **ops:** CI deadman that runs outside CI ([189a0b8](https://github.com/froggychips/mcp-skills-vault/commit/189a0b87459613286bf43f7ae92291b5517e57c3))


### Bug Fixes

* **discover:** break ranking ties on name so the inbox stops reshuffling ([dbb364e](https://github.com/froggychips/mcp-skills-vault/commit/dbb364e261bd578e66970cdf7ddc7bb1e38cbc2e))
* **discover:** break ranking ties on name so the inbox stops reshuffling ([a2fad7d](https://github.com/froggychips/mcp-skills-vault/commit/a2fad7db4e340ce4e2d91d1c7d2157ccd00ea2ab))
* **docker:** talk to registry-1.docker.io, not to the docker.io namespace ([b45be3a](https://github.com/froggychips/mcp-skills-vault/commit/b45be3afec37f623ccd547890a3862d26d6b63ce))
* **docker:** talk to registry-1.docker.io, not to the docker.io namespace ([5ccb18a](https://github.com/froggychips/mcp-skills-vault/commit/5ccb18a12429abe6d4c7fc907b170d964b955911))
* **eval:** survive a missing launcher instead of taking the run down ([60c3535](https://github.com/froggychips/mcp-skills-vault/commit/60c353573f70c2e096738d1117fa7a356c9fedc7))
* **eval:** survive a missing launcher instead of taking the run down ([b7d55eb](https://github.com/froggychips/mcp-skills-vault/commit/b7d55ebd7c45f7b70d42acdee893b272ad84f20b))
* flush stdout before exiting, so verdicts and JSON aren't truncated ([d197806](https://github.com/froggychips/mcp-skills-vault/commit/d197806786f3fda51fbaf6bd542cf9da7a2d8d7e))
* flush stdout before exiting, so verdicts and JSON aren't truncated ([4336f6d](https://github.com/froggychips/mcp-skills-vault/commit/4336f6db2d4b32f65d1df16beb05c18ecc969b81))
* **license:** classify Eclipse, SPDX expressions and npm's non-SPDX values ([f6fba34](https://github.com/froggychips/mcp-skills-vault/commit/f6fba3448d9ff545b1dab8c37d662b437d640560))
* **license:** classify Eclipse, SPDX expressions and npm's non-SPDX values ([93220c7](https://github.com/froggychips/mcp-skills-vault/commit/93220c7911410970a84f836c05b8f81397805298))
* **release:** run release-please in manifest mode so the version actually bumps ([9b83db9](https://github.com/froggychips/mcp-skills-vault/commit/9b83db9c5c98718c1a92a91e1f51f26820ac78be))
* **release:** run release-please in manifest mode so the version actually bumps ([993358d](https://github.com/froggychips/mcp-skills-vault/commit/993358d5d2cd4716338f3cf87723237ac102292a))
* **scores:** preflight on API reachability, not on `gh auth status` ([de60457](https://github.com/froggychips/mcp-skills-vault/commit/de604576fc504eedad5c812340bc4d4019893b9e))
* **scores:** preflight on API reachability, not on `gh auth status` ([b04dc4d](https://github.com/froggychips/mcp-skills-vault/commit/b04dc4d92b1eafa79fbe37a4bc18f3e5cb36d1e6))


### Documentation

* sync all .md to 114 entries / 20-76-18 tiers / sandboxed eval / 285 tests ([#66](https://github.com/froggychips/mcp-skills-vault/issues/66)) ([e2a64f4](https://github.com/froggychips/mcp-skills-vault/commit/e2a64f4cc26f08e50b361ef018f6921b7b8439a1))


### Build

* **deps:** bump actions/checkout from 6 to 7 ([#68](https://github.com/froggychips/mcp-skills-vault/issues/68)) ([6a2ecc8](https://github.com/froggychips/mcp-skills-vault/commit/6a2ecc81ce2a69486e0ac5d42be419abcf454f7a))
* **deps:** bump actions/setup-node from 6 to 7 ([de7ebf6](https://github.com/froggychips/mcp-skills-vault/commit/de7ebf6418b98a07e47a99923f087f5945538973))
* **deps:** bump actions/setup-node from 6 to 7 ([58d5511](https://github.com/froggychips/mcp-skills-vault/commit/58d551196977d9a65a4663aed256770ced1cb21a))


### CI

* deadman for the self-hosted runner ([15513f2](https://github.com/froggychips/mcp-skills-vault/commit/15513f2c384abad0f5ea9e4cdebd6d808a246246))
* deadman for the self-hosted runner ([568ac83](https://github.com/froggychips/mcp-skills-vault/commit/568ac83ff5a4d02a297c2f74a47beb887a21c25d))
* give refresh-hashes a GITHUB_TOKEN instead of the maintainer's keyring ([e593a4b](https://github.com/froggychips/mcp-skills-vault/commit/e593a4b4a775e10ac7fd5f63d7d2e1e14e5d4d68))
* give refresh-hashes a GITHUB_TOKEN instead of the maintainer's keyring ([7ff444f](https://github.com/froggychips/mcp-skills-vault/commit/7ff444fb5837662e68f251a2fc54e4300493eac7))
* move npm-publish + mcp-eval-pr to self-hosted (no github-hosted runners) ([#67](https://github.com/froggychips/mcp-skills-vault/issues/67)) ([8be08dd](https://github.com/froggychips/mcp-skills-vault/commit/8be08dd4a7bd76e23d5f61b4ab73612bec2223f7))
* park the deadman — this account has no GitHub-hosted minutes ([6bb13e2](https://github.com/froggychips/mcp-skills-vault/commit/6bb13e29f270ff6ee5c0c27c0eb8c99bea049d83))
* park the deadman — this account has no GitHub-hosted minutes ([1e994df](https://github.com/froggychips/mcp-skills-vault/commit/1e994df80f31d0d005ffd052135867f9b03302ce))
* smoke the weekly refresh PR, which the pull_request gate can't see ([d4c71c0](https://github.com/froggychips/mcp-skills-vault/commit/d4c71c051073906dffd0306e95ec1032304c2a9b))
* smoke the weekly refresh PR, which the pull_request gate can't see ([b4ce6f6](https://github.com/froggychips/mcp-skills-vault/commit/b4ce6f65f4eb1308779f680d6aa7f1471cc60d1e))

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
