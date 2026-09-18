# Changelog

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
