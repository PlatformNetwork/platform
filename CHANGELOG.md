# Changelog

## [0.2.2](https://github.com/PlatformNetwork/platform/compare/v0.2.1...v0.2.2) (2026-01-10)


### Features

* **validator:** add periodic challenge refresh + apply emission_weight ([3cfbd77](https://github.com/PlatformNetwork/platform/commit/3cfbd77188bc405b02075023d2f7d2c4c7a2f84d))
* **validator:** add periodic metagraph refresh every 5 minutes ([22c9f57](https://github.com/PlatformNetwork/platform/commit/22c9f57bb4bde0aad2858cc9b29ab8ce5d1c1c81))
* **validator:** convert hotkey weights to UIDs using metagraph ([630990c](https://github.com/PlatformNetwork/platform/commit/630990c5203da34a3116bc46405db0db5ebcb09a))


### Bug Fixes

* **bridge:** route root-level endpoints without /api/v1 prefix ([b5102e5](https://github.com/PlatformNetwork/platform/commit/b5102e564cb81a2ea04b07e103938ed54989d2d7))
* **ci:** separate coverage job to prevent cancellation ([8cd7b3e](https://github.com/PlatformNetwork/platform/commit/8cd7b3ef433385c8fb3891d47fac0c92a4b492a4))
* **docker:** use external network to avoid compose label conflict ([8056f50](https://github.com/PlatformNetwork/platform/commit/8056f50da7d1b4169ada7d55f5ee92889ffda1d1))
* **validator:** max-upscale weights to match Python SDK behavior ([63af164](https://github.com/PlatformNetwork/platform/commit/63af1641f65a5c307509747749dccda9565f6568))
* **validator:** send 100% burn when challenge returns no/empty/unresolved weights ([b180427](https://github.com/PlatformNetwork/platform/commit/b180427f95398271c552f42e55442068b38ee23d))
* **validator:** unresolved hotkey weights go to burn instead of being lost ([969bf87](https://github.com/PlatformNetwork/platform/commit/969bf87fcf154ec28bac321ea5c8bc0666d2eb40))


### Code Refactoring

* remove P2P consensus and networking code ([7678293](https://github.com/PlatformNetwork/platform/commit/76782935d5efb0215746c11969cdcde8426535a4))


### Documentation

* add docker network create step to validator guide ([52d29f8](https://github.com/PlatformNetwork/platform/commit/52d29f86facf15d4575433ef2be0769aaa7f4c5d))


### Miscellaneous

* fix configuration table in the readme ([9f3fa85](https://github.com/PlatformNetwork/platform/commit/9f3fa8596a8d10387c8f87a0a423c992f4577776))
* fix configuration table in the readme ([160541e](https://github.com/PlatformNetwork/platform/commit/160541e57ba9f29360ca072025b56aac471f1619))
* nitpicks by coderabbitai ([3e21331](https://github.com/PlatformNetwork/platform/commit/3e21331fc594d17bb5f91b13343752bb28d6df28))
* remove unused method `receive_write_proposal` ([2eabda6](https://github.com/PlatformNetwork/platform/commit/2eabda61b2871e11362b86c707c63e843981cda4))


### Tests

* add missing tests for command.rs ([a7d5f44](https://github.com/PlatformNetwork/platform/commit/a7d5f448282a228ae7454d15e8522319e3789d22))
* add missing tests for config.rs ([7c94ac3](https://github.com/PlatformNetwork/platform/commit/7c94ac32972dcf0690277eef2a98532b885d3ab3))
* cover missing paths for health.rs ([0f777ef](https://github.com/PlatformNetwork/platform/commit/0f777ef12bf3b5a814e69da0b370e6e3cf51b9eb))
* **platform-storage:** add comprehensive test coverage for storage modules ([90940ce](https://github.com/PlatformNetwork/platform/commit/90940ce59a02bacf0dbc59b970349361c9268994))
* **subnet-manager:** add comprehensive units tests ([59beb07](https://github.com/PlatformNetwork/platform/commit/59beb07939d0be70a7cce684aa39e5bb22bc272e))

## [0.2.1](https://github.com/PlatformNetwork/platform/compare/v0.2.0...v0.2.1) (2026-01-09)


### Features

* add container broker to platform-server ([4772327](https://github.com/PlatformNetwork/platform/commit/47723278a21f2a4b5dfbceb56d1966d67b142c70))
* add tempo fetching from Bittensor chain ([e455e29](https://github.com/PlatformNetwork/platform/commit/e455e29a6266a2a8adf626c086b41c96863a1605))
* add WsContainerClient for WebSocket broker access ([58c8618](https://github.com/PlatformNetwork/platform/commit/58c861855ed2c8114c9e69e06097aba8f7dae0ff))
* auto-generate random BROKER_JWT_SECRET if not provided ([d7be22b](https://github.com/PlatformNetwork/platform/commit/d7be22bfe9d5cf19aaffef496fe5fc3e424fd9dc))
* auto-pull images in broker when creating containers ([f0ef63d](https://github.com/PlatformNetwork/platform/commit/f0ef63df4ac3c0815da932d1002ed8e1501c86f0))
* **broker:** add image build support via Build command ([6da49e2](https://github.com/PlatformNetwork/platform/commit/6da49e2550c12565b2fe347252dcd240f0043145))
* CI publish HTML test coverage report to GitHub Pages ([299d25a](https://github.com/PlatformNetwork/platform/commit/299d25ab7851831e3e33fa5eb0bdb17a8d6a905e))
* CI publish HTML test coverage report to GitHub Pages ([1155c72](https://github.com/PlatformNetwork/platform/commit/1155c721eba7a8820315ae6afad666eb89046558))
* Docker-in-Docker support with named volumes and CopyFrom/CopyTo protocol ([e56a639](https://github.com/PlatformNetwork/platform/commit/e56a639a181ee24f56f6ab4fdfece577593e935c))
* enable debug logging for challenges and broker ([1db95e6](https://github.com/PlatformNetwork/platform/commit/1db95e6c7aeccfa3e21100fdd7011f6fb083cf1d))
* Improve auto-updater coverage and fix CI coverage command ([d9183f2](https://github.com/PlatformNetwork/platform/commit/d9183f2bff80e627f5199dce076d4fd1a1bde8ef))
* Improve auto-updater coverage and fix CI coverage command ([19a6e0d](https://github.com/PlatformNetwork/platform/commit/19a6e0d00aaaf9234066e16f70b6db2f9fbe1ace))
* remove image whitelist by default, allow all public images ([0d30bfa](https://github.com/PlatformNetwork/platform/commit/0d30bfada92015a5e8f2ac75863a2d092fd5c7d3))
* validator metrics reporting (CPU/RAM) with 5s interval and in-memory cache ([f06e67d](https://github.com/PlatformNetwork/platform/commit/f06e67da58de13887591c1c4223ec9a7f71ba5b6))


### Bug Fixes

* add PLATFORM_PUBLIC_URL to validator docker-compose ([c70f755](https://github.com/PlatformNetwork/platform/commit/c70f755408005b00446dfeb934430bf02b51ca09))
* **consensus:** improve test accuracy for zero-stake scenarios ([de9d492](https://github.com/PlatformNetwork/platform/commit/de9d4921e27025f4d20cb483bc0761dd6175eb5b))
* default PLATFORM_PUBLIC_URL to chain.platform.network ([a980e47](https://github.com/PlatformNetwork/platform/commit/a980e47ec2ca46dd0296abb6f7ad4ca8c240e119))
* export VALIDATOR_HOTKEY and VALIDATOR_SECRET_KEY as env vars ([eb3065c](https://github.com/PlatformNetwork/platform/commit/eb3065c73819384d7777a278c3ca240e20eeefb6))
* handle auth message even when JWT validation is disabled ([19e9d1f](https://github.com/PlatformNetwork/platform/commit/19e9d1f6c8e0d202db8e7b4b3c58698981b90abd))
* increase broker JWT TTL to 10 years to prevent ExpiredSignature errors ([94682da](https://github.com/PlatformNetwork/platform/commit/94682daed18fb6c0264edddb6f6caceeb47e54c0))
* increase container limits and add startup cleanup ([9387864](https://github.com/PlatformNetwork/platform/commit/93878641b9dc6031acace439847d85defd95d793))
* integer overflow in calculation ([138fbf9](https://github.com/PlatformNetwork/platform/commit/138fbf908d8ec619406c9f72b409ebd239154ed9))
* integer overflow in calculation ([534c7f9](https://github.com/PlatformNetwork/platform/commit/534c7f995d6ce475fbbb766dc2232b947f77411b))
* pass CHALLENGE_UUID env var for broker authentication ([d88bfe5](https://github.com/PlatformNetwork/platform/commit/d88bfe5e15ccd18f75dd81ed5ee9eb0a79e6b0de))
* remove restrictive cap_drop from container broker, add user field ([372641c](https://github.com/PlatformNetwork/platform/commit/372641ca437daa1ee6b2d32b8b1b86cf3ae6a711))
* reorder validator routes - static paths before :hotkey parameter ([6ffb7ca](https://github.com/PlatformNetwork/platform/commit/6ffb7cadc65f90411b09c9d2e44309f2dc666535))
* update tests to use strict() policy for image whitelist tests ([fb63e63](https://github.com/PlatformNetwork/platform/commit/fb63e63871da1830229f8ade4dfc22ef5459acac))
* use actual hostname as fallback for broker URL ([351b657](https://github.com/PlatformNetwork/platform/commit/351b6571036f0853ae40d522f07079ced43e0c79))
* use challenge name (not UUID) for JWT token generation ([8ecab04](https://github.com/PlatformNetwork/platform/commit/8ecab04badd85532cebd9ef380b90323d97ddfdc))


### Code Refactoring

* **consensus:** address code review feedback ([10a5394](https://github.com/PlatformNetwork/platform/commit/10a53945b5cdf73dd27760ecce0be5fa6aeacaec))


### Documentation

* update README to reflect centralized architecture ([4bc8313](https://github.com/PlatformNetwork/platform/commit/4bc83130134dd5162976cc61e00cb770c2d3b37e))


### Miscellaneous

* remove unused import ([13b55b1](https://github.com/PlatformNetwork/platform/commit/13b55b1c0ee8ed7d6d841dab181c722b7430a25b))
* update doc string ([8245dab](https://github.com/PlatformNetwork/platform/commit/8245dab16cc5ad8c6f610f435036946229424db5))
* version up serial_test ([926598c](https://github.com/PlatformNetwork/platform/commit/926598c04d95d5c6ae80c17363eeafc4cacc0cb2))


### Tests

* **auto-updater:** add helper-backed coverage tests ([f572dd8](https://github.com/PlatformNetwork/platform/commit/f572dd8be5dcf59d62fa467725bf55e6380a4c27))
* broaden platform-bittensor coverage ([add3be8](https://github.com/PlatformNetwork/platform/commit/add3be8ada943e9179a8bb7306afebeb9640a53c))
* **challenge-orchestrator:** add env and helper coverage ([a97b84e](https://github.com/PlatformNetwork/platform/commit/a97b84eaa5f0ae651c5e2c3f5326d4db396f9d08))
* **challenge-orchestrator:** broaden orchestrator, lifecycle, evaluator, and health coverage ([ed67e29](https://github.com/PlatformNetwork/platform/commit/ed67e297c08b8824b2eb9aabd709e99144cc101c))
* **challenge-orchestrator:** expand config/health/evaluator coverage ([3c30e6b](https://github.com/PlatformNetwork/platform/commit/3c30e6b631682af637d7f9bdbf23d4c7f082acaa))
* **challenge-sdk:** Add comprehensive test coverage ([168d03d](https://github.com/PlatformNetwork/platform/commit/168d03d3e9cc967ee503485f8ad33ca13622746d))
* **challenge-sdk:** Add comprehensive test coverage for challenge SDK modules ([6dd0d55](https://github.com/PlatformNetwork/platform/commit/6dd0d5585cdeacda9f026bb66134e1bf4438003a))
* **challenge-sdk:** Add database persistence test across reopens ([b7a7984](https://github.com/PlatformNetwork/platform/commit/b7a7984c35664378a35801b225531b373ea638d5))
* **challenge-sdk:** enhance multi-agent testing in get_latest_results ([ddf89c0](https://github.com/PlatformNetwork/platform/commit/ddf89c0788f19197ba432470efa9ba543880f9fb))
* **consensus:** add comprehensive test coverage for consensus module ([fe39408](https://github.com/PlatformNetwork/platform/commit/fe39408c27b02b2b984b8397a9e6abc20c58958c))
* **consensus:** comprehensive coverage improvements for platform-consensus ([7d96ec8](https://github.com/PlatformNetwork/platform/commit/7d96ec8a6829c51ae91ec0b6b8e07ff1601374c4))
* **distributed-db:** Achieve 97% test coverage across all modules ([982c67c](https://github.com/PlatformNetwork/platform/commit/982c67c4e7faa7c90c8539f4f3185b4544601ef1))
* **distributed-db:** Achieve 97% test coverage across all modules ([1946fd6](https://github.com/PlatformNetwork/platform/commit/1946fd6e2c8c60949f8b4e6a78658e8b7f966db1))
* **distributed-db:** consolidate test helpers and fix code review issues ([d2dade0](https://github.com/PlatformNetwork/platform/commit/d2dade00e83ebf661b340e7c3364ef17463a4e47))
* **epoch:** add comprehensive unit tests achieving 95%+ coverage ([ceb4984](https://github.com/PlatformNetwork/platform/commit/ceb49845f4bfe5eedb1c6555331c48051fdf3359))
* **epoch:** add comprehensive unit tests achieving 95%+ coverage ([4e96e50](https://github.com/PlatformNetwork/platform/commit/4e96e50c2f9c6ab3e8952961b3231ee0f56d6607))
* expand bittensor helper coverage ([e6c4950](https://github.com/PlatformNetwork/platform/commit/e6c49505b169bce1d2c6dc1e48166272ec70b50d))
* **platform-core:** Add comprehensive test coverage for core module ([446af5a](https://github.com/PlatformNetwork/platform/commit/446af5a7cfd01bf42ce1365ad1238a7c3a749a3c))
* **platform-server:** add comprehensive unit tests ([8ebc662](https://github.com/PlatformNetwork/platform/commit/8ebc66281f7bc30ba74f2da9008efe04b143fccd))
* **platform-server:** add comprehensive unit tests ([551a4f4](https://github.com/PlatformNetwork/platform/commit/551a4f4147789caaa0c361d0ec9ea395fc403666))
* **platform-server:** improve test quality and reduce duplication ([5726879](https://github.com/PlatformNetwork/platform/commit/57268791d2fc4a4428c60cc942efd4fad7365e17))
* **rpc:** add comprehensive test suite for platform-rpc module ([7cb4a33](https://github.com/PlatformNetwork/platform/commit/7cb4a33c4e08af0097f00b119605fb57f6932d70))
* **rpc:** add comprehensive test suite for platform-rpc module ([55fc570](https://github.com/PlatformNetwork/platform/commit/55fc570c338885f1c81da349bf6ffb4b8b76dbec))
* **secure-runtime:** achieve comprehensive test coverage for container runtime ([93459a8](https://github.com/PlatformNetwork/platform/commit/93459a8b2c18f00fd8ef1a502141c617c6100df1))

## [0.2.0](https://github.com/PlatformNetwork/platform/compare/v0.1.0...v0.2.0) (2026-01-04)


### ⚠ BREAKING CHANGES

* Production validators now require the broker by default.

### Features

* add --no-bootnode flag and improve bootnode reconnection ([c1045a6](https://github.com/PlatformNetwork/platform/commit/c1045a6cb9b8b7b067d51bf4b9fa4b8639ccbe56))
* add bridge API to proxy submissions to term-challenge ([85c30da](https://github.com/PlatformNetwork/platform/commit/85c30da11153c0d31404802ac0dbd13482423fe3))
* add challenge custom events for WebSocket broadcast ([39b0ccf](https://github.com/PlatformNetwork/platform/commit/39b0ccfd80035759690b2aa507f4a1f7da4a5d70))
* add Custom P2P message type for challenge-specific protocols ([00ebeec](https://github.com/PlatformNetwork/platform/commit/00ebeec7ba46b9b53b1490a624836d5f6cca4b13))
* add docker-compose for bootnode deployment ([d0f3f1e](https://github.com/PlatformNetwork/platform/commit/d0f3f1ea87ebacfd035098df4b02741b00fe6147))
* Add dynamic route discovery via /.well-known/routes ([106681f](https://github.com/PlatformNetwork/platform/commit/106681fb60b88adced6adcf8c7cd2226288e3d78))
* add infinite retry loop (30s) for platform-server connection in validator-node ([d8e28b6](https://github.com/PlatformNetwork/platform/commit/d8e28b651426006fc6f7427b79ccb685018f9d29))
* add keypair to RpcHandler for webhook P2P broadcast ([0f4eb83](https://github.com/PlatformNetwork/platform/commit/0f4eb83ad7e9794d0d0b8e032d7b2f2aa1c83622))
* add P2P message forwarding to challenge containers ([8abeda7](https://github.com/PlatformNetwork/platform/commit/8abeda761ce2c8efe6e831bfc0584bee65d75628))
* add periodic cleanup of stale task containers ([4b26cf4](https://github.com/PlatformNetwork/platform/commit/4b26cf45d85ec6887731212d7f0d160086cca25e))
* add periodic validator sync to challenge containers ([cff55d7](https://github.com/PlatformNetwork/platform/commit/cff55d7aa86e470d20836ee3ccae3e8f648c0bec))
* add persistent data volume for challenge containers ([1b5463b](https://github.com/PlatformNetwork/platform/commit/1b5463b7fa5d377aaf45f188a0d9c2c2233424a4))
* add platform-server (central API) with PostgreSQL, Data API, Claim/Lease ([6bd057d](https://github.com/PlatformNetwork/platform/commit/6bd057dde1c9ba94b6074b4f27ffbe3c4bee8bf6))
* add secure-container-runtime crate with powerful helpers ([38862c4](https://github.com/PlatformNetwork/platform/commit/38862c4c9d986e541e2bd3316c90695890af95a9))
* Add Sentry error monitoring (enabled by default) ([fdd0f65](https://github.com/PlatformNetwork/platform/commit/fdd0f650a056eb2463267fd4c591a024eda3868f))
* add verbose logging option to docker-compose.server.yml ([57e17e6](https://github.com/PlatformNetwork/platform/commit/57e17e6e178435ea5c7e25070e9054ee5996916f))
* add WebSocket event listener for distributed evaluation ([54057fd](https://github.com/PlatformNetwork/platform/commit/54057fde405c3bd575b2ae5637485b0e0af52482))
* add WebSocket transport to secure-container-runtime ([004f60c](https://github.com/PlatformNetwork/platform/commit/004f60c5d57c197adde4a10e3ab175ed2138af5a))
* authenticated WebSocket + validator whitelist endpoint ([f18b74b](https://github.com/PlatformNetwork/platform/commit/f18b74b5a7df94689ea19df0bae2b5a2e5be0993))
* auto-convert hotkeys to UIDs in weight submission ([319f92d](https://github.com/PlatformNetwork/platform/commit/319f92d6b20bc2b2d873ed85a3451b1f59e3e881))
* auto-create Docker network and connect validator ([e8de0ce](https://github.com/PlatformNetwork/platform/commit/e8de0ce876b6410e4b7ed1c68a3bc98ac591f0cb))
* auto-pull docker images and add refresh challenges command ([3b9f9f2](https://github.com/PlatformNetwork/platform/commit/3b9f9f2570f20044ca429bc6f590448ad354a4cf))
* Auto-retry bootstrap peer connection every 30 seconds ([326b8a6](https://github.com/PlatformNetwork/platform/commit/326b8a68d4465f807caa6593414f4892781ba17a))
* auto-start challenge containers from platform-server registry ([4362a3c](https://github.com/PlatformNetwork/platform/commit/4362a3cabf1f2c8f55c8cd2993c8ebfdaa84d89c))
* centralized LLM review with miner API key ([39e72c1](https://github.com/PlatformNetwork/platform/commit/39e72c1d217bbc67f7974d4cae58ebc60c3a282d))
* **challenge-sdk:** add P2P chain storage module ([8bac6e9](https://github.com/PlatformNetwork/platform/commit/8bac6e932f1b6f3a15277b02d1087b32fd8972f7))
* **consensus:** Add stake-based governance with bootstrap period ([7dc4e3f](https://github.com/PlatformNetwork/platform/commit/7dc4e3fc54df942fc89a937d5ccd3c2a2e61e7ff))
* **csudo:** complete CLI refactoring with beautiful interactive mode ([60b115c](https://github.com/PlatformNetwork/platform/commit/60b115ca6c4818a74fac6474b4a504f5fe659097))
* Derive libp2p peer ID from validator keypair for stable identity ([e64b1c6](https://github.com/PlatformNetwork/platform/commit/e64b1c63f27057d6e938b06ff92ec8b3581d5bdd))
* DEVELOPMENT_MODE support for local Docker images ([71a8086](https://github.com/PlatformNetwork/platform/commit/71a80861bea969125584826b9830055147f5a68e))
* emission-based weight distribution with UID 0 burn ([169ac1b](https://github.com/PlatformNetwork/platform/commit/169ac1b72787a6ab4bec524d9ce8dac0cc06e8fc))
* generic bridge API for multi-challenge support ([686c44f](https://github.com/PlatformNetwork/platform/commit/686c44fdebc9d8ab65863204b5313007d8987ea4))
* Hardcode default bootnode address ([9f270af](https://github.com/PlatformNetwork/platform/commit/9f270af793565ee0d275c161a236f64253279559))
* immediate stake validation via identify protocol ([d38b39b](https://github.com/PlatformNetwork/platform/commit/d38b39b42de40323a4b87990fe1848f7eecb68e3))
* implement sr25519 signature verification for agent submissions ([6fb3820](https://github.com/PlatformNetwork/platform/commit/6fb38206b4a6cbb9515f82e03d19d117a2dbc213))
* integrate container broker into validator node ([1a0592f](https://github.com/PlatformNetwork/platform/commit/1a0592f3a81ac70551e4b99f98c5f0b48111ff19))
* Major platform improvements and bittensor-rs Subtensor API integration ([db6cd10](https://github.com/PlatformNetwork/platform/commit/db6cd107725ad0b85a236d77c27db1080da10f8c))
* make secure broker the default container backend ([e50e1df](https://github.com/PlatformNetwork/platform/commit/e50e1df3b9cfeedf27b97fd9277c54bf3011d99d))
* **orchestrator:** add ContainerBackend abstraction for secure mode ([5e729c9](https://github.com/PlatformNetwork/platform/commit/5e729c9baa680d7d5e5d649aa682b4d301b8f793))
* **orchestrator:** use Docker named volume for persistent challenge data ([c1db0ed](https://github.com/PlatformNetwork/platform/commit/c1db0edd3656329789e756e5b505b846965403ed))
* pass BROADCAST_SECRET to challenge containers ([a5d7505](https://github.com/PlatformNetwork/platform/commit/a5d7505b0be9e2241d7bd67c9dd8de7e69eb7eb2))
* pass VERBOSE env var to challenge containers for debug logging ([2c6cb55](https://github.com/PlatformNetwork/platform/commit/2c6cb550f32d548d1b7c2069dac79e607cb0b7d3))
* **platform-server:** dynamic challenge orchestration ([55686f0](https://github.com/PlatformNetwork/platform/commit/55686f0e1f3af5edf0e2835955c582a6fbec5206))
* real sr25519 signatures + binary evaluation in Docker ([353aff3](https://github.com/PlatformNetwork/platform/commit/353aff3b8180aca7acaf66631950efd7d46814e3))
* **sdk:** add P2P messages for real-time progress sharing ([b524581](https://github.com/PlatformNetwork/platform/commit/b524581a779e69827a6e8dbe90d5e392cd30fec9))
* **security:** add stake-weighted PBFT, merkle sync verification, and hotkey rate limiting ([27353a0](https://github.com/PlatformNetwork/platform/commit/27353a08c773b8cca6b83e16df4ca2c57b6db651))
* **security:** implement authenticated P2P communication with challenge containers ([5e48ea2](https://github.com/PlatformNetwork/platform/commit/5e48ea2ad919daaab8798a6d73c8e5137070786f))
* **sentry:** improve error tracking with hotkey context ([1039741](https://github.com/PlatformNetwork/platform/commit/103974185243bd78c07c87465827cc44b885fe59))
* **server:** add submissions and evaluations API routes ([88e9d4a](https://github.com/PlatformNetwork/platform/commit/88e9d4a0e7d1856fc90dd7300d65808bb6053f46))
* sr25519 crypto + Docker image whitelist security ([b723820](https://github.com/PlatformNetwork/platform/commit/b7238203f491179033e2e518ee57e273b0de6eee))
* **state:** add versioned state serialization with automatic migration ([1fe787b](https://github.com/PlatformNetwork/platform/commit/1fe787b5328507f36e12d1f98e4e1d79ce829d6d))
* **storage:** add anti-corruption protections for RocksDB ([f45d41c](https://github.com/PlatformNetwork/platform/commit/f45d41c7c9ce73be8db18d7533005ece9b7d1913))
* sync metagraph at startup for validator stake lookup ([c155fe4](https://github.com/PlatformNetwork/platform/commit/c155fe49a04237aad1a7f4c76b202a84149aafc4))
* unified platform binary with server/validator modes ([5036425](https://github.com/PlatformNetwork/platform/commit/5036425e4336105d61fb249fba9a8c42053db24f))
* validate miner_hotkey is SS58 format in /submit endpoint ([972161d](https://github.com/PlatformNetwork/platform/commit/972161d2a5cc26715a82e7d8c46fe722894abe56))
* **validator-node:** authenticate WebSocket connection with signature ([5934e7d](https://github.com/PlatformNetwork/platform/commit/5934e7d1bb1bcc5b5197dbcd217b0ada3d95409e))
* **validator-node:** handle ChallengeStopped WebSocket event ([f3d52d0](https://github.com/PlatformNetwork/platform/commit/f3d52d0d10d9b79d8762bdc6f76384c3151e2e37))
* **validator:** integrate with platform-server for centralized weights ([1c5b77a](https://github.com/PlatformNetwork/platform/commit/1c5b77ad6fb677355acd3d6f58e5b9a865effdcb))
* **validator:** sync validators to challenge containers on startup ([94f72c5](https://github.com/PlatformNetwork/platform/commit/94f72c5124ab8d598b2571964336b2522bd34a49))
* **weights:** Add CRv4 timelock encryption support ([475126d](https://github.com/PlatformNetwork/platform/commit/475126d9113f53316da35a2b7eadf5f007412724))
* **weights:** add persistence for commit-reveal state ([53dd4dd](https://github.com/PlatformNetwork/platform/commit/53dd4dd482867049e13ec2c1fff0bf4fb836d2a9))


### Bug Fixes

* add 30s delay before crash exit to allow Watchtower updates ([1635a16](https://github.com/PlatformNetwork/platform/commit/1635a168a5b0350fc6e35c59a1bb11301b8a8f2d))
* add bootnode retry timer to validator event loop ([007b920](https://github.com/PlatformNetwork/platform/commit/007b9205d7cd513b7e293f6be7a908c88d3950c1))
* add bridge routes to unified platform binary ([ce04921](https://github.com/PlatformNetwork/platform/commit/ce0492162aead5b1ed5b8831117e3cbccc8c92d3))
* add cache bind mount for Docker-in-Docker path mapping ([107b064](https://github.com/PlatformNetwork/platform/commit/107b064abadc22eef1da572032914cdf866f3577))
* add challenge to ChainState when receiving P2P Proposal ([0ab4c2e](https://github.com/PlatformNetwork/platform/commit/0ab4c2e525b0abfb60e35c3ce170a0e0c5aba3bf))
* add DNS servers to docker-compose.server.yml ([ef47913](https://github.com/PlatformNetwork/platform/commit/ef479131e6bdfbf8dc4292acd293a02c60b47c22))
* add eval logs bind mount for Docker-in-Docker ([1b29e3d](https://github.com/PlatformNetwork/platform/commit/1b29e3d012a2617ff34ee1dce78805dc9434942e))
* add events/broadcast route to platform bin + secure with BROADCAST_SECRET ([ebb468f](https://github.com/PlatformNetwork/platform/commit/ebb468f1873c337f621ca89b6c21b1526cdadc0f))
* add logging for P2P outbox message processing ([aef5359](https://github.com/PlatformNetwork/platform/commit/aef535966e99ddb85b439b17a57dd83b969c8f3b))
* Add peer ID to bootstrap peer address ([2be994d](https://github.com/PlatformNetwork/platform/commit/2be994daae8662ea563ce2e8f0bbc3fd2cc734fe))
* add whitelist route and metagraph sync to platform bin server mode ([c09cd79](https://github.com/PlatformNetwork/platform/commit/c09cd799c2252e91a803fde760ad7b0ae0dd38cc))
* allow all ghcr.io/platformnetwork/ images in agent runner whitelist ([9ed64b3](https://github.com/PlatformNetwork/platform/commit/9ed64b309e1c504ec0dc6a77998f7b640bed75a8))
* allow custom DATABASE_URL (Supabase, etc.) ([f543705](https://github.com/PlatformNetwork/platform/commit/f543705981c0c39851719efc70b675dd1477e4e0))
* auto-detect validator network for challenge containers ([5bf156f](https://github.com/PlatformNetwork/platform/commit/5bf156f32addaaf133f6f6253a163c3efeda6193))
* auto-recover from corrupted distributed-db and state ([332f75d](https://github.com/PlatformNetwork/platform/commit/332f75d2977ccdfb0e4ef58e41698129c69cc7b3))
* **bittensor:** update to bittensor-rs f79759e with DRAND fix ([11cfe4a](https://github.com/PlatformNetwork/platform/commit/11cfe4a1831c4c30ce82126c3657f31f2205bca3))
* broadcast ChallengeStarted event to validators ([9047616](https://github.com/PlatformNetwork/platform/commit/9047616cd000b48b4fa764eefaa8e2f7c789bbb6))
* broadcast ChallengeStopped event to validators in platform bin server ([b99e43d](https://github.com/PlatformNetwork/platform/commit/b99e43d5c5217de5a5e3c229b6f3c90032847fda))
* **challenge-sdk:** fix consensus test math ([8aa071f](https://github.com/PlatformNetwork/platform/commit/8aa071f4219028972cc7140e3157d76e901b8036))
* change stale container cleanup to 2 hours ([8f4592d](https://github.com/PlatformNetwork/platform/commit/8f4592dda88c69c9b4d08f1c9521e974ed6f9bf5))
* **ci:** move -E filter before -- in cargo llvm-cov nextest ([c91e830](https://github.com/PlatformNetwork/platform/commit/c91e8309c2efa47a44df9f2fed0c6ab48f57c902))
* **ci:** properly use cargo cache across jobs ([14bc231](https://github.com/PlatformNetwork/platform/commit/14bc2315b2703a1727579309d602bb46a6de3d2b))
* **ci:** separate cache keys for release and debug builds ([a2149e4](https://github.com/PlatformNetwork/platform/commit/a2149e4ff1c7cc39384ee58655060dcf5cbf4c09))
* clippy warnings and add mandatory CI hooks ([9a9c395](https://github.com/PlatformNetwork/platform/commit/9a9c395da843e63d27f3aec6cd25367cede8b207))
* **clippy:** resolve all clippy warnings for CI ([e8829bd](https://github.com/PlatformNetwork/platform/commit/e8829bd87dc830d6688e9bf1dacd68a185ffb114))
* connect validator container to platform-network on startup ([41d9d8b](https://github.com/PlatformNetwork/platform/commit/41d9d8b2784743ce7a4ae2b5ed45d05fd01d6c20))
* **consensus:** correct test expectations for 33% default threshold ([d621eb8](https://github.com/PlatformNetwork/platform/commit/d621eb8cd150745356997276604b46a228e29450))
* **consensus:** improve P2P mesh stability and reduce quorum threshold ([34f65a0](https://github.com/PlatformNetwork/platform/commit/34f65a0bfd502f3807fc208bf52986311b8319eb))
* correct netuid_index calculation and salt serialization ([c2ba34b](https://github.com/PlatformNetwork/platform/commit/c2ba34bee74d2a0be2120e44b95c2bff1fa536d0))
* correct sled corruption recovery to remove actual db files ([00df049](https://github.com/PlatformNetwork/platform/commit/00df049bb7d86e06b7f57a8d6275ce87317d25e6))
* **db:** strip trailing database name from URL ([19d4298](https://github.com/PlatformNetwork/platform/commit/19d4298f16f7737f41478e13f74f61c733a48bf0))
* Derive peer ID from hotkey (public key) not seed ([39f578d](https://github.com/PlatformNetwork/platform/commit/39f578d5810b4365e99ec313a13f1ee9cb2b8a9b))
* **docker:** add clang/libclang-dev for zstd-sys bindgen ([650d5f7](https://github.com/PlatformNetwork/platform/commit/650d5f71601248cf4f87251e4400eb4836c88434))
* **docker:** default to validator-node for backward compatibility ([4d6f210](https://github.com/PlatformNetwork/platform/commit/4d6f210e492c5c688d78bb3f7107c338637d1e6e))
* **docker:** use ubuntu:24.04 for glibc 2.39 compatibility ([af00fac](https://github.com/PlatformNetwork/platform/commit/af00facebfe1193671930615bb82c59245a2e6aa))
* don't cleanup challenge containers with different suffixes ([f433704](https://github.com/PlatformNetwork/platform/commit/f433704f62ef1b878e35eee7b397ae1272b142af))
* force exact network name 'platform-network' ([27071de](https://github.com/PlatformNetwork/platform/commit/27071de11cf53231348054df216001a64a3895d4))
* **gossipsub:** resolve empty mesh issue by removing add_explicit_peer calls ([375ce2e](https://github.com/PlatformNetwork/platform/commit/375ce2eb3b2830a1f7d36f01ee5b0e47979fdebf))
* implement targeted P2P send (broadcasts to all) ([121d5f0](https://github.com/PlatformNetwork/platform/commit/121d5f07c967f78e0c81dfb92809925e70311c9e))
* include challenge_configs in chain_getState RPC response ([00690e7](https://github.com/PlatformNetwork/platform/commit/00690e76917baf1f0c507dd14513dba527cb63a7))
* migrate remaining ed25519 to sr25519 + add mandatory CI hooks ([65bd1e8](https://github.com/PlatformNetwork/platform/commit/65bd1e866b0e0c9357ad819070bd170728d3802e))
* **network:** add mesh repair mechanism for gossipsub ([bad9b34](https://github.com/PlatformNetwork/platform/commit/bad9b349cb385943880ec8492ade05b6c9701b9e))
* **network:** add mesh repair mechanism for gossipsub ([b171ff4](https://github.com/PlatformNetwork/platform/commit/b171ff4b0849118ffff94e190649d189a1a42178))
* **network:** handle gossipsub Subscribed event for proper mesh membership ([f8efbd6](https://github.com/PlatformNetwork/platform/commit/f8efbd6fa66469cce6e580eb2d2f26a526901971))
* **network:** improve gossipsub mesh stability for bootnodes ([381ae26](https://github.com/PlatformNetwork/platform/commit/381ae26b1d45a6a37f901e839fe7c5159f98004b))
* **orchestrator:** pass PORT=8080 env var to challenge containers ([ab4782e](https://github.com/PlatformNetwork/platform/commit/ab4782e2efbd912974971cff40401ff36d05da39))
* Pass bootstrap-peer argument directly in docker-compose ([d3ac865](https://github.com/PlatformNetwork/platform/commit/d3ac865e198aeb7bd589082c9b43a9c8152da7e4))
* pass real challenge config values in ChallengeStarted event ([06dc544](https://github.com/PlatformNetwork/platform/commit/06dc544eecfecd80d2e2287c9bee8491871cc136))
* pass VALIDATOR_SECRET_KEY to challenge containers ([44e1dce](https://github.com/PlatformNetwork/platform/commit/44e1dce594eb6fdaab96096f84edb20e608e5cc8))
* populate registered_hotkeys from metagraph sync ([aff29f3](https://github.com/PlatformNetwork/platform/commit/aff29f3a2be60ee8deab7425268f1a81e8ad81e5))
* remove obsolete version from docker-compose.bootnode.yml ([3ba56f2](https://github.com/PlatformNetwork/platform/commit/3ba56f26af552bd5543919d1c0d4d930704b188f))
* resolve CI lint and clippy warnings ([c470b4c](https://github.com/PlatformNetwork/platform/commit/c470b4c1b8d9cf263a0ed066ffa8b5d2ea4444a1))
* reveal mechanism weights when internal epoch manager detects reveal phase ([3291318](https://github.com/PlatformNetwork/platform/commit/3291318451b35b949485caf7efcbbbd96202bd9f))
* skip stake validation in no-bittensor mode for PeerIdentified event ([f6ff0a2](https://github.com/PlatformNetwork/platform/commit/f6ff0a28f31084913d27d9176690f4070e02048c))
* trigger commit/reveal on Subtensor timing windows in tests ([fa85fea](https://github.com/PlatformNetwork/platform/commit/fa85fea5c9df466907af165630077602b0b4fbfa))
* Update bittensor-rs to 3fc7ab5 and export sync_metagraph ([c328831](https://github.com/PlatformNetwork/platform/commit/c328831e3b091ecde107a140d8d1c562ab83d50f))
* Update bittensor-rs to a1a4558 and fix clippy warnings ([b9bc10c](https://github.com/PlatformNetwork/platform/commit/b9bc10c7d0d99480dcc5c286eb7a477880ca4156))
* Update bittensor-rs to db10a19 - fix commit-reveal detection ([80f10e5](https://github.com/PlatformNetwork/platform/commit/80f10e53ac7a78754a2e933d5e9123b8dd96b666))
* update challenge endpoints for P2P and dev mode containers ([9ee7c7a](https://github.com/PlatformNetwork/platform/commit/9ee7c7a80444d370273d3f0f3eaf44bdaef07ddd))
* update coverage badge generation to use peaceiris/actions-gh-pages ([347daba](https://github.com/PlatformNetwork/platform/commit/347daba15461fb59306b244e1a6296b7c2eed2d5))
* update release-please config for workspace ([c6ff25c](https://github.com/PlatformNetwork/platform/commit/c6ff25c57f25fd3add9bf70ae000d1c80e4deb01))
* use challenge name (not UUID) for CHALLENGE_ID env var ([b5bd205](https://github.com/PlatformNetwork/platform/commit/b5bd205a611242222428854bede60ce26264b157))
* use container ID for challenge container naming suffix ([39e4724](https://github.com/PlatformNetwork/platform/commit/39e4724ff13ca2ae37fdf9c4f39fa61b341c89fb))
* use container name for challenge endpoint instead of 127.0.0.1 ([f04d4fa](https://github.com/PlatformNetwork/platform/commit/f04d4fa86a0a603bc6834907b7c1642facfdf96b))
* use correct salt type for reveal_weights ([41e0a05](https://github.com/PlatformNetwork/platform/commit/41e0a05fab3cf95e82e07b1d4fb68ce02f28669a))
* use effective stake (alpha + root) for validator validation ([cb30a93](https://github.com/PlatformNetwork/platform/commit/cb30a935d547375634f36ba25396a901552550b2))
* use orchestrator endpoint instead of hardcoded URL for challenge containers ([bd4c349](https://github.com/PlatformNetwork/platform/commit/bd4c349c4cdc402df1e9b1108b111cb371d66a4f))
* use PLATFORM_PUBLIC_URL for validator challenge containers ([7ce3b24](https://github.com/PlatformNetwork/platform/commit/7ce3b24b890a1820be2c9aff6e87db56c72ff24b))
* Use proper Substrate SR25519 derivation for peer ID ([95321e5](https://github.com/PlatformNetwork/platform/commit/95321e52ce4aeccdd828a243ec7408ab00b0c3c7))
* use real container endpoints for P2P outbox polling ([ae9250d](https://github.com/PlatformNetwork/platform/commit/ae9250df751e745ffb7b3a632eaeadf91ce72eeb))
* use simple release type for workspace ([60c3078](https://github.com/PlatformNetwork/platform/commit/60c3078cef809d2ea07e1b136e617917836dcd34))
* use simple release type with manifest config ([ba79252](https://github.com/PlatformNetwork/platform/commit/ba79252ff3b4c847376215e94a17666cdba521f8))
* use stake_weight for validator stake validation ([be15cdc](https://github.com/PlatformNetwork/platform/commit/be15cdc769547d030410afab71de21c542927304))
* use stored endpoints for challenge container URLs ([2adda1a](https://github.com/PlatformNetwork/platform/commit/2adda1a3d308c614d6aa8043b90e2955a88fe77d))
* use total_stake from runtime API for validator stake validation ([dcb389c](https://github.com/PlatformNetwork/platform/commit/dcb389c020a90441d38c603451c1217bd1a59b50))
* use u16 for NetUidStorageIndex in hash computation ([c8a392e](https://github.com/PlatformNetwork/platform/commit/c8a392eb8ad15b8d80e674d6f0a93741e23d1ab3))
* use u16 salt directly for reveal_mechanism_weights ([72f3806](https://github.com/PlatformNetwork/platform/commit/72f380625e9931c37670d9dfaf8f807f81b1dd51))
* validator uses Subtensor.set_mechanism_weights() for CRv4 ([eda164e](https://github.com/PlatformNetwork/platform/commit/eda164e21eac7a1ae51294447937882c7ab9724c))
* validator uses Subtensor.set_mechanism_weights() for CRv4 ([3e0b1e5](https://github.com/PlatformNetwork/platform/commit/3e0b1e5e1fc09974aa7df80ef6a3effc0c75cf7f))
* **validator:** change default RPC port from 8545 to 8080 ([c610dde](https://github.com/PlatformNetwork/platform/commit/c610dde4001f874520b1695ade98e1602be57f3f))
* **validator:** check sudo/owner FIRST before any stake validation ([81524af](https://github.com/PlatformNetwork/platform/commit/81524af60381ebf15849de08f5761535f954a85b))
* **validator:** use correct container name with validator suffix for challenge endpoints ([c6137eb](https://github.com/PlatformNetwork/platform/commit/c6137ebc24c1f97e9853bcd3e99fb732a431042f))
* warn when validator cannot join platform network ([3c1bdde](https://github.com/PlatformNetwork/platform/commit/3c1bdde332146b7ede99cdbd0240d891ba117b9c))


### Performance Improvements

* **ci:** optimize caching for Rust builds and Docker images ([52fb82b](https://github.com/PlatformNetwork/platform/commit/52fb82bd74e064755d851ad4c7d76a63032226c2))


### Code Refactoring

* clean dead code in evaluator, increase proxy timeout ([cbffb81](https://github.com/PlatformNetwork/platform/commit/cbffb8107f2deb4f1757a67c0e1e569e0f11b63e))
* event-driven commit/reveal from Bittensor timing ([4d3f0ff](https://github.com/PlatformNetwork/platform/commit/4d3f0fff314163a2cf1150b81c8ce644c6ab22a9))
* migrate from ed25519 to sr25519 for Substrate/Bittensor compatibility ([dbf722e](https://github.com/PlatformNetwork/platform/commit/dbf722e4906063b8ef0f9a4a39cadc52faeca89e))
* remove anti-cheat weight manipulation for pure pass-through ([63ed510](https://github.com/PlatformNetwork/platform/commit/63ed5101e1f262a9b919f50642e4856603e329a6))
* remove P2P networking, centralized architecture only ([66477bd](https://github.com/PlatformNetwork/platform/commit/66477bd62eb3163f27487bcd944bfa105647bf58))
* remove P2P networking, centralized architecture only ([9ef71a6](https://github.com/PlatformNetwork/platform/commit/9ef71a66255882bac864455ac792b6d54c460425))
* Remove redundant weights_v2.rs, use bittensor_rs::Subtensor directly ([5317b8d](https://github.com/PlatformNetwork/platform/commit/5317b8d518bc76b4fd8c3bec10f2b85e218d448d))
* remove term-challenge specific code from validator-node ([a4713e9](https://github.com/PlatformNetwork/platform/commit/a4713e96986ad36b278657fb0855bd157f5439d9))
* Replace WeightSubmitter with bittensor_rs::Subtensor ([1b55113](https://github.com/PlatformNetwork/platform/commit/1b5511344bf20d04424081a934b42ab5c5e8541b))
* simplify WeightAssignment to hotkey + weight only ([56ccd21](https://github.com/PlatformNetwork/platform/commit/56ccd2118e107a5fe15796063116bb3dcfdf6d01))


### Documentation

* add badges and repobeats analytics to README ([5c2a3bb](https://github.com/PlatformNetwork/platform/commit/5c2a3bb0b6f51d925ebce2803ea0ede845341385))
* add banner image to README ([2a89445](https://github.com/PlatformNetwork/platform/commit/2a89445086881d644737473ad4a22fc344f60972))
* add hardware requirements section (4 vCPU, 16GB RAM minimum) ([e1ffadb](https://github.com/PlatformNetwork/platform/commit/e1ffadbc7cef3f868029c36bd5915cc5a2cab53a))
* add network requirements (port 9000/tcp) ([a0fee78](https://github.com/PlatformNetwork/platform/commit/a0fee78d65581be7a4439af717694e6d098735f8))
* comprehensive README with incentive mechanism and validator guide ([b85812f](https://github.com/PlatformNetwork/platform/commit/b85812f57ed668ac872cc26e9f7f1170bdd08010))
* improve README formatting and clarify aggregation method ([31ab5bc](https://github.com/PlatformNetwork/platform/commit/31ab5bc7a0a7cb5ee81a64cceac0b0341006c8d4))
* improve README formatting and clarify aggregation method ([ccc90f0](https://github.com/PlatformNetwork/platform/commit/ccc90f0ac319bc306522d05ae9f3f5c6a613b6fc))
* move description before badges ([4c6c3fc](https://github.com/PlatformNetwork/platform/commit/4c6c3fc958c83af903d270c032327512ab24ea01))
* move repobeats after badges, update rust to 1.90+ ([491f255](https://github.com/PlatformNetwork/platform/commit/491f2550043817853e0425a12a916863bc5ab378))
* remove Validator Utility Maximization section from README ([fef431a](https://github.com/PlatformNetwork/platform/commit/fef431a1f1a3382b9eef9253c66896d7169bf31b))
* simplify README - remove weight capping, commit-reveal, and agent terminology ([8897501](https://github.com/PlatformNetwork/platform/commit/88975016a62b03c4636003d40e6b09c703a9eeee))
* update storage requirements (250GB min, 500GB recommended) ([43b6805](https://github.com/PlatformNetwork/platform/commit/43b6805b6ec74afce2ae99517193874f6d335c14))
* **validator:** simplify guide - no GPU, no third-party APIs needed ([79a1e97](https://github.com/PlatformNetwork/platform/commit/79a1e97b2933db10fa1deaa24091a9cb1a1f1481))


### Miscellaneous

* add git hooks for format and CI checks ([b42dfc8](https://github.com/PlatformNetwork/platform/commit/b42dfc809efdd21fc04017210bc2a42c574f7557))
* add MIT license file ([7fd5106](https://github.com/PlatformNetwork/platform/commit/7fd510649557a35dc63fb81aac9ece92f306c02d))
* update bittensor-rs to 453ce56 (proper SCALE decoding) ([56f99f9](https://github.com/PlatformNetwork/platform/commit/56f99f96fc1f6c25617ab329b3ee97b822fcf5b4))
* update Rust to 1.92 (latest stable) ([ca22249](https://github.com/PlatformNetwork/platform/commit/ca222496b24be834c94ecb25fd083840fa2e5eea))


### CI/CD

* add automatic versioning with release-please ([80070f7](https://github.com/PlatformNetwork/platform/commit/80070f76d2a86eaee9169a3a7a4f3c5f91da66af))
* add code coverage badge with cargo-llvm-cov ([7b22a73](https://github.com/PlatformNetwork/platform/commit/7b22a732383138574c41ee9e81ecd28d88e1e852))
* docker push only after build/clippy/test pass ([616dfac](https://github.com/PlatformNetwork/platform/commit/616dfaca0bc4f733dbb80f7bff1836ffed536a20))
* optimize CI with nextest, better caching, and parallel jobs ([6155af8](https://github.com/PlatformNetwork/platform/commit/6155af8845e4c0ccb6c945e8aff53909c591f8f5))
* optimize with fully parallel jobs ([360c14c](https://github.com/PlatformNetwork/platform/commit/360c14c8496a419c1f0b616bbe982c9b2d0fa086))
* optimize workflow with disk cleanup and rust-cache ([4bd7164](https://github.com/PlatformNetwork/platform/commit/4bd71647bd096e23eccc7bc99799e773894d7635))
* restore parallel jobs with proper cache dependencies ([11d25b0](https://github.com/PlatformNetwork/platform/commit/11d25b0b2b2c9e4332fc17ef3151a4dc0a2c8c89))
* round coverage to whole number ([35bc17e](https://github.com/PlatformNetwork/platform/commit/35bc17e2d31892da3fd9308a63fafc14ae0e16b6))
* use platform-runner label ([7080d56](https://github.com/PlatformNetwork/platform/commit/7080d56e6550c5de4c1c32a643f429e513b31699))
* use self-hosted runners ([63c1e86](https://github.com/PlatformNetwork/platform/commit/63c1e86d23c1596bff751801a34a8fad3dd9d71f))
