# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to 
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]


## [1.1.14] - 2026-08-10

### Fixed

- Create the temporary keystore file in `BasicKeyStore.storeTemp()` with owner-only permissions on POSIX filesystems. ([#152](https://github.com/heroku/env-keystore/pull/152))
- Always delete the temporary keystore file in `BasicKeyStore.asFile()`, even when the consumer throws an exception. ([#152](https://github.com/heroku/env-keystore/pull/152))

### Deprecated

- Deprecate all disk-IO methods on `EnvKeyStore` and `BasicKeyStore` (`store(OutputStream)`, `store(Path)`, `storeTemp()`, `asFile(Consumer<File>)`). Writing keystore material to disk is out of scope for this library and will be removed in a subsequent release. Use `toBytes()` or `toInputStream()` and handle I/O in the caller. ([#152](https://github.com/heroku/env-keystore/pull/152))

## [1.1.13] - 2026-04-20


## [1.1.12] - 2025-07-03

- Update dependencies.

## [1.1.11] - 2024-11-11

- Update dependencies.

## [1.1.10] - 2024-09-27

### Fixed

- Migrate from bcpkix-jdk15on to bcpkix-jdk18on, fixing security issues with bouncycastle. ([#91](https://github.com/heroku/env-keystore/pull/91))

## [1.1.9] - 2024-07-17

- Update dependencies.

## [1.1.8] - 2023-10-09

### Changed

- Update release process. ([#61](https://github.com/heroku/env-keystore/pull/61))

[unreleased]: https://github.com/heroku/env-keystore/compare/v1.1.14...HEAD
[1.1.14]: https://github.com/heroku/env-keystore/compare/v1.1.13...v1.1.14
[1.1.13]: https://github.com/heroku/env-keystore/compare/v1.1.12...v1.1.13
[1.1.12]: https://github.com/heroku/env-keystore/compare/v1.1.11...v1.1.12
[1.1.11]: https://github.com/heroku/env-keystore/compare/v1.1.10...v1.1.11
[1.1.10]: https://github.com/heroku/env-keystore/compare/v1.1.9...v1.1.10
[1.1.9]: https://github.com/heroku/env-keystore/compare/v1.1.8...v1.1.9
[1.1.8]: https://github.com/heroku/env-keystore/compare/v1.1.7...v1.1.8
