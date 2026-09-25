# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
## [0.12.3](https://github.com/0x676e67/quic/compare/v0.12.2..v0.12.3) - 2026-09-25

## [0.12.2](https://github.com/0x676e67/quic/compare/v0.12.1..v0.12.2) - 2026-09-20

### Bug Fixes

- *(proto)* Report terminal stream errors before flow-control blocking ([#50](https://github.com/0x676e67/quic/issues/50)) - ([ba712e0](https://github.com/0x676e67/quic/commit/ba712e07096361fbf83ad9382e169c66d68f8d1e))
- *(release)* Manage versions in the workspace and publish one release ([#46](https://github.com/0x676e67/quic/issues/46)) - ([e142467](https://github.com/0x676e67/quic/commit/e14246789e5819958d973eeca20382516e6087b0))

### Miscellaneous Tasks

- Release v0.12.1 ([#39](https://github.com/0x676e67/quic/issues/39)) - ([766238f](https://github.com/0x676e67/quic/commit/766238fa5c743b89e6687f20149a9d1b810f6241))


## [0.12.1] - 2026-09-18

The first entry kept in this file, which replaces the per-crate changelogs and
covers both `quic` and `quic-proto`. It reaches back to the commit that created
this repository; the history inherited from quinn before that point is not
repeated here.

### Fixed

- *(ci)* repair upstream sync failures
- *(proto)* avoid stale server RTT removals ([#31](https://github.com/0x676e67/quic/pull/31))
- *(proto)* finish server RTT store rename

### Other

- address clippy lints raised under edition 2024
- restore edition 2024 lost in the upstream merge
- pass initial RTT in the pacer reset test
- *(proto)* internalize server RTT memory store
- *(proto)* clarify server RTT cache behavior
- *(proto)* consolidate RTT handling
- *(proto)* split server RTT storage module
- *(proto)* make server RTT storage configurable
- Merge upstream quinn main
- Sync quinn upstream ([#14](https://github.com/0x676e67/quic/pull/14))
- fmt ([#17](https://github.com/0x676e67/quic/pull/17))
- make fuzz targets compatible with workspace checks ([#16](https://github.com/0x676e67/quic/pull/16))
- standardize on Apache-2.0 license
- Revise README for clarity and additional resources
- Add example section to README
- Add CI and license badges to README
- Update README
- rename project to `quic` ([#13](https://github.com/0x676e67/quic/pull/13))
- Initialize `quic-rs` repo and migrate codebase
