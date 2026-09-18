# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.12.2](https://github.com/0x676e67/quic/compare/quic-proto-v0.12.1...quic-proto-v0.12.2) - 2026-09-18

### Other

- release v0.12.1 ([#39](https://github.com/0x676e67/quic/pull/39))

## [0.12.1](https://github.com/0x676e67/quic/compare/quic-proto-v0.11.16...quic-proto-v0.12.1) - 2026-09-18

### Fixed

- *(ci)* repair upstream sync failures
- *(proto)* avoid stale server RTT removals ([#31](https://github.com/0x676e67/quic/pull/31))
- *(proto)* finish server RTT store rename

### Other

- v0.12.1
- address clippy lints raised under edition 2024
- restore edition 2024 lost in the upstream merge
- pass initial RTT in the pacer reset test
- Merge remote-tracking branch 'upstream/main' into sync
- Merge upstream quinn main
- Merge branch 'feat' into task4/initial-rtt-final-review
- *(proto)* internalize server RTT memory store
- *(proto)* clarify server RTT cache behavior
- *(proto)* consolidate RTT handling
- *(proto)* split server RTT storage module
- *(proto)* make server RTT storage configurable
- Merge branch 'main' into feat
- fmt ([#17](https://github.com/0x676e67/quic/pull/17))
- make fuzz targets compatible with workspace checks ([#16](https://github.com/0x676e67/quic/pull/16))
- standardize on Apache-2.0 license
- Sync quinn upstream ([#14](https://github.com/0x676e67/quic/pull/14))
- rename project to `quic` ([#13](https://github.com/0x676e67/quic/pull/13))
- Initialize `quic-rs` repo and migrate codebase
