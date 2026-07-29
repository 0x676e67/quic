# quic

**quic** is a pure-Rust, async [quinn](https://github.com/quinn-rs/quinn) fork for select [QUIC][quic] extensions, including ones unlikely to land upstream.

[![CI](https://github.com/0x676e67/quic/actions/workflows/rust.yml/badge.svg)](https://github.com/0x676e67/quic/actions/workflows/rust.yml)
[![GitHub License](https://img.shields.io/github/license/0x676e67/quic)](https://github.com/0x676e67/quic/blob/main/LICENSE)
[![Crates.io](https://img.shields.io/crates/v/quic.svg)](https://crates.io/crates/quic)

More information about this crate can be found in the [crate documentation](https://docs.rs/quic).

## Features

- Client and server support
- Ordered and unordered streams, plus unreliable datagrams
- Pluggable cryptography backed by [rustls][rustls] and [*ring*][ring]
- Async API for Linux, macOS and Windows
- Minimum supported Rust version of 1.85.0

## Overview

- `quic`: High-level async API; see the [examples] for usage.
- `quic-proto`: [Sans-I/O][sans-io] QUIC state machine for custom event loops.
- `bench`, `perf` and `fuzz`: Benchmarking, performance testing and fuzzing.

## Example

```sh
$ cargo run --example server ./
$ cargo run --example client https://localhost:4433/Cargo.toml
```

This launches an HTTP 0.9 server on the loopback address serving the current
working directory, with the client fetching `./Cargo.toml`. By default, the
server generates a self-signed certificate and stores it to disk, where the
client will automatically find and trust it.

## License

Licensed under either of Apache License, Version 2.0 ([LICENSE](LICENSE) or
http://www.apache.org/licenses/LICENSE-2.0).

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the [Apache-2.0](LICENSE) license,
shall be licensed as above, without any additional terms or conditions.

[quic]: https://quicwg.github.io/
[issues]: https://github.com/0x676e67/quic/issues
[rustls]: https://github.com/ctz/rustls
[ring]: https://github.com/briansmith/ring
[talk]: https://paris.rustfest.eu/sessions/a-quic-future-in-rust
[animation]: https://dirkjan.ochtman.nl/files/head-of-line-blocking.html
[youtube]: https://www.youtube.com/watch?v=EHgyY5DNdvI
[letsencrypt]: https://letsencrypt.org/
[rcgen]: https://crates.io/crates/rcgen
[examples]: https://github.com/0x676e67/quic/tree/main/quic/examples
[sans-io]: https://sans-io.readthedocs.io/how-to-sans-io.html
[insecure]: https://github.com/0x676e67/quic/blob/main/quic/examples/insecure_connection.rs
