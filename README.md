# quic

[![CI](https://github.com/0x676e67/quic/actions/workflows/rust.yml/badge.svg)](https://github.com/0x676e67/quic/actions/workflows/rust.yml)
[![GitHub License](https://img.shields.io/github/license/0x676e67/quic)](https://github.com/0x676e67/quic/blob/main/LICENSE)
[![Crates.io](https://img.shields.io/crates/v/quic.svg)](https://crates.io/crates/quic)

A [Sans-I/O][sans-io] aware, QUIC implementation for Rust.

## Features

- QUIC version 1 per [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html), secured with TLS per [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html).
- Loss detection and congestion control based on [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002.html).
- Ordered and unordered streams, plus unreliable datagrams per [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html).
- 0-RTT data for resumed connections.
- Connection migration and path MTU discovery based on [RFC 8899](https://www.rfc-editor.org/rfc/rfc8899.html).
- Async APIs for Linux, macOS and Windows, including Tokio, Smol, and native Compio completion I/O; pluggable cryptography with [rustls][rustls] and [*ring*][ring].
- Continues the [quinn] codebase, tracking upstream changes.

## Usage

To use `quic`, first add this to your `Cargo.toml`:

```toml
[dependencies]
quic = "0.12"
```

Next, add this to your crate:

```rust
use quic::{ClientConfig, Endpoint};

fn main() {
    // ...
}
```

Compio support is part of the same crate and uses the local `quic-proto` state machine:

```toml
[dependencies]
quic = { version = "0.12", features = ["runtime-compio"] }
```

Use `quic::compio::Endpoint` inside a running Compio runtime. Compio owns I/O buffers until an
operation completes, so its endpoint, connection, and stream types are runtime-local and live in
the `compio` module. The readiness-based Tokio and Smol types remain at the crate root.

Use a current stable Rust toolchain with Compio. The Rust 1.88 minimum-version check covers the
other features, and CI tests Compio separately on stable.

## License

The workspace is licensed under Apache License, Version 2.0 ([LICENSE](LICENSE) or
http://www.apache.org/licenses/LICENSE-2.0). The `quic` crate also contains Compio-derived code
under the MIT terms recorded in [quic/LICENSE-MIT](quic/LICENSE-MIT) and
[quic/NOTICE.md](quic/NOTICE.md).

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the [Apache-2.0](LICENSE) license,
shall be licensed as above, without any additional terms or conditions.

[quic]: https://quicwg.github.io/
[quinn]: https://github.com/quinn-rs/quinn
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
