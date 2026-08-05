# quic

A [Sans-I/O][sans-io] aware, QUIC implementation for Rust.

[![CI](https://github.com/0x676e67/quic/actions/workflows/rust.yml/badge.svg)](https://github.com/0x676e67/quic/actions/workflows/rust.yml)
[![GitHub License](https://img.shields.io/github/license/0x676e67/quic)](https://github.com/0x676e67/quic/blob/main/LICENSE)
[![Crates.io](https://img.shields.io/crates/v/quic.svg)](https://crates.io/crates/quic)

More information about this crate can be found in the [crate documentation](https://docs.rs/quic).

## Features

- QUIC version 1 ([RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html)), secured with TLS ([RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html)).
- Loss detection and congestion control based on [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002.html).
- Ordered and unordered streams, plus unreliable datagrams ([RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html)).
- 0-RTT data for resumed connections.
- Connection migration and path MTU discovery based on [RFC 8899](https://www.rfc-editor.org/rfc/rfc8899.html).
- Async APIs for Linux, macOS and Windows; pluggable cryptography with [rustls][rustls] and [*ring*][ring].
- Minimum supported Rust version: 1.88.0.

## Usage

Add `quic` to your `Cargo.toml`:

```toml
[dependencies]
quic = "0.11"
```

Then import the types needed to create an endpoint:

```rust
use quic::{ClientConfig, Endpoint};

fn main() {
    // ...
}
```

See the [examples] for complete client and server implementations.

## License

Licensed under either of Apache License, Version 2.0 ([LICENSE](LICENSE) or
http://www.apache.org/licenses/LICENSE-2.0).

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the [Apache-2.0](LICENSE) license,
shall be licensed as above, without any additional terms or conditions.

## Accolades

The project is based on a fork of [quinn](https://github.com/quinn-rs/quinn).

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
