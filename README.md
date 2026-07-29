# quic

[![CI](https://github.com/0x676e67/quic/actions/workflows/rust.yml/badge.svg)](https://github.com/0x676e67/quic/actions/workflows/rust.yml)
![Crates.io License](https://img.shields.io/crates/l/quic)
[![Crates.io](https://img.shields.io/crates/v/quic.svg)](https://crates.io/crates/quic)

**quic** is a pure-Rust, async-compatible [quinn](https://github.com/quinn-rs/quinn) fork implementing selected [QUIC][quic] extensions, including those unlikely to be merged upstream.

## Features

- Simultaneous client/server operation
- Ordered and unordered stream reads for improved performance
- Works on stable Rust, tested on Linux, macOS and Windows
- Pluggable cryptography, with a standard implementation backed by
  [rustls][rustls] and [*ring*][ring]
- Application-layer datagrams for small, unreliable messages
- Future-based async API
- Minimum supported Rust version of 1.85.0

# Getting Started

**Examples**

```sh
$ cargo run --example server ./
$ cargo run --example client https://localhost:4433/Cargo.toml
```

This launches an HTTP 0.9 server on the loopback address serving the current
working directory, with the client fetching `./Cargo.toml`. By default, the
server generates a self-signed certificate and stores it to disk, where the
client will automatically find and trust it.

## License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this project by you, as defined in the
Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.

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
