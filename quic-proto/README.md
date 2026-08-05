# quic-proto

`quic-proto` is the low-level QUIC state machine used by
[`quic`](https://docs.rs/quic). It contains no socket or async runtime code.

Most applications should use the high-level `quic` crate. Use `quic-proto`
directly when integrating QUIC with a custom event loop or building an FFI
layer. The main entry points are `Endpoint`, which routes datagrams, and
`Connection`, which holds the state for one QUIC connection.

API documentation is available on [docs.rs](https://docs.rs/quic-proto).

## License

Licensed under the [Apache License 2.0](LICENSE).
