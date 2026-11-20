# Third-party notices

The native Compio frontend in `src/compio.rs` and `src/compio/` is derived from
`compio-quic` 0.8.0 at commit `08e5a47036cb7be40c1faf5a58909b640d98ee2e`,
with later fixes reviewed through commit
`8ee611f08944d1bfcca976956838c84848e52262`.

Compio is Copyright (c) 2023 Berrysoft and is licensed under the MIT License.
The applicable text is in `LICENSE-MIT`.

`compio-quic` adapts code from Quinn and h3. Quinn is available under
Apache-2.0 or MIT, and h3 is available under MIT. The integrated code has been
rebased onto this repository's local `quic-proto` state machine and modified
for its runtime, feature, and protocol-extension behavior.
