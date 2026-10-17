# iroh-p2p-core

Shared foundational primitives for decentralized peer-to-peer (P2P) systems built on **iroh** and **QUIC**.

Used across the [Glyph](https://github.com/glyph-messenger/glyph) ecosystem (decentralized messenger) and [Rune](https://github.com/glyph-messenger/rune) (mesh VPN).

---

## Features & Modules

- **`endpoint_id`**: 32-byte Ed25519 node public key identifier with hexadecimal string parsing, compact formatting (`short_hex`), and direct conversion to/from `iroh_base::PublicKey`.
- **`identity`**: Node identity (`Identity`) wrapping `iroh_base::SecretKey` with secure disk persistence (`0600` file permissions on Unix), key generation, message signing, and verification.
- **`signature`**: 64-byte Ed25519 wire signatures (`WireSignature`) with custom Serde implementations for binary and textual serializers.
- **`ticket`**: Generic, cryptographically signed network discovery tickets (`SignedTicket<T>`) encoded as compact Base32 strings with customizable prefixes (e.g. `glyph:v1:...` or `rune-net:v1:...`).
- **`peerbook`**: Dynamic, thread-safe remote address catalog (`PeerBook`) tracking direct IP socket addresses and iroh Relay URLs per peer.
- **`replay`**: Sliding-window anti-replay filter (`ReplayFilter`) tracking timestamps and single-use nonces to protect control and signaling streams.
- **`framing`**: Zero-overhead length-prefixed stream framing helpers (`read_frame`, `write_frame`, `read_bincode_msg`, `write_bincode_msg`) over async streams.

---

## Building and Testing

```bash
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
```

---

## License

MIT OR Apache-2.0
