# Changelog

All notable changes to RbShard will be documented in this file.

The project follows semantic versioning for public releases. Container-format revisions are versioned independently through `RbShard::FORMAT_VERSION`.

## Unreleased

### Added

- Authenticated `RBSH` v2 container format.
- PBKDF2-HMAC-SHA256 password/key derivation with random 16-byte salts.
- Twofish-CBC encryption with random 16-byte IVs for v2 containers.
- Encrypt-then-MAC authentication using HMAC-SHA256 over the v2 header and ciphertext.
- Bounded KDF iteration parsing to limit malicious-header work amplification.
- Backward-compatible reading of RBS v1 containers and original headerless payloads.
- `RbShard.pack`, `RbShard.unpack`, `RbShard.container?`, and `RbShard.inspect_rbs` helpers.
- Optional rejection of legacy headerless `.rbs` payloads.
- Binary-safe and empty-input-safe LZW processing.
- Dedicated `FormatError` and `IntegrityError` exceptions.
- `rbshard` command-line interface for pack, unpack, inspect, encode, decode, and version operations.
- CLI control for v2 PBKDF2 iteration count.
- Formal multi-version container specification in `docs/FORMAT.md`.
- Expanded automated tests for binary data, randomized v2 output, authentication failures, v1 compatibility, file helpers, and CLI workflows.
- Multi-version Ruby GitHub Actions CI.

### Changed

- `save_rbs` now writes authenticated v2 containers.
- `load_rbs` auto-detects v2, v1, and legacy formats.
- The legacy `encode` / `decode` API remains available only for compatibility-oriented raw payload workflows.
- LZW code serialization is explicitly little-endian and its dictionary is bounded to 16-bit codes.
- Gem packaging now exposes the `rbshard` executable and keeps the GTK desktop stack out of core runtime dependencies.
- The web UI writes v2 containers for uploaded files and binds to loopback by default.

### Security

- New containers no longer use the legacy default Twofish mode; v2 explicitly selects CBC with a random IV.
- V2 verifies HMAC authentication before decryption or decompression.
- Encryption and authentication keys are independently derived from PBKDF2 output.
- V1 remains readable but is documented as unauthenticated.
- The project remains experimental and has not received a dedicated cryptographic audit.
