# Changelog

All notable changes to RbShard will be documented in this file.

The project follows semantic versioning for public releases. Container-format revisions are versioned independently from gem releases.

## Unreleased

### Added

- Streaming authenticated **RBS v3** file format.
- Record-oriented v3 layout with independently authenticated encrypted chunks.
- Authenticated v3 footer binding chunk order, chunk count, and total plaintext length.
- `RbShard.pack_stream` / `RbShard.unpack_stream` IO APIs with bounded memory use.
- `RbShard.pack_file` / `RbShard.unpack_file` helpers for large files.
- Atomic destination commit on file unpack: failed authentication cannot replace an existing output with partial plaintext.
- Configurable v3 chunk sizing with bounded parser limits and a 1 MiB default.
- File metadata inspection that does not load complete archives into memory.
- Authenticated `RBSH` v2 in-memory container format.
- PBKDF2-HMAC-SHA256 password/key derivation with random salts.
- Twofish-CBC encryption with random IVs for v2/v3 containers.
- Encrypt-then-MAC authentication using HMAC-SHA256.
- Bounded KDF iteration parsing to limit malicious-header work amplification.
- Backward-compatible reading of RBS v1 containers and original headerless payloads.
- `RbShard.pack`, `RbShard.unpack`, `RbShard.container?`, and `RbShard.inspect_rbs` helpers.
- Optional rejection of legacy headerless `.rbs` payloads.
- Binary-safe and empty-input-safe LZW processing.
- Dedicated `FormatError` and `IntegrityError` exceptions.
- `rbshard` command-line interface for pack, unpack, inspect, encode, decode, and version operations.
- CLI controls for PBKDF2 iteration count and v3 chunk size.
- Formal multi-version container specification in `docs/FORMAT.md`.
- Expanded automated tests for binary data, v2/v3 authentication failures, streaming, truncation, atomic output safety, compatibility, and CLI workflows.
- Multi-version Ruby GitHub Actions CI.

### Changed

- CLI `pack` now streams input into RBS v3 instead of loading the complete file into memory.
- CLI `unpack` uses the streaming reader for v3 and preserves v2/v1/legacy compatibility.
- CLI `inspect` reads bounded file metadata instead of `File.binread`-ing the archive.
- `save_rbs` continues to provide the in-memory v2 compatibility API; file workflows should prefer `pack_file`.
- `load_rbs` auto-detects v3, v2, v1, and legacy formats when materialized in memory.
- The legacy `encode` / `decode` API remains available only for compatibility-oriented raw payload workflows.
- LZW code serialization is explicitly little-endian and its dictionary is bounded to 16-bit codes.
- Gem packaging exposes the `rbshard` executable and keeps the GTK desktop stack out of core runtime dependencies.
- The web UI writes authenticated v2 containers for uploaded files and binds to loopback by default.

### Security

- V3 authenticates every chunk before decryption/decompression and authenticates the complete chunk sequence with a final footer tag.
- V3 file unpacking uses an atomic temporary destination so incomplete authentication never commits partial plaintext.
- New authenticated containers explicitly select CBC with fresh IVs rather than relying on the legacy Twofish default mode.
- V2/v3 verify HMAC authentication before decrypting protected ciphertext.
- Encryption and authentication keys are independently derived from PBKDF2 output.
- V1 remains readable but is documented as unauthenticated.
- The project remains experimental and has not received a dedicated cryptographic audit.
