# Changelog

All notable changes to RbShard will be documented in this file.

The project follows semantic versioning for public releases. Container-format revisions are versioned independently through `RbShard::FORMAT_VERSION`.

## Unreleased

### Added

- Versioned `RBSH` v1 container format with magic bytes and payload length metadata.
- SHA-256 plaintext integrity verification after decryption.
- `RbShard.pack`, `RbShard.unpack`, `RbShard.container?`, and `RbShard.inspect_rbs` helpers.
- Optional rejection of legacy headerless `.rbs` payloads.
- Binary-safe and empty-input-safe LZW processing.
- Dedicated `FormatError` and `IntegrityError` exceptions.
- `rbshard` command-line interface for pack, unpack, inspect, encode, decode, and version operations.
- Formal container specification in `docs/FORMAT.md`.
- Expanded automated tests for binary data, corruption, containers, and legacy compatibility.

### Changed

- `save_rbs` now writes versioned containers.
- `load_rbs` auto-detects versioned containers while retaining legacy read compatibility.
- LZW code serialization is explicitly little-endian and its dictionary is bounded to 16-bit codes.
- Gem packaging now exposes the `rbshard` executable and keeps the GTK desktop stack out of core runtime dependencies.

### Security

- Documentation now explicitly distinguishes v1 integrity checking from authenticated encryption.
