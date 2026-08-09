# RbShard Container Format

This document describes the portable `.rbs` container family. New writers emit format version 2. Readers retain compatibility with version 1 and with the original headerless raw codec.

## Goals

The container layer gives RbShard files a recognizable signature, explicit versioning, deterministic payload boundaries, password-based key derivation, randomized encryption, integrity/authenticity checking, and an upgrade path independent of the public Ruby API.

## Version 2 (current)

### Byte layout

All offsets are measured from the beginning of the file.

| Offset | Length | Name | Encoding |
| ---: | ---: | --- | --- |
| 0 | 4 | magic | ASCII `RBSH` |
| 4 | 1 | version | unsigned byte, value `2` |
| 5 | 4 | KDF iterations | unsigned 32-bit little-endian |
| 9 | 16 | salt | random bytes |
| 25 | 16 | IV | random bytes |
| 41 | 4 | encrypted length | unsigned 32-bit little-endian |
| 45 | N | encrypted payload | opaque bytes |
| 45 + N | 32 | authentication tag | HMAC-SHA256 |

The total file size MUST be `77 + N` bytes.

### Key derivation

The caller-supplied key/password is processed using PBKDF2-HMAC-SHA256:

```text
PBKDF2-HMAC-SHA256(
  password = caller supplied key bytes,
  salt = 16-byte container salt,
  iterations = header iteration count,
  output length = 64 bytes
)
```

The first 32 derived bytes are the Twofish encryption key. The final 32 bytes are the HMAC authentication key.

The current writer default is 200,000 PBKDF2 iterations. Readers accept bounded iteration counts so a malicious header cannot request unbounded KDF work.

### Encryption pipeline

```text
plaintext
   |
   v
LZW compression
   |
   v
Twofish-CBC + PKCS#7 padding
32-byte derived encryption key
16-byte random IV
   |
   v
ciphertext
```

The 16-byte IV is stored in the authenticated header. Repacking identical plaintext with the same password SHOULD produce different container bytes because both the salt and IV are randomly generated.

### Authentication

Version 2 uses encrypt-then-MAC. The tag is:

```text
HMAC-SHA256(authentication_key, complete_v2_header || ciphertext)
```

Readers MUST verify the tag before attempting CBC decryption or decompression. An authentication failure should be reported without attempting to distinguish a wrong password from modified/corrupted input.

## Version 1 (read compatibility)

Version 1 was the first self-identifying RbShard container design.

| Offset | Length | Name | Encoding |
| ---: | ---: | --- | --- |
| 0 | 4 | magic | ASCII `RBSH` |
| 4 | 1 | version | unsigned byte, value `1` |
| 5 | 4 | encrypted length | unsigned 32-bit little-endian |
| 9 | N | encrypted payload | legacy raw codec bytes |
| 9 + N | 32 | digest | SHA-256 of plaintext |

The total file size is `41 + N` bytes.

Version 1 detects accidental corruption and generally detects wrong-key output, but its digest is unkeyed and therefore it is **not an authenticated format**. New writers MUST prefer version 2.

## Headerless legacy payloads

Files from the original implementation contain only the result of the legacy `RbShard.encode` pipeline and therefore do not start with `RBSH`.

`RbShard.load_rbs` can read these by default for backward compatibility. Applications that do not need old files can pass `allow_legacy: false` to reject them. The raw `encode` / `decode` API is preserved specifically for compatibility and should not be selected for new file formats.

## Compatibility matrix

| Input | Current reader | Current writer |
| --- | --- | --- |
| Headerless legacy | supported by default | raw API only |
| RBS v1 | supported | no |
| RBS v2 | supported | yes |
| Unknown future version | rejected | n/a |

## Parser requirements

Implementations should reject:

* truncated headers;
* unknown magic values;
* unsupported versions when decoding;
* files whose actual size differs from the declared payload length;
* v2 KDF iteration counts outside the implementation's accepted safety bounds;
* v2 authentication-tag mismatches before decryption;
* failed decryption; and
* malformed compressed streams.

Parsers should treat all payload, salt, IV, tag, and key material as binary and should not depend on the process default text encoding.

## Security boundary

Version 2 materially improves the format by adding randomized CBC encryption, password-based key derivation, independent encryption/authentication keys, and encrypt-then-HMAC authentication. It remains an experimental project built on a pure-Ruby Twofish dependency and has not received a dedicated cryptographic audit. Applications with high-value secrets should prefer mature, audited storage formats and libraries.
