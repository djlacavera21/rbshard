# RbShard Container Format

This document describes the portable `.rbs` container family. File-oriented writers now emit streaming **RBS v3** containers. The in-memory `RbShard.pack` API continues to emit authenticated RBS v2. Readers retain compatibility with v3, v2, v1, and the original headerless raw codec.

## Goals

The format provides recognizable magic bytes, explicit versioning, bounded parser work, password-based key derivation, randomized encryption, integrity/authenticity checking, backward compatibility, and a path for multi-gigabyte files without loading the entire plaintext or ciphertext into memory.

## Version 3 — streaming file format

RBS v3 divides plaintext into independently compressed, encrypted, and authenticated records. A final authenticated footer binds the ordered list of chunk tags and aggregate counts.

### File header

| Offset | Length | Name | Encoding |
| ---: | ---: | --- | --- |
| 0 | 4 | magic | ASCII `RBSH` |
| 4 | 1 | version | unsigned byte, value `3` |
| 5 | 4 | KDF iterations | unsigned 32-bit little-endian |
| 9 | 4 | chunk size | unsigned 32-bit little-endian |
| 13 | 16 | salt | random bytes |

The v3 header is 29 bytes.

The password/key is expanded with PBKDF2-HMAC-SHA256 into 64 bytes. The first 32 bytes are the Twofish encryption key and the final 32 bytes are the HMAC authentication key. The default KDF work factor remains 200,000 iterations.

### Chunk record

Each non-empty plaintext chunk is represented as:

| Length | Name | Encoding |
| ---: | --- | --- |
| 4 | marker | ASCII `CHNK` |
| 4 | chunk index | unsigned 32-bit little-endian |
| 4 | plaintext length | unsigned 32-bit little-endian |
| 4 | ciphertext length | unsigned 32-bit little-endian |
| 16 | IV | random bytes |
| N | ciphertext | LZW-compressed plaintext encrypted with Twofish-CBC + PKCS#7 |
| 32 | chunk tag | HMAC-SHA256 |

The per-chunk tag is:

```text
HMAC-SHA256(authentication_key,
            complete_v3_header || chunk_record_header || ciphertext)
```

Readers MUST validate the chunk index and length bounds, read the complete ciphertext/tag, and verify the chunk tag before decrypting or decompressing that record.

Chunk IVs are generated independently. Chunk indexes begin at zero and increase by exactly one.

### Footer

After the last chunk, writers emit:

| Length | Name | Encoding |
| ---: | --- | --- |
| 4 | marker | ASCII `END!` |
| 4 | chunk count | unsigned 32-bit little-endian |
| 8 | total plaintext bytes | unsigned 64-bit little-endian |
| 32 | final tag | HMAC-SHA256 |

The final tag is produced incrementally over:

```text
complete_v3_header ||
chunk_0_tag || chunk_1_tag || ... || chunk_n_tag ||
footer_marker || chunk_count || total_plaintext_bytes
```

This footer detects missing/reordered records and authenticates the aggregate chunk count and total plaintext length. Readers MUST reject trailing bytes after the footer.

### Streaming and commit semantics

The library's `pack_stream` / `unpack_stream` methods operate on IO objects with memory bounded to approximately one working chunk plus its compressed/ciphertext representations.

The file-oriented `unpack_file` helper writes v3 plaintext to a temporary file and atomically renames it to the requested destination only after the final footer authenticates. A wrong password, corrupted chunk, truncated archive, or invalid footer therefore does not replace the existing destination with partially verified plaintext.

The default plaintext chunk size is 1 MiB. Current readers accept chunk sizes from 1 KiB through 64 MiB.

## Version 2 — authenticated in-memory format

RBS v2 remains supported and is still emitted by `RbShard.pack` / `RbShard.save_rbs` for compatibility with the in-memory API.

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

The total file size is `77 + N` bytes. V2 compresses the complete plaintext with LZW, encrypts it with Twofish-CBC + PKCS#7, and authenticates `complete_v2_header || ciphertext` with HMAC-SHA256. Readers verify the tag before decryption.

V2 is authenticated but requires the complete payload in memory; v3 is preferred for file workflows.

## Version 1 — read compatibility

| Offset | Length | Name | Encoding |
| ---: | ---: | --- | --- |
| 0 | 4 | magic | ASCII `RBSH` |
| 4 | 1 | version | unsigned byte, value `1` |
| 5 | 4 | encrypted length | unsigned 32-bit little-endian |
| 9 | N | encrypted payload | legacy raw codec bytes |
| 9 + N | 32 | digest | SHA-256 of plaintext |

Version 1 uses an unkeyed digest and therefore is **not an authenticated format**. It remains read-only compatibility data.

## Headerless legacy payloads

Original files contain only the result of the historical `RbShard.encode` pipeline and do not start with `RBSH`. `RbShard.load_rbs` / `unpack_file` can read these by default. Callers may set `allow_legacy: false` to reject them.

## Compatibility matrix

| Input | Current reader | Current writer |
| --- | --- | --- |
| Headerless legacy | supported by default | raw API only |
| RBS v1 | supported | no |
| RBS v2 | supported | `pack` / `save_rbs` |
| RBS v3 | supported | `pack_stream` / `pack_file` / CLI `pack` |
| Unknown future version | rejected for decoding | n/a |

## Parser requirements

Implementations should reject malformed/truncated headers, unsupported versions, unreasonable KDF or chunk-size parameters, invalid record markers, non-sequential chunk indexes, impossible record lengths, authentication-tag mismatches before decryption, malformed compressed streams, inconsistent footer counts/lengths, truncated footers, and trailing bytes after a valid footer.

All payload, salt, IV, tag, and key material is binary. Implementations should not depend on the process default text encoding.

## Security boundary

V2 and v3 use randomized CBC encryption, PBKDF2-HMAC-SHA256, independently derived encryption/authentication keys, and encrypt-then-HMAC authentication. V3 additionally constrains memory use and authenticates each record before plaintext release. RbShard remains an experimental project built on a pure-Ruby Twofish dependency and has not received an independent cryptographic audit; high-value or regulated secrets should still prefer mature, audited encryption formats and libraries.
