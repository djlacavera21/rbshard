# RbShard Container Format

This document describes the portable `.rbs` container introduced as format version 1.

## Goals

The container layer gives RbShard files a recognizable signature, explicit versioning, deterministic payload boundaries, and post-decryption integrity checking while preserving the original `RbShard.encode` / `RbShard.decode` codec for compatibility.

## Byte layout

All offsets are measured from the beginning of the file.

| Offset | Length | Name | Encoding |
| ---: | ---: | --- | --- |
| 0 | 4 | magic | ASCII `RBSH` |
| 4 | 1 | version | unsigned byte |
| 5 | 4 | encrypted length | unsigned 32-bit little-endian |
| 9 | N | encrypted payload | opaque bytes |
| 9 + N | 32 | digest | SHA-256 bytes |

The total file size MUST be `41 + N` bytes for version 1.

## Payload processing

Writers perform the following logical pipeline:

```text
plaintext
   |
   v
LZW compression
   |
   v
Twofish encryption
   |
   v
encrypted payload
```

The trailing digest is `SHA256(plaintext)`.

Readers validate the magic, version, declared payload length, and total container size before attempting to decode the payload. After decryption and decompression, readers compare `SHA256(plaintext)` with the stored digest.

## Compatibility

Files created by earlier releases contain only the encrypted LZW payload and therefore do not start with `RBSH`. `RbShard.load_rbs` treats these as legacy payloads when `allow_legacy` is true. Applications that require only the new container can set `allow_legacy: false`.

## Security properties and limitations

Version 1 detects accidental corruption and normally detects an incorrect key after decryption. The digest is not keyed, so version 1 MUST NOT be described as an authenticated-encryption format and is not designed to protect against deliberate ciphertext modification by an active attacker.

A future format version should use a standard authenticated-encryption or encrypt-then-MAC construction, include any required nonce/salt/KDF parameters in the authenticated header, and publish interoperable test vectors.

## Parser requirements

Implementations should reject:

* truncated headers;
* unknown magic values;
* unsupported versions;
* files whose actual size differs from the declared payload length;
* malformed compressed streams;
* failed decryption; and
* plaintext whose digest does not match the stored digest.

Parsers should treat all payload data as binary and should not depend on the process default text encoding.
