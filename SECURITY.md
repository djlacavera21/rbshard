# Security Policy

RbShard is an experimental encryption/container project. It should not be treated as independently audited cryptographic software.

## Supported formats

New files are written using RBS format version 2. Version 2 uses PBKDF2-HMAC-SHA256, Twofish-CBC with a random IV, and encrypt-then-MAC authentication with HMAC-SHA256.

Version 1 and original headerless payloads remain readable for compatibility, but they do not provide the same security properties as version 2. In particular, version 1 is not authenticated and the headerless legacy codec preserves the historical raw Twofish behavior.

## Security expectations

For new data:

- prefer `RbShard.pack`, `RbShard.save_rbs`, or the `rbshard pack` command;
- avoid the legacy `encode` API unless compatibility requires it;
- use high-entropy keys or strong passphrases;
- prefer `--key-env` or `--key-file` over `--key` in shell workflows;
- keep encrypted archives and key material in separate trust domains when practical; and
- do not weaken PBKDF2 iteration counts merely for convenience outside controlled test environments.

## Threat-model limitations

RbShard v2 authenticates its header and ciphertext before decryption, but the implementation still has important limitations:

- the Twofish dependency is implemented in pure Ruby and may not provide constant-time behavior;
- secret material lives in Ruby-managed memory and is not reliably zeroized;
- whole files are currently buffered in memory;
- metadata such as total archive size is visible;
- local endpoint security, shell history, environment exposure, filesystem permissions, swap, backups, and process inspection are outside the container format's protection; and
- the project has not undergone an independent cryptographic or implementation audit.

For high-value or regulated secrets, use a mature audited encryption format/library appropriate to the environment rather than relying solely on RbShard.

## Reporting a vulnerability

Please avoid publishing exploitable details in a public issue before the maintainer has had a reasonable opportunity to assess them. Use GitHub's private security-reporting feature when enabled for the repository. If private reporting is unavailable, open a minimal public issue requesting a private contact channel without including exploit details.

A useful report should include the affected version/commit, the relevant container format version, reproduction conditions, expected versus observed behavior, and the security impact.
