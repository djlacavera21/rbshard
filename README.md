# rbshard

rbshard 0.1.0

RbShard is a compact Ruby compression and encryption toolkit. It combines a binary-safe LZW codec with Twofish encryption and provides a versioned `.rbs` container format, command-line tooling, file helpers, and optional web/desktop interfaces.

> **Security note:** RbShard is an experimental project, not a substitute for a professionally reviewed authenticated-encryption format. The v1 container adds corruption/wrong-key detection with SHA-256, but it does not provide cryptographic authentication against an active attacker. Do not use it as the sole protection for high-value secrets.

## Features

* Binary-safe LZW compression and decompression
* Twofish encryption and decryption
* Versioned, self-identifying `.rbs` containers
* SHA-256 plaintext integrity verification after decryption
* Legacy headerless `.rbs` read compatibility
* First-class `rbshard` command-line interface
* Convenience helpers for files and in-memory payloads
* Experimental WEBrick web UI and optional GTK desktop UI
* Minitest coverage for core and CLI workflows
* Multi-version Ruby CI
* Formal container-format documentation

## Architecture

```text
             +-------------------+
             | Ruby API / CLI/UI |
             +---------+---------+
                       |
              +--------v--------+
              | RBS Container   |
              | magic/version   |
              | length/digest   |
              +--------+--------+
                       |
              +--------v--------+
              | Twofish crypto  |
              +--------+--------+
                       |
              +--------v--------+
              | LZW compression |
              +-----------------+
```

The legacy `encode` / `decode` methods operate on the LZW + Twofish layers directly. New file-oriented APIs add the versioned container layer around that codec.

## Container format

New files written by `save_rbs` use format version 1:

| Field | Size | Description |
| --- | ---: | --- |
| Magic | 4 bytes | ASCII `RBSH` |
| Version | 1 byte | Currently `1` |
| Payload length | 4 bytes | Little-endian encrypted payload length |
| Payload | variable | LZW-compressed data encrypted with Twofish |
| Digest | 32 bytes | SHA-256 of the original plaintext |

The header makes new archives distinguishable from older raw encrypted payloads. `load_rbs` automatically reads both formats by default. See [`docs/FORMAT.md`](docs/FORMAT.md) for the byte-level specification and parser requirements.

## Ruby API

```ruby
require 'rbshard'

data = 'Hello rbshard!'
key = 'secretkey1234567'

RbShard.save_rbs('message.rbs', data, key)
original = RbShard.load_rbs('message.rbs', key)
puts original # => "Hello rbshard!"
```

### In-memory containers

```ruby
archive = RbShard.pack('example text', key)
metadata = RbShard.inspect_rbs(archive)
# => { format: :container, version: 1, payload_bytes: ..., total_bytes: ... }

plaintext = RbShard.unpack(archive, key)
```

### Legacy codec API

`encode` and `decode` remain available and produce/consume the original headerless encrypted representation:

```ruby
encoded = RbShard.encode(data, key)
decoded = RbShard.decode(encoded, key)
```

To reject old headerless files when loading from disk:

```ruby
RbShard.load_rbs('message.rbs', key, allow_legacy: false)
```

## Command-line interface

The gem exposes a `rbshard` executable. From a source checkout, use `ruby bin/rbshard` in place of `rbshard`.

```sh
# Pack a file using a key stored in an environment variable
export RBSHARD_KEY='secretkey1234567'
rbshard pack --key-env RBSHARD_KEY report.pdf report.rbs

# Inspect metadata without decrypting
rbshard inspect report.rbs

# Restore the original file
rbshard unpack --key-env RBSHARD_KEY report.rbs report.pdf
```

Keys can be supplied with `--key`, `--key-env`, or `--key-file`. `--key-env` and `--key-file` are preferable because direct command-line arguments may be visible to other local processes or shell history.

The CLI also exposes `encode` and `decode` commands for the legacy raw codec and `unpack --no-legacy` for applications that want to reject headerless files.

## Web UI

Start the experimental local web interface with:

```sh
ruby bin/rbshard_ui
```

Then visit `http://127.0.0.1:4567`. File uploads are written as versioned `.rbs` containers, while text encode/decode retains the original Base64-wrapped raw codec for compatibility. The server binds to loopback by default; `BIND` and `PORT` environment variables can override its listener.

## Desktop UI

The desktop interface requires the optional `gtk3` gem and its native platform dependencies:

```sh
gem install gtk3
ruby bin/rbshard_desktop
```

GTK is intentionally not a core gem dependency so command-line and server environments do not need to install a desktop stack. The UI provides text encode/decode operations, file encryption/decryption, open/save actions, clipboard support, clearing controls, error dialogs, and status messages.

## Development

Install the core development dependencies and run all tests:

```sh
bundle install
bundle exec rake test
```

CI runs the suite across supported Ruby versions and smoke-tests the command-line executable. The core library intentionally has a small public API. Changes to the on-disk format should introduce a new `FORMAT_VERSION` and retain an explicit migration/read path for older versions whenever practical.

## Repository layout

```text
bin/
  rbshard             CLI
  rbshard_ui          local WEBrick UI
  rbshard_desktop     optional GTK UI
lib/
  rbshard.rb           core codec and container implementation
  rbshard/version.rb   gem version
docs/
  FORMAT.md            RBS container specification
test/
  test_rbshard.rb      core tests
  test_cli.rb          CLI integration tests
```

## Roadmap

The next major format revision should replace the v1 digest-only integrity mechanism with a standard authenticated-encryption or encrypt-then-MAC construction. Additional priorities include password-based key derivation with explicit salts and parameters, streaming support for large files, fuzz/property testing of the parser and LZW decoder, portable test vectors, richer metadata, and reproducible release automation.

See [`CHANGELOG.md`](CHANGELOG.md) for the current unreleased work.
