# rbshard

rbshard 0.1.0

RbShard is a compact Ruby compression and encryption toolkit. It combines a binary-safe LZW codec with Twofish encryption and provides a versioned `.rbs` container format, command-line tooling, file helpers, and optional web/desktop interfaces.

> **Security note:** RbShard remains experimental and unaudited. New RBS v2 containers use PBKDF2-HMAC-SHA256, randomized Twofish-CBC, and encrypt-then-HMAC authentication, but high-value or regulated secrets should still use a mature audited encryption format. See [`SECURITY.md`](SECURITY.md).

## Features

* Binary-safe LZW compression and decompression
* Authenticated RBS v2 containers
* PBKDF2-HMAC-SHA256 key derivation with random salts
* Twofish-CBC encryption with random IVs
* HMAC-SHA256 encrypt-then-MAC authentication
* Backward-compatible RBS v1 and headerless legacy readers
* First-class `rbshard` command-line interface
* Convenience helpers for files and in-memory payloads
* Experimental WEBrick web UI and optional GTK desktop UI
* Core and CLI Minitest coverage
* Multi-version Ruby CI
* Formal container-format and security documentation

## Architecture

```text
             +-------------------+
             | Ruby API / CLI/UI |
             +---------+---------+
                       |
              +--------v---------+
              | RBS v2 container|
              | version / KDF    |
              | salt / IV / HMAC |
              +--------+---------+
                       |
              +--------v---------+
              | Twofish-CBC      |
              +--------+---------+
                       |
              +--------v---------+
              | LZW compression  |
              +------------------+
```

The legacy `encode` / `decode` methods operate on the original LZW + Twofish path directly. New file-oriented APIs use authenticated v2 containers. Readers can still open v1 and original headerless payloads.

## Container format

New files written by `save_rbs` use **RBS v2**:

| Field | Size | Description |
| --- | ---: | --- |
| Magic | 4 bytes | ASCII `RBSH` |
| Version | 1 byte | `2` |
| KDF iterations | 4 bytes | PBKDF2 iteration count, little-endian |
| Salt | 16 bytes | Random PBKDF2 salt |
| IV | 16 bytes | Random Twofish-CBC IV |
| Payload length | 4 bytes | Encrypted payload length, little-endian |
| Payload | variable | LZW-compressed, Twofish-CBC encrypted data |
| Authentication tag | 32 bytes | HMAC-SHA256 over header + ciphertext |

The supplied password/key is expanded with PBKDF2-HMAC-SHA256 into separate 32-byte encryption and authentication keys. The current writer default is 200,000 PBKDF2 iterations.

See [`docs/FORMAT.md`](docs/FORMAT.md) for the byte-level v2 specification, v1 compatibility layout, and parser requirements.

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
# => {
#   format: :container,
#   version: 2,
#   authenticated: true,
#   kdf: :'pbkdf2-hmac-sha256',
#   cipher: :'twofish-cbc',
#   ...
# }

plaintext = RbShard.unpack(archive, key)
```

### Compatibility API

`encode` and `decode` remain available for original headerless payloads:

```ruby
encoded = RbShard.encode(data, key)
decoded = RbShard.decode(encoded, key)
```

That path preserves historical behavior for compatibility and should not be selected for new encrypted file formats.

To reject headerless files when loading from disk:

```ruby
RbShard.load_rbs('message.rbs', key, allow_legacy: false)
```

RBS v1 containers remain readable automatically.

## Command-line interface

The gem exposes a `rbshard` executable. From a source checkout, use `ruby bin/rbshard` in place of `rbshard`.

```sh
# Pack a file using a key stored in an environment variable
export RBSHARD_KEY='correct horse battery staple'
rbshard pack --key-env RBSHARD_KEY report.pdf report.rbs

# Inspect metadata without decrypting
rbshard inspect report.rbs

# Restore the original file
rbshard unpack --key-env RBSHARD_KEY report.rbs report.pdf
```

Keys can be supplied with `--key`, `--key-env`, or `--key-file`. `--key-env` and `--key-file` are preferable because direct command-line arguments may be visible to other local processes or shell history.

`pack --kdf-iterations N` is available for controlled interoperability/testing scenarios. Production users should normally retain the default rather than reducing the work factor.

The CLI also exposes `encode` and `decode` commands for the legacy raw codec and `unpack --no-legacy` for applications that want to reject headerless files.

## Web UI

Start the experimental local web interface with:

```sh
ruby bin/rbshard_ui
```

Then visit `http://127.0.0.1:4567`. File uploads are written as authenticated v2 `.rbs` containers, while text encode/decode retains the original Base64-wrapped raw codec for compatibility. The server binds to loopback by default; `BIND` and `PORT` environment variables can override its listener.

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

CI runs the suite across supported Ruby versions and smoke-tests the command-line executable. Test code can lower the PBKDF2 iteration count to the accepted minimum to keep the suite fast while still exercising the v2 path.

The on-disk container version is independent of the gem version. Any future format change should increment `FORMAT_VERSION` and preserve an explicit migration/read path whenever practical.

## Repository layout

```text
.github/workflows/
  ci.yml              Ruby test matrix
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
  test_rbshard.rb      core/container tests
  test_cli.rb          CLI integration tests
CHANGELOG.md           unreleased/release changes
SECURITY.md            security model and reporting guidance
```

## Roadmap

Next priorities are streaming encryption/decryption for large files, fuzz/property testing of the parser and LZW decoder, portable interoperability test vectors, richer authenticated metadata, safer secret-entry UX, reproducible release automation, and eventually evaluating whether a more modern audited cryptographic dependency should replace the legacy Twofish implementation entirely.

See [`CHANGELOG.md`](CHANGELOG.md) for the current unreleased work.
