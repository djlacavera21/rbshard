# rbshard

rbshard 0.1.0

RbShard is a compact Ruby compression and encryption toolkit. It combines a binary-safe LZW codec with Twofish encryption and provides versioned `.rbs` containers, streaming file workflows, a command-line interface, file helpers, and optional web/desktop interfaces.

> **Security note:** RbShard remains experimental and unaudited. RBS v2/v3 use PBKDF2-HMAC-SHA256, randomized Twofish-CBC, and encrypt-then-HMAC authentication, but high-value or regulated secrets should still use a mature audited encryption format. See [`SECURITY.md`](SECURITY.md).

## Features

* Streaming authenticated **RBS v3** for large files
* Bounded-memory chunked compression/encryption/decryption
* Per-chunk HMAC verification plus authenticated final footer
* Atomic destination commit after complete v3 verification
* Authenticated in-memory RBS v2 containers
* PBKDF2-HMAC-SHA256 key derivation with random salts
* Twofish-CBC encryption with fresh random IVs
* HMAC-SHA256 encrypt-then-MAC authentication
* Backward-compatible RBS v1 and headerless legacy readers
* Binary-safe LZW compression and decompression
* First-class `rbshard` CLI
* Metadata inspection without loading whole archives
* Experimental WEBrick web UI and optional GTK desktop UI
* Core, streaming, and CLI Minitest coverage
* Multi-version Ruby CI and release-gated gem publishing
* Formal multi-version container specification

## Architecture

```text
                 +---------------------+
                 | Ruby API / CLI / UI |
                 +----------+----------+
                            |
              +-------------+-------------+
              |                           |
       +------v-------+            +------v-------+
       | RBS v3 file |            | RBS v2 memory|
       | chunk stream|            | single blob  |
       +------+-------+            +------+-------+
              |                           |
       +------v---------------------------v------+
       | PBKDF2 -> Twofish-CBC -> HMAC-SHA256   |
       +------------------+---------------------+
                          |
                   +------v-------+
                   | LZW codec    |
                   +--------------+
```

The original `encode` / `decode` methods remain available only for compatibility with headerless legacy payloads.

## RBS v3 streaming format

File workflows now use **RBS v3**. A v3 archive contains:

```text
RBSH v3 header
    |
    +-- CHNK 0: lengths + IV + ciphertext + HMAC
    +-- CHNK 1: lengths + IV + ciphertext + HMAC
    +-- ...
    |
    `-- END!: chunk count + plaintext length + final HMAC
```

Each plaintext chunk is compressed independently with LZW, encrypted independently with Twofish-CBC and a fresh IV, and authenticated before decryption. The footer authenticates the ordered sequence of chunk tags and aggregate counts, detecting truncation or reordering.

The default plaintext chunk size is **1 MiB**. The current implementation accepts 1 KiB through 64 MiB chunks.

`unpack_file` writes to a temporary destination and atomically renames it only after the final footer validates, so a failed password/authentication check cannot replace an existing destination with partially verified plaintext.

See [`docs/FORMAT.md`](docs/FORMAT.md) for the byte-level v3/v2/v1 specification.

## Command-line interface

The gem exposes a `rbshard` executable. From a source checkout, use `ruby bin/rbshard`.

```sh
export RBSHARD_KEY='correct horse battery staple'

# Stream a large file into RBS v3
rbshard pack --key-env RBSHARD_KEY disk-image.bin disk-image.rbs

# Inspect metadata without reading the whole archive
rbshard inspect disk-image.rbs

# Stream and atomically restore the original file
rbshard unpack --key-env RBSHARD_KEY disk-image.rbs disk-image.bin
```

For controlled testing/interoperability:

```sh
rbshard pack \
  --chunk-size 4194304 \
  --kdf-iterations 200000 \
  --key-env RBSHARD_KEY \
  input.bin output.rbs
```

Keys can be supplied with `--key`, `--key-env`, or `--key-file`. `--key-env` and `--key-file` are preferable because direct arguments may appear in process listings or shell history.

`unpack --no-legacy` rejects original headerless payloads. `encode` and `decode` expose the old raw codec for compatibility only.

## Ruby API

### Streaming files

```ruby
require 'rbshard'

key = 'correct horse battery staple'

metadata = RbShard.pack_file(
  'backup.tar',
  'backup.rbs',
  key,
  chunk_size: 4 * 1024 * 1024
)

RbShard.unpack_file('backup.rbs', 'backup-restored.tar', key)
```

### Streaming IO

```ruby
File.open('input.bin', 'rb') do |input|
  File.open('output.rbs', 'wb') do |output|
    RbShard.pack_stream(input, output, key)
  end
end
```

`RbShard.unpack_stream` accepts input/output IO objects and authenticates each chunk before writing its plaintext.

### In-memory v2 containers

```ruby
archive = RbShard.pack('small message', key)
plaintext = RbShard.unpack(archive, key)
```

The in-memory API intentionally remains v2; large file workflows should use `pack_file` / `unpack_file`.

### Compatibility API

```ruby
encoded = RbShard.encode('legacy data', 'secretkey1234567')
decoded = RbShard.decode(encoded, 'secretkey1234567')
```

Readers understand v3, v2, v1, and headerless legacy inputs.

## Format compatibility

| Format | Read | Write | Authentication | Streaming |
| --- | --- | --- | --- | --- |
| Headerless legacy | yes | raw API | no | no |
| RBS v1 | yes | no | no | no |
| RBS v2 | yes | in-memory API | yes | no |
| RBS v3 | yes | file/stream API + CLI | yes | yes |

## Web UI

Start the experimental local interface with:

```sh
ruby bin/rbshard_ui
```

Then visit `http://127.0.0.1:4567`. The server binds to loopback by default. The web UI currently uses authenticated v2 for uploaded files; the CLI/file API is the preferred v3 path for large objects.

## Desktop UI

The optional GTK desktop interface requires:

```sh
gem install gtk3
ruby bin/rbshard_desktop
```

GTK is intentionally excluded from core runtime dependencies.

## Development

```sh
bundle install
bundle exec rake test
```

The suite includes core container tests, streaming integrity/atomicity tests, and CLI integration tests. GitHub Actions covers Ruby 3.0 through 3.4. Gem packaging is built on pull requests, while publication is restricted to published releases.

## Repository layout

```text
.github/workflows/
  ci.yml              main Ruby test matrix
  ruby.yml            compatibility matrix
  gem-push.yml        build-on-PR / publish-on-release
bin/
  rbshard             streaming CLI
  rbshard_ui          local WEBrick UI
  rbshard_desktop     optional GTK UI
lib/
  rbshard.rb           core codec + v1/v2 compatibility
  rbshard/stream.rb    streaming RBS v3 engine
  rbshard/version.rb   gem version
docs/
  FORMAT.md            byte-level format specification
test/
  test_rbshard.rb      core/container tests
  test_stream.rb       streaming/integrity/atomicity tests
  test_cli.rb          CLI integration tests
CHANGELOG.md           unreleased/release changes
SECURITY.md            security model and reporting guidance
```

## Roadmap

With chunked streaming implemented, the next expansion targets are **property/fuzz testing**, portable interoperability test vectors, richer authenticated metadata, resumable/parallel chunk processing, safer interactive secret entry, reproducible releases, and evaluating a modern audited cryptographic backend while retaining RBS compatibility.

See [`CHANGELOG.md`](CHANGELOG.md) for the current unreleased work.
