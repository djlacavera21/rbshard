# rbshard

rbshard 0.1.0

RbShard is a small Ruby compression and encryption toolkit. It combines a compact LZW codec with Twofish encryption and provides a versioned `.rbs` container format for storing encrypted payloads.

> **Security note:** RbShard is an experimental project, not a substitute for a professionally reviewed authenticated-encryption format. The v1 container adds corruption/wrong-key detection with SHA-256, but it does not provide cryptographic authentication against an active attacker. Do not use it as the sole protection for high-value secrets.

## Features

* Binary-safe LZW compression and decompression
* Twofish encryption and decryption
* Versioned, self-identifying `.rbs` containers
* SHA-256 plaintext integrity verification after decryption
* Legacy headerless `.rbs` read compatibility
* Convenience helpers for files and in-memory payloads
* Experimental Sinatra-style web UI and GTK desktop UI
* Minitest coverage for text, binary data, containers, corruption, and legacy files

## Container format

New files written by `save_rbs` use format version 1:

| Field | Size | Description |
| --- | ---: | --- |
| Magic | 4 bytes | ASCII `RBSH` |
| Version | 1 byte | Currently `1` |
| Payload length | 4 bytes | Little-endian encrypted payload length |
| Payload | variable | LZW-compressed data encrypted with Twofish |
| Digest | 32 bytes | SHA-256 of the original plaintext |

The header makes new archives distinguishable from older raw encrypted payloads. `load_rbs` automatically reads both formats by default.

## Usage

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
archive = RbShard.pack('classified-ish text', key)
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

## Web UI

Start the experimental web interface with:

```sh
ruby bin/rbshard_ui
```

Then visit `http://localhost:4567`. The interface supports text and file encode/decode operations and validates user-supplied keys before processing.

## Desktop UI

Start the GTK desktop application with:

```sh
ruby bin/rbshard_desktop
```

The desktop UI provides text encode/decode operations, file encryption/decryption, open/save actions, clipboard support, clearing controls, error dialogs, and status messages.

## Development

Install dependencies and run the test suite:

```sh
bundle install
bundle exec ruby -Itest test/test_rbshard.rb
```

The core library intentionally has a small public API. Changes to the on-disk container should introduce a new `FORMAT_VERSION` and retain an explicit migration/read path for older versions whenever practical.

## Roadmap

Good next steps include replacing the v1 digest-only integrity scheme with a standard authenticated-encryption construction, streaming large files instead of buffering them entirely in memory, adding a command-line interface, fuzz/property tests for the LZW decoder and container parser, and publishing a formal format specification with test vectors.
