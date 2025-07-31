# rbshard

rbshard 0.1.0

RbShard provides simple compression and encryption utilities built in Ruby.
Compression is performed with a minimal LZW implementation and data is
encrypted using the Twofish cipher. Files stored with the `.rbs` extension
contain compressed and encrypted payloads.

## Features

* LZW based compression and decompression
* Twofish encryption and decryption
* Convenience helpers to read and write `.rbs` files

## Usage

```
require 'rbshard'

data = 'Hello rbshard!'
key = 'secretkey1234567'

# Encode and save a file
RbShard.save_rbs('message.rbs', data, key)

# Load and decode
original = RbShard.load_rbs('message.rbs', key)
puts original # => "Hello rbshard!"
```

Development is experimental and feedback is welcome.
