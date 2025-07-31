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

## Web UI

An experimental web interface is provided to quickly try out encoding and
decoding operations. Start the server with:

```
ruby bin/rbshard_ui
```

Then visit `http://localhost:4567` in your browser to access forms for encoding
and decoding text using a secret key. Keys must be at least eight characters
long. You can paste text directly or upload files to encode and decode. The
interface escapes displayed results for better security and will return encoded
or decoded files for download when using the upload options.
Feedback is welcome as the UI continues to evolve.

## Desktop UI

You can also use a simple GTK-based desktop application to run encode and
decode operations locally:

```
ruby bin/rbshard_desktop
```

This opens a window with text areas for input and results along with an entry
field for your secret key. A simple menu provides options to open files for
encoding, save results to disk and quit the application. Additional menu items
allow encrypting and decrypting arbitrary files such as PDFs or text documents
directly to and from `.rbs` archives. Keys must be at least eight characters
long and invalid operations will show an error dialog.
