require 'digest'
require 'twofish'
require_relative 'rbshard/version'

module RbShard
  MAGIC = "RBSH".b.freeze
  FORMAT_VERSION = 1
  HEADER_SIZE = 9
  DIGEST_SIZE = 32

  class Error < StandardError; end
  class FormatError < Error; end
  class IntegrityError < Error; end

  class LZW
    MAX_CODE = 0xffff

    def self.compress(input)
      input = input.to_s.b
      return ''.b if input.empty?

      dict_size = 256
      dictionary = Hash[Array(0..255).map { |i| [i.chr(Encoding::BINARY), i] }]
      w = ''.b
      result = []

      input.each_byte do |byte|
        c = byte.chr(Encoding::BINARY)
        wc = w + c
        if dictionary.key?(wc)
          w = wc
        else
          result << dictionary.fetch(w)
          if dict_size <= MAX_CODE
            dictionary[wc] = dict_size
            dict_size += 1
          end
          w = c
        end
      end

      result << dictionary.fetch(w) unless w.empty?
      result.pack('S<*')
    end

    def self.decompress(compressed)
      compressed = compressed.to_s.b
      return ''.b if compressed.empty?
      raise FormatError, 'Compressed payload has an invalid length' if compressed.bytesize.odd?

      compressed_codes = compressed.unpack('S<*')
      dict_size = 256
      dictionary = Hash[Array(0..255).map { |i| [i, i.chr(Encoding::BINARY)] }]
      first = compressed_codes.shift
      w = dictionary[first]
      raise FormatError, "Invalid initial LZW code: #{first}" unless w

      result = w.dup
      compressed_codes.each do |code|
        entry = dictionary[code] || (code == dict_size ? w + w.byteslice(0, 1) : nil)
        raise FormatError, "Invalid LZW code: #{code}" unless entry

        result << entry
        if dict_size <= MAX_CODE
          dictionary[dict_size] = w + entry.byteslice(0, 1)
          dict_size += 1
        end
        w = entry
      end
      result
    end
  end

  def self.encrypt(data, key)
    validate_key!(key)
    cipher = Twofish.new(key, padding: Twofish::Padding::PKCS7)
    cipher.encrypt(data.to_s.b)
  end

  def self.decrypt(data, key)
    validate_key!(key)
    cipher = Twofish.new(key, padding: Twofish::Padding::PKCS7)
    cipher.decrypt(data.to_s.b)
  rescue StandardError => e
    raise IntegrityError, "Unable to decrypt payload: #{e.message}"
  end

  # Legacy raw codec retained for API compatibility.
  def self.encode(data, key)
    encrypt(LZW.compress(data), key)
  end

  def self.decode(data, key)
    LZW.decompress(decrypt(data, key))
  end

  # Versioned .rbs container:
  # magic(4) + version(1) + encrypted_length(4 LE) + encrypted_payload + sha256(32)
  # The digest covers the original plaintext and provides deterministic detection
  # of corruption or an incorrect key after decryption.
  def self.pack(data, key)
    plaintext = data.to_s.b
    encrypted = encode(plaintext, key)
    header = MAGIC + [FORMAT_VERSION, encrypted.bytesize].pack('CL<')
    header + encrypted + Digest::SHA256.digest(plaintext)
  end

  def self.unpack(container, key)
    bytes = container.to_s.b
    raise FormatError, 'File is too small to be an RbShard container' if bytes.bytesize < HEADER_SIZE + DIGEST_SIZE
    raise FormatError, 'Invalid RbShard magic header' unless bytes.start_with?(MAGIC)

    version, encrypted_length = bytes.byteslice(MAGIC.bytesize, 5).unpack('CL<')
    raise FormatError, "Unsupported RbShard format version: #{version}" unless version == FORMAT_VERSION

    expected_size = HEADER_SIZE + encrypted_length + DIGEST_SIZE
    raise FormatError, 'RbShard container length does not match its header' unless bytes.bytesize == expected_size

    encrypted = bytes.byteslice(HEADER_SIZE, encrypted_length)
    expected_digest = bytes.byteslice(HEADER_SIZE + encrypted_length, DIGEST_SIZE)
    plaintext = decode(encrypted, key)
    actual_digest = Digest::SHA256.digest(plaintext)
    raise IntegrityError, 'Integrity check failed; the key may be wrong or the file may be corrupted' unless secure_compare(actual_digest, expected_digest)

    plaintext
  rescue IntegrityError, FormatError
    raise
  rescue StandardError => e
    raise IntegrityError, "Unable to decode RbShard container: #{e.message}"
  end

  def self.container?(data)
    data.to_s.b.start_with?(MAGIC)
  end

  def self.save_rbs(path, data, key)
    File.binwrite(path, pack(data, key))
  end

  def self.load_rbs(path, key, allow_legacy: true)
    data = File.binread(path)
    return unpack(data, key) if container?(data)
    return decode(data, key) if allow_legacy

    raise FormatError, 'Legacy headerless RbShard payload rejected'
  end

  def self.inspect_rbs(data)
    bytes = data.to_s.b
    return { format: :legacy, version: nil, payload_bytes: bytes.bytesize } unless container?(bytes)
    raise FormatError, 'File is too small to contain a complete header' if bytes.bytesize < HEADER_SIZE

    version, encrypted_length = bytes.byteslice(MAGIC.bytesize, 5).unpack('CL<')
    {
      format: :container,
      version: version,
      payload_bytes: encrypted_length,
      total_bytes: bytes.bytesize
    }
  end

  def self.validate_key!(key)
    raise ArgumentError, 'Key is required' if key.nil? || key.empty?
    key
  end
  private_class_method :validate_key!

  def self.secure_compare(left, right)
    return false unless left.bytesize == right.bytesize
    left.bytes.zip(right.bytes).reduce(0) { |memo, (a, b)| memo | (a ^ b) }.zero?
  end
  private_class_method :secure_compare
end
