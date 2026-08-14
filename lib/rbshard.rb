require 'digest'
require 'openssl'
require 'securerandom'
require 'twofish'
require_relative 'rbshard/version'

module RbShard
  MAGIC = "RBSH".b.freeze
  FORMAT_VERSION = 2

  V1_HEADER_SIZE = 9
  V1_DIGEST_SIZE = 32

  V2_SALT_SIZE = 16
  V2_IV_SIZE = 16
  V2_TAG_SIZE = 32
  V2_HEADER_SIZE = 45
  V2_KDF_ITERATIONS = 200_000
  V2_DERIVED_KEY_SIZE = 64

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

  # Legacy raw encryption API. This intentionally preserves the historical
  # default Twofish mode so existing encoded payloads remain decodable.
  def self.encrypt(data, key)
    validate_legacy_key!(key)
    cipher = Twofish.new(key, padding: Twofish::Padding::PKCS7)
    cipher.encrypt(data.to_s.b)
  end

  def self.decrypt(data, key)
    validate_legacy_key!(key)
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

  # In-memory authenticated v2 container. File-oriented callers should prefer
  # pack_file/unpack_file, which use streaming RBS v3 for bounded memory use.
  def self.pack(data, key, kdf_iterations: V2_KDF_ITERATIONS)
    validate_password!(key)
    validate_iterations!(kdf_iterations)

    plaintext = data.to_s.b
    compressed = LZW.compress(plaintext)
    salt = SecureRandom.random_bytes(V2_SALT_SIZE)
    iv = SecureRandom.random_bytes(V2_IV_SIZE)
    encryption_key, authentication_key = derive_v2_keys(key, salt, kdf_iterations)
    encrypted = encrypt_cbc(compressed, encryption_key, iv)

    header = MAGIC +
             [FORMAT_VERSION, kdf_iterations].pack('CL<') +
             salt + iv +
             [encrypted.bytesize].pack('L<')
    tag = OpenSSL::HMAC.digest('SHA256', authentication_key, header + encrypted)
    header + encrypted + tag
  end

  def self.unpack(container, key)
    bytes = container.to_s.b
    raise FormatError, 'File is too small to be an RbShard container' if bytes.bytesize < 5
    raise FormatError, 'Invalid RbShard magic header' unless bytes.start_with?(MAGIC)

    version = bytes.getbyte(MAGIC.bytesize)
    case version
    when 1 then unpack_v1(bytes, key)
    when 2 then unpack_v2(bytes, key)
    when 3 then unpack_v3_bytes(bytes, key)
    else
      raise FormatError, "Unsupported RbShard format version: #{version}"
    end
  end

  def self.container?(data)
    data.to_s.b.start_with?(MAGIC)
  end

  # Retained as an in-memory v2 helper for API compatibility. For large files,
  # use pack_file so the input is never loaded in full.
  def self.save_rbs(path, data, key, kdf_iterations: V2_KDF_ITERATIONS)
    File.binwrite(path, pack(data, key, kdf_iterations: kdf_iterations))
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
    raise FormatError, 'File is too small to contain a complete header' if bytes.bytesize < 5

    version = bytes.getbyte(MAGIC.bytesize)
    case version
    when 1
      inspect_v1(bytes)
    when 2
      inspect_v2(bytes)
    when 3
      inspect_v3_bytes(bytes)
    else
      { format: :container, version: version, supported: false, total_bytes: bytes.bytesize }
    end
  end

  def self.unpack_v1(bytes, key)
    raise FormatError, 'File is too small to be an RbShard v1 container' if bytes.bytesize < V1_HEADER_SIZE + V1_DIGEST_SIZE

    version, encrypted_length = bytes.byteslice(MAGIC.bytesize, 5).unpack('CL<')
    raise FormatError, "Unsupported RbShard format version: #{version}" unless version == 1

    expected_size = V1_HEADER_SIZE + encrypted_length + V1_DIGEST_SIZE
    raise FormatError, 'RbShard v1 container length does not match its header' unless bytes.bytesize == expected_size

    encrypted = bytes.byteslice(V1_HEADER_SIZE, encrypted_length)
    expected_digest = bytes.byteslice(V1_HEADER_SIZE + encrypted_length, V1_DIGEST_SIZE)
    plaintext = decode(encrypted, key)
    actual_digest = Digest::SHA256.digest(plaintext)
    raise IntegrityError, 'V1 integrity check failed; the key may be wrong or the file may be corrupted' unless secure_compare(actual_digest, expected_digest)

    plaintext
  rescue IntegrityError, FormatError
    raise
  rescue StandardError => e
    raise IntegrityError, "Unable to decode RbShard v1 container: #{e.message}"
  end
  private_class_method :unpack_v1

  def self.unpack_v2(bytes, key)
    validate_password!(key)
    raise FormatError, 'File is too small to be an RbShard v2 container' if bytes.bytesize < V2_HEADER_SIZE + V2_TAG_SIZE

    version, kdf_iterations = bytes.byteslice(MAGIC.bytesize, 5).unpack('CL<')
    raise FormatError, "Unsupported RbShard format version: #{version}" unless version == 2
    validate_iterations!(kdf_iterations)

    salt = bytes.byteslice(9, V2_SALT_SIZE)
    iv = bytes.byteslice(25, V2_IV_SIZE)
    encrypted_length = bytes.byteslice(41, 4).unpack1('L<')
    expected_size = V2_HEADER_SIZE + encrypted_length + V2_TAG_SIZE
    raise FormatError, 'RbShard v2 container length does not match its header' unless bytes.bytesize == expected_size

    header = bytes.byteslice(0, V2_HEADER_SIZE)
    encrypted = bytes.byteslice(V2_HEADER_SIZE, encrypted_length)
    expected_tag = bytes.byteslice(V2_HEADER_SIZE + encrypted_length, V2_TAG_SIZE)
    encryption_key, authentication_key = derive_v2_keys(key, salt, kdf_iterations)
    actual_tag = OpenSSL::HMAC.digest('SHA256', authentication_key, header + encrypted)
    raise IntegrityError, 'Authentication failed; the key may be wrong or the file may be corrupted' unless secure_compare(actual_tag, expected_tag)

    compressed = decrypt_cbc(encrypted, encryption_key, iv)
    LZW.decompress(compressed)
  rescue IntegrityError, FormatError
    raise
  rescue StandardError => e
    raise IntegrityError, "Unable to decode RbShard v2 container: #{e.message}"
  end
  private_class_method :unpack_v2

  def self.inspect_v1(bytes)
    raise FormatError, 'File is too small to contain a complete v1 header' if bytes.bytesize < V1_HEADER_SIZE
    _version, encrypted_length = bytes.byteslice(MAGIC.bytesize, 5).unpack('CL<')
    {
      format: :container,
      version: 1,
      authenticated: false,
      payload_bytes: encrypted_length,
      total_bytes: bytes.bytesize
    }
  end
  private_class_method :inspect_v1

  def self.inspect_v2(bytes)
    raise FormatError, 'File is too small to contain a complete v2 header' if bytes.bytesize < V2_HEADER_SIZE
    _version, kdf_iterations = bytes.byteslice(MAGIC.bytesize, 5).unpack('CL<')
    encrypted_length = bytes.byteslice(41, 4).unpack1('L<')
    {
      format: :container,
      version: 2,
      streaming: false,
      authenticated: true,
      kdf: :'pbkdf2-hmac-sha256',
      kdf_iterations: kdf_iterations,
      cipher: :'twofish-cbc',
      payload_bytes: encrypted_length,
      total_bytes: bytes.bytesize
    }
  end
  private_class_method :inspect_v2

  def self.derive_v2_keys(password, salt, iterations)
    material = OpenSSL::PKCS5.pbkdf2_hmac(password.to_s.b, salt, iterations, V2_DERIVED_KEY_SIZE, 'SHA256')
    [material.byteslice(0, 32), material.byteslice(32, 32)]
  end
  private_class_method :derive_v2_keys

  def self.encrypt_cbc(data, key, iv)
    cipher = Twofish.new(key, mode: :cbc, padding: Twofish::Padding::PKCS7)
    cipher.iv = iv
    cipher.encrypt(data.to_s.b)
  end
  private_class_method :encrypt_cbc

  def self.decrypt_cbc(data, key, iv)
    cipher = Twofish.new(key, mode: :cbc, padding: Twofish::Padding::PKCS7)
    cipher.iv = iv
    cipher.decrypt(data.to_s.b)
  end
  private_class_method :decrypt_cbc

  def self.validate_password!(key)
    raise ArgumentError, 'Key is required' if key.nil? || key.empty?
    key
  end
  private_class_method :validate_password!

  def self.validate_legacy_key!(key)
    validate_password!(key)
    raise ArgumentError, 'Legacy Twofish keys must be 32 bytes or fewer' if key.to_s.b.bytesize > 32
    key
  end
  private_class_method :validate_legacy_key!

  def self.validate_iterations!(iterations)
    unless iterations.is_a?(Integer) && iterations.between?(10_000, 10_000_000)
      raise FormatError, 'PBKDF2 iteration count is outside the accepted range'
    end
    iterations
  end
  private_class_method :validate_iterations!

  def self.secure_compare(left, right)
    return false unless left.bytesize == right.bytesize
    left.bytes.zip(right.bytes).reduce(0) { |memo, (a, b)| memo | (a ^ b) }.zero?
  end
  private_class_method :secure_compare
end

require_relative 'rbshard/stream'
