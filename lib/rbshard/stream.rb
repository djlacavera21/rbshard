# frozen_string_literal: true

require 'stringio'

module RbShard
  STREAM_FORMAT_VERSION = 3
  V3_SALT_SIZE = 16
  V3_HEADER_SIZE = 29
  V3_CHUNK_MARKER = "CHNK".b.freeze
  V3_FOOTER_MARKER = "END!".b.freeze
  V3_RECORD_HEADER_SIZE = 32
  V3_TAG_SIZE = 32
  V3_FOOTER_SIZE = 48
  V3_DEFAULT_CHUNK_SIZE = 1024 * 1024
  V3_MIN_CHUNK_SIZE = 1024
  V3_MAX_CHUNK_SIZE = 64 * 1024 * 1024

  # Stream a file/IO into an authenticated RBS v3 container. Memory use is
  # bounded by roughly one plaintext chunk, one compressed chunk, and one
  # ciphertext chunk instead of the entire input file.
  def self.pack_stream(input_io, output_io, key, chunk_size: V3_DEFAULT_CHUNK_SIZE, kdf_iterations: V2_KDF_ITERATIONS)
    validate_password!(key)
    validate_iterations!(kdf_iterations)
    validate_chunk_size!(chunk_size)

    salt = SecureRandom.random_bytes(V3_SALT_SIZE)
    encryption_key, authentication_key = derive_v2_keys(key, salt, kdf_iterations)
    header = MAGIC + [STREAM_FORMAT_VERSION, kdf_iterations, chunk_size].pack('CL<L<') + salt
    output_io.write(header)

    final_mac = OpenSSL::HMAC.new(authentication_key, OpenSSL::Digest.new('SHA256'))
    final_mac.update(header)

    chunk_index = 0
    total_plaintext = 0

    loop do
      plaintext = input_io.read(chunk_size)
      break if plaintext.nil? || plaintext.empty?

      plaintext = plaintext.b
      compressed = LZW.compress(plaintext)
      iv = SecureRandom.random_bytes(V2_IV_SIZE)
      ciphertext = encrypt_cbc(compressed, encryption_key, iv)
      record_header = V3_CHUNK_MARKER +
                      [chunk_index, plaintext.bytesize, ciphertext.bytesize].pack('L<L<L<') +
                      iv
      tag = OpenSSL::HMAC.digest('SHA256', authentication_key, header + record_header + ciphertext)

      output_io.write(record_header)
      output_io.write(ciphertext)
      output_io.write(tag)
      final_mac.update(tag)

      total_plaintext += plaintext.bytesize
      chunk_index += 1
    end

    footer_metadata = V3_FOOTER_MARKER + [chunk_index, total_plaintext].pack('L<Q<')
    final_mac.update(footer_metadata)
    output_io.write(footer_metadata)
    output_io.write(final_mac.digest)

    {
      format: :container,
      version: STREAM_FORMAT_VERSION,
      streaming: true,
      authenticated: true,
      chunk_size: chunk_size,
      chunk_count: chunk_index,
      plaintext_bytes: total_plaintext,
      kdf_iterations: kdf_iterations
    }
  end

  # Verify and decrypt an RBS v3 stream. Each chunk is authenticated before it
  # is decrypted and emitted. The final footer authenticates the ordered list
  # of chunk tags plus aggregate counts, detecting truncation or reordering.
  def self.unpack_stream(input_io, output_io, key)
    validate_password!(key)
    header = read_exact(input_io, V3_HEADER_SIZE, 'RBS v3 header')
    raise FormatError, 'Invalid RbShard magic header' unless header.start_with?(MAGIC)

    version, kdf_iterations, chunk_size = header.byteslice(4, 9).unpack('CL<L<')
    raise FormatError, "Unsupported RbShard streaming format version: #{version}" unless version == STREAM_FORMAT_VERSION
    validate_iterations!(kdf_iterations)
    validate_chunk_size!(chunk_size)

    salt = header.byteslice(13, V3_SALT_SIZE)
    encryption_key, authentication_key = derive_v2_keys(key, salt, kdf_iterations)
    final_mac = OpenSSL::HMAC.new(authentication_key, OpenSSL::Digest.new('SHA256'))
    final_mac.update(header)

    expected_index = 0
    total_plaintext = 0

    loop do
      marker = read_exact(input_io, 4, 'RBS v3 record marker')

      case marker
      when V3_CHUNK_MARKER
        remainder = read_exact(input_io, V3_RECORD_HEADER_SIZE - 4, 'RBS v3 chunk header')
        record_header = marker + remainder
        index, plaintext_length, ciphertext_length = remainder.byteslice(0, 12).unpack('L<L<L<')
        iv = remainder.byteslice(12, V2_IV_SIZE)

        raise FormatError, "Unexpected chunk index #{index}; expected #{expected_index}" unless index == expected_index
        unless plaintext_length.positive? && plaintext_length <= chunk_size
          raise FormatError, 'RBS v3 chunk plaintext length is outside the accepted range'
        end

        max_ciphertext = (plaintext_length * 2) + 16
        unless ciphertext_length.positive? && ciphertext_length <= max_ciphertext
          raise FormatError, 'RBS v3 chunk ciphertext length is outside the accepted range'
        end

        ciphertext = read_exact(input_io, ciphertext_length, 'RBS v3 chunk ciphertext')
        expected_tag = read_exact(input_io, V3_TAG_SIZE, 'RBS v3 chunk authentication tag')
        actual_tag = OpenSSL::HMAC.digest('SHA256', authentication_key, header + record_header + ciphertext)
        raise IntegrityError, 'Chunk authentication failed; the key may be wrong or the file may be corrupted' unless secure_compare(actual_tag, expected_tag)

        compressed = decrypt_cbc(ciphertext, encryption_key, iv)
        plaintext = LZW.decompress(compressed)
        raise IntegrityError, 'Authenticated chunk plaintext length does not match its record' unless plaintext.bytesize == plaintext_length

        output_io.write(plaintext)
        final_mac.update(expected_tag)
        total_plaintext += plaintext_length
        expected_index += 1
      when V3_FOOTER_MARKER
        footer_remainder = read_exact(input_io, V3_FOOTER_SIZE - 4, 'RBS v3 footer')
        chunk_count, declared_plaintext = footer_remainder.byteslice(0, 12).unpack('L<Q<')
        expected_final_tag = footer_remainder.byteslice(12, V3_TAG_SIZE)
        footer_metadata = marker + footer_remainder.byteslice(0, 12)

        raise FormatError, 'RBS v3 footer chunk count does not match decoded records' unless chunk_count == expected_index
        raise FormatError, 'RBS v3 footer plaintext length does not match decoded records' unless declared_plaintext == total_plaintext

        final_mac.update(footer_metadata)
        actual_final_tag = final_mac.digest
        raise IntegrityError, 'Final stream authentication failed; the archive may be truncated or reordered' unless secure_compare(actual_final_tag, expected_final_tag)
        raise FormatError, 'Trailing data found after RBS v3 footer' unless input_io.read(1).nil?

        return {
          format: :container,
          version: STREAM_FORMAT_VERSION,
          streaming: true,
          authenticated: true,
          chunk_size: chunk_size,
          chunk_count: chunk_count,
          plaintext_bytes: declared_plaintext,
          kdf_iterations: kdf_iterations
        }
      else
        raise FormatError, "Invalid RBS v3 record marker: #{marker.inspect}"
      end
    end
  rescue IntegrityError, FormatError
    raise
  rescue StandardError => e
    raise IntegrityError, "Unable to decode RbShard v3 stream: #{e.message}"
  end

  def self.pack_file(input_path, output_path, key, chunk_size: V3_DEFAULT_CHUNK_SIZE, kdf_iterations: V2_KDF_ITERATIONS)
    File.open(input_path, 'rb') do |input|
      File.open(output_path, 'wb') do |output|
        pack_stream(input, output, key, chunk_size: chunk_size, kdf_iterations: kdf_iterations)
      end
    end
  end

  # File-oriented unpacking commits plaintext atomically. A failed footer/tag
  # never leaves a partially verified destination file behind.
  def self.unpack_file(input_path, output_path, key, allow_legacy: true)
    File.open(input_path, 'rb') do |input|
      prefix = input.read(5)
      input.rewind

      if prefix&.start_with?(MAGIC) && prefix.getbyte(4) == STREAM_FORMAT_VERSION
        atomic_output(output_path) do |output|
          unpack_stream(input, output, key)
        end
      else
        plaintext = load_rbs(input_path, key, allow_legacy: allow_legacy)
        atomic_output(output_path) { |output| output.write(plaintext) }
      end
    end
  end

  def self.inspect_rbs_file(path)
    total_bytes = File.size(path)
    File.open(path, 'rb') do |io|
      prefix = io.read(5)
      return { format: :legacy, version: nil, payload_bytes: total_bytes, total_bytes: total_bytes } unless prefix&.start_with?(MAGIC)

      version = prefix.getbyte(4)
      io.rewind
      case version
      when 1
        header = read_exact(io, V1_HEADER_SIZE, 'RBS v1 header')
        encrypted_length = header.byteslice(5, 4).unpack1('L<')
        {
          format: :container, version: 1, authenticated: false,
          payload_bytes: encrypted_length, total_bytes: total_bytes
        }
      when 2
        header = read_exact(io, V2_HEADER_SIZE, 'RBS v2 header')
        _version, kdf_iterations = header.byteslice(4, 5).unpack('CL<')
        encrypted_length = header.byteslice(41, 4).unpack1('L<')
        {
          format: :container, version: 2, streaming: false, authenticated: true,
          kdf: :'pbkdf2-hmac-sha256', kdf_iterations: kdf_iterations,
          cipher: :'twofish-cbc', payload_bytes: encrypted_length, total_bytes: total_bytes
        }
      when STREAM_FORMAT_VERSION
        header = read_exact(io, V3_HEADER_SIZE, 'RBS v3 header')
        _version, kdf_iterations, chunk_size = header.byteslice(4, 9).unpack('CL<L<')
        validate_iterations!(kdf_iterations)
        validate_chunk_size!(chunk_size)

        metadata = {
          format: :container, version: STREAM_FORMAT_VERSION, streaming: true,
          authenticated: true, kdf: :'pbkdf2-hmac-sha256',
          kdf_iterations: kdf_iterations, cipher: :'twofish-cbc',
          chunk_size: chunk_size, total_bytes: total_bytes
        }

        if total_bytes >= V3_HEADER_SIZE + V3_FOOTER_SIZE
          io.seek(-V3_FOOTER_SIZE, IO::SEEK_END)
          footer = io.read(V3_FOOTER_SIZE)
          if footer&.start_with?(V3_FOOTER_MARKER)
            chunk_count, plaintext_bytes = footer.byteslice(4, 12).unpack('L<Q<')
            metadata[:chunk_count] = chunk_count
            metadata[:plaintext_bytes] = plaintext_bytes
          end
        end
        metadata
      else
        { format: :container, version: version, supported: false, total_bytes: total_bytes }
      end
    end
  end

  def self.unpack_v3_bytes(bytes, key)
    input = StringIO.new(bytes.to_s.b)
    output = StringIO.new(''.b)
    unpack_stream(input, output, key)
    output.string
  end
  private_class_method :unpack_v3_bytes

  def self.inspect_v3_bytes(bytes)
    input = StringIO.new(bytes.to_s.b)
    header = read_exact(input, V3_HEADER_SIZE, 'RBS v3 header')
    _version, kdf_iterations, chunk_size = header.byteslice(4, 9).unpack('CL<L<')
    validate_iterations!(kdf_iterations)
    validate_chunk_size!(chunk_size)

    metadata = {
      format: :container, version: STREAM_FORMAT_VERSION, streaming: true,
      authenticated: true, kdf: :'pbkdf2-hmac-sha256',
      kdf_iterations: kdf_iterations, cipher: :'twofish-cbc',
      chunk_size: chunk_size, total_bytes: bytes.bytesize
    }

    if bytes.bytesize >= V3_HEADER_SIZE + V3_FOOTER_SIZE
      footer = bytes.byteslice(bytes.bytesize - V3_FOOTER_SIZE, V3_FOOTER_SIZE)
      if footer.start_with?(V3_FOOTER_MARKER)
        chunk_count, plaintext_bytes = footer.byteslice(4, 12).unpack('L<Q<')
        metadata[:chunk_count] = chunk_count
        metadata[:plaintext_bytes] = plaintext_bytes
      end
    end
    metadata
  end
  private_class_method :inspect_v3_bytes

  def self.validate_chunk_size!(chunk_size)
    unless chunk_size.is_a?(Integer) && chunk_size.between?(V3_MIN_CHUNK_SIZE, V3_MAX_CHUNK_SIZE)
      raise FormatError, "Chunk size must be between #{V3_MIN_CHUNK_SIZE} and #{V3_MAX_CHUNK_SIZE} bytes"
    end
    chunk_size
  end
  private_class_method :validate_chunk_size!

  def self.read_exact(io, length, label)
    data = ''.b
    while data.bytesize < length
      part = io.read(length - data.bytesize)
      raise FormatError, "Truncated #{label}" if part.nil? || part.empty?
      data << part.b
    end
    data
  end
  private_class_method :read_exact

  def self.atomic_output(path)
    directory = File.dirname(File.expand_path(path))
    basename = File.basename(path)
    temporary = File.join(directory, ".#{basename}.rbshard-#{Process.pid}-#{SecureRandom.hex(6)}.tmp")

    begin
      result = nil
      File.open(temporary, 'wb', 0o600) do |output|
        result = yield output
        output.flush
        output.fsync rescue nil
      end
      File.rename(temporary, path)
      result
    ensure
      File.delete(temporary) if File.exist?(temporary)
    end
  end
  private_class_method :atomic_output
end
