# frozen_string_literal: true

require 'minitest/autorun'
require 'stringio'
require 'tmpdir'
require_relative '../lib/rbshard'

class RbShardStreamTest < Minitest::Test
  KEY = 'streaming-test-password'.freeze
  FAST_KDF_ITERATIONS = 10_000
  CHUNK_SIZE = 1024

  def stream_pack(data)
    input = StringIO.new(data.b)
    output = StringIO.new(''.b)
    metadata = RbShard.pack_stream(
      input,
      output,
      KEY,
      chunk_size: CHUNK_SIZE,
      kdf_iterations: FAST_KDF_ITERATIONS
    )
    [output.string, metadata]
  end

  def test_multi_chunk_stream_round_trip
    original = ((0..255).to_a.pack('C*') * 13) + 'tail'
    archive, packed_metadata = stream_pack(original)
    restored = StringIO.new(''.b)
    unpacked_metadata = RbShard.unpack_stream(StringIO.new(archive), restored, KEY)

    assert_equal original.b, restored.string
    assert_equal 3, packed_metadata[:version]
    assert_equal 4, packed_metadata[:chunk_count]
    assert_equal packed_metadata[:chunk_count], unpacked_metadata[:chunk_count]
    assert_equal original.bytesize, unpacked_metadata[:plaintext_bytes]
  end

  def test_empty_stream_round_trip
    archive, metadata = stream_pack('')
    restored = StringIO.new(''.b)
    result = RbShard.unpack_stream(StringIO.new(archive), restored, KEY)

    assert_equal ''.b, restored.string
    assert_equal 0, metadata[:chunk_count]
    assert_equal 0, result[:plaintext_bytes]
  end

  def test_in_memory_unpack_accepts_v3
    original = 'v3 through generic unpack' * 100
    archive, = stream_pack(original)

    assert_equal original, RbShard.unpack(archive, KEY)
    metadata = RbShard.inspect_rbs(archive)
    assert_equal 3, metadata[:version]
    assert_equal true, metadata[:streaming]
  end

  def test_chunk_tampering_is_rejected
    archive, = stream_pack('A' * 3000)
    corrupted = archive.dup
    ciphertext_offset = RbShard::V3_HEADER_SIZE + RbShard::V3_RECORD_HEADER_SIZE
    corrupted.setbyte(ciphertext_offset, corrupted.getbyte(ciphertext_offset) ^ 0xff)

    assert_raises(RbShard::IntegrityError) do
      RbShard.unpack_stream(StringIO.new(corrupted), StringIO.new(''.b), KEY)
    end
  end

  def test_truncated_footer_is_rejected
    archive, = stream_pack('footer check' * 200)
    truncated = archive.byteslice(0, archive.bytesize - 10)

    assert_raises(RbShard::FormatError) do
      RbShard.unpack_stream(StringIO.new(truncated), StringIO.new(''.b), KEY)
    end
  end

  def test_file_unpack_is_atomic_on_authentication_failure
    Dir.mktmpdir('rbshard-stream') do |dir|
      input = File.join(dir, 'input.bin')
      archive = File.join(dir, 'archive.rbs')
      output = File.join(dir, 'output.bin')
      original = SecureRandom.random_bytes(5000)
      File.binwrite(input, original)
      File.binwrite(output, 'existing destination')

      RbShard.pack_file(
        input,
        archive,
        KEY,
        chunk_size: CHUNK_SIZE,
        kdf_iterations: FAST_KDF_ITERATIONS
      )

      assert_raises(RbShard::IntegrityError) do
        RbShard.unpack_file(archive, output, 'wrong-password')
      end
      assert_equal 'existing destination', File.binread(output)

      metadata = RbShard.unpack_file(archive, output, KEY)
      assert_equal original, File.binread(output)
      assert_equal 3, metadata[:version]
    end
  end

  def test_file_inspection_reads_v3_metadata_without_decryption
    Dir.mktmpdir('rbshard-inspect') do |dir|
      input = File.join(dir, 'input.bin')
      archive = File.join(dir, 'archive.rbs')
      original = 'metadata' * 1000
      File.binwrite(input, original)

      RbShard.pack_file(
        input,
        archive,
        KEY,
        chunk_size: CHUNK_SIZE,
        kdf_iterations: FAST_KDF_ITERATIONS
      )
      metadata = RbShard.inspect_rbs_file(archive)

      assert_equal 3, metadata[:version]
      assert_equal true, metadata[:streaming]
      assert_equal CHUNK_SIZE, metadata[:chunk_size]
      assert_equal original.bytesize, metadata[:plaintext_bytes]
      assert_operator metadata[:chunk_count], :>, 1
    end
  end
end
