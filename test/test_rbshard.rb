require 'digest'
require 'minitest/autorun'
require 'tempfile'
require_relative '../lib/rbshard'

class RbShardTest < Minitest::Test
  KEY = 'secretkey1234567'.freeze
  FAST_KDF_ITERATIONS = 10_000

  def test_legacy_round_trip
    data = 'Hello rbshard!'
    encoded = RbShard.encode(data, KEY)
    assert_equal data, RbShard.decode(encoded, KEY)
  end

  def test_legacy_binary_round_trip
    data = (0..255).to_a.pack('C*') * 4
    assert_equal data, RbShard.decode(RbShard.encode(data, KEY), KEY)
  end

  def test_empty_lzw_round_trip
    assert_equal ''.b, RbShard::LZW.decompress(RbShard::LZW.compress(''))
  end

  def test_v2_container_round_trip
    data = "container data\x00with binary".b
    packed = RbShard.pack(data, KEY, kdf_iterations: FAST_KDF_ITERATIONS)
    metadata = RbShard.inspect_rbs(packed)

    assert RbShard.container?(packed)
    assert_equal data, RbShard.unpack(packed, KEY)
    assert_equal :container, metadata[:format]
    assert_equal 2, metadata[:version]
    assert_equal true, metadata[:authenticated]
    assert_equal :'pbkdf2-hmac-sha256', metadata[:kdf]
    assert_equal FAST_KDF_ITERATIONS, metadata[:kdf_iterations]
    assert_equal :'twofish-cbc', metadata[:cipher]
  end

  def test_v2_uses_random_salt_and_iv
    first = RbShard.pack('same data', KEY, kdf_iterations: FAST_KDF_ITERATIONS)
    second = RbShard.pack('same data', KEY, kdf_iterations: FAST_KDF_ITERATIONS)

    refute_equal first, second
    assert_equal 'same data', RbShard.unpack(first, KEY)
    assert_equal 'same data', RbShard.unpack(second, KEY)
  end

  def test_v2_detects_ciphertext_corruption_before_decryption
    packed = RbShard.pack('important data', KEY, kdf_iterations: FAST_KDF_ITERATIONS).dup
    payload_offset = RbShard::V2_HEADER_SIZE
    packed.setbyte(payload_offset, packed.getbyte(payload_offset) ^ 0xff)

    assert_raises(RbShard::IntegrityError) { RbShard.unpack(packed, KEY) }
  end

  def test_v2_detects_tag_corruption
    packed = RbShard.pack('important data', KEY, kdf_iterations: FAST_KDF_ITERATIONS).dup
    packed.setbyte(packed.bytesize - 1, packed.getbyte(packed.bytesize - 1) ^ 0xff)

    assert_raises(RbShard::IntegrityError) { RbShard.unpack(packed, KEY) }
  end

  def test_v2_rejects_wrong_key
    packed = RbShard.pack('important data', KEY, kdf_iterations: FAST_KDF_ITERATIONS)

    assert_raises(RbShard::IntegrityError) do
      RbShard.unpack(packed, 'different-password')
    end
  end

  def test_container_rejects_bad_magic
    packed = RbShard.pack('data', KEY, kdf_iterations: FAST_KDF_ITERATIONS).dup
    packed[0, 4] = 'NOPE'

    assert_raises(RbShard::FormatError) { RbShard.unpack(packed, KEY) }
  end

  def test_unpack_reads_v1_container
    plaintext = 'v1 compatibility'
    encrypted = RbShard.encode(plaintext, KEY)
    v1 = RbShard::MAGIC + [1, encrypted.bytesize].pack('CL<') + encrypted + Digest::SHA256.digest(plaintext)

    assert_equal plaintext, RbShard.unpack(v1, KEY)
    assert_equal 1, RbShard.inspect_rbs(v1)[:version]
    assert_equal false, RbShard.inspect_rbs(v1)[:authenticated]
  end

  def test_save_and_load_rbs_uses_current_container_format
    Tempfile.create(['rbshard', '.rbs']) do |file|
      RbShard.save_rbs(file.path, 'saved data', KEY, kdf_iterations: FAST_KDF_ITERATIONS)
      raw = File.binread(file.path)

      assert RbShard.container?(raw)
      assert_equal 2, RbShard.inspect_rbs(raw)[:version]
      assert_equal 'saved data', RbShard.load_rbs(file.path, KEY)
    end
  end

  def test_load_rbs_supports_legacy_payloads
    Tempfile.create(['rbshard-legacy', '.rbs']) do |file|
      File.binwrite(file.path, RbShard.encode('legacy data', KEY))
      assert_equal 'legacy data', RbShard.load_rbs(file.path, KEY)
      assert_raises(RbShard::FormatError) do
        RbShard.load_rbs(file.path, KEY, allow_legacy: false)
      end
    end
  end

  def test_legacy_key_length_is_bounded
    assert_raises(ArgumentError) { RbShard.encode('data', 'x' * 33) }
  end

  def test_v2_rejects_unreasonable_kdf_iterations
    assert_raises(RbShard::FormatError) do
      RbShard.pack('data', KEY, kdf_iterations: 999)
    end
  end
end
