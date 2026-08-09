require 'minitest/autorun'
require 'tempfile'
require_relative '../lib/rbshard'

class RbShardTest < Minitest::Test
  KEY = 'secretkey1234567'.freeze

  def test_round_trip
    data = 'Hello rbshard!'
    encoded = RbShard.encode(data, KEY)
    assert_equal data, RbShard.decode(encoded, KEY)
  end

  def test_binary_round_trip
    data = (0..255).to_a.pack('C*') * 4
    assert_equal data, RbShard.decode(RbShard.encode(data, KEY), KEY)
  end

  def test_empty_lzw_round_trip
    assert_equal ''.b, RbShard::LZW.decompress(RbShard::LZW.compress(''))
  end

  def test_versioned_container_round_trip
    data = "container data\x00with binary".b
    packed = RbShard.pack(data, KEY)

    assert RbShard.container?(packed)
    assert_equal data, RbShard.unpack(packed, KEY)
    assert_equal :container, RbShard.inspect_rbs(packed)[:format]
    assert_equal RbShard::FORMAT_VERSION, RbShard.inspect_rbs(packed)[:version]
  end

  def test_container_detects_corruption
    packed = RbShard.pack('important data', KEY).dup
    packed.setbyte(packed.bytesize - 1, packed.getbyte(packed.bytesize - 1) ^ 0xff)

    assert_raises(RbShard::IntegrityError) { RbShard.unpack(packed, KEY) }
  end

  def test_container_rejects_bad_magic
    packed = RbShard.pack('data', KEY).dup
    packed[0, 4] = 'NOPE'

    assert_raises(RbShard::FormatError) { RbShard.unpack(packed, KEY) }
  end

  def test_save_and_load_rbs_uses_container_format
    Tempfile.create(['rbshard', '.rbs']) do |file|
      RbShard.save_rbs(file.path, 'saved data', KEY)
      raw = File.binread(file.path)

      assert RbShard.container?(raw)
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
end
