require 'minitest/autorun'
require_relative '../lib/rbshard'

class RbShardTest < Minitest::Test
  def test_round_trip
    data = 'Hello rbshard!'
    key = 'secretkey1234567'
    encoded = RbShard.encode(data, key)
    decoded = RbShard.decode(encoded, key)
    assert_equal data, decoded
  end
end
