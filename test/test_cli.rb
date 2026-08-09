require 'minitest/autorun'
require 'open3'
require 'rbconfig'
require 'tmpdir'

class RbShardCLITest < Minitest::Test
  ROOT = File.expand_path('..', __dir__)
  CLI = File.join(ROOT, 'bin', 'rbshard')
  KEY = 'secretkey1234567'.freeze

  def run_cli(*args, env: {})
    Open3.capture3(env, RbConfig.ruby, CLI, *args, chdir: ROOT)
  end

  def test_version
    stdout, stderr, status = run_cli('version')
    assert status.success?, stderr
    assert_match(/\A\d+\.\d+\.\d+/, stdout)
  end

  def test_pack_inspect_and_unpack_round_trip
    Dir.mktmpdir('rbshard-cli') do |dir|
      input = File.join(dir, 'input.bin')
      archive = File.join(dir, 'archive.rbs')
      output = File.join(dir, 'output.bin')
      original = "hello\x00rbshard\xff".b
      File.binwrite(input, original)

      _stdout, stderr, status = run_cli('pack', '--key-env', 'RBSHARD_TEST_KEY', input, archive, env: { 'RBSHARD_TEST_KEY' => KEY })
      assert status.success?, stderr
      assert File.exist?(archive)

      stdout, stderr, status = run_cli('inspect', archive)
      assert status.success?, stderr
      assert_includes stdout, 'format: container'
      assert_includes stdout, 'version: 1'

      _stdout, stderr, status = run_cli('unpack', '--key-env', 'RBSHARD_TEST_KEY', archive, output, env: { 'RBSHARD_TEST_KEY' => KEY })
      assert status.success?, stderr
      assert_equal original, File.binread(output)
    end
  end

  def test_missing_key_is_reported
    Dir.mktmpdir('rbshard-cli') do |dir|
      input = File.join(dir, 'input.txt')
      output = File.join(dir, 'output.rbs')
      File.write(input, 'data')

      _stdout, stderr, status = run_cli('pack', input, output)
      refute status.success?
      assert_includes stderr, 'provide exactly one of --key, --key-env, or --key-file'
    end
  end

  def test_unpack_can_reject_legacy_payload
    Dir.mktmpdir('rbshard-cli') do |dir|
      input = File.join(dir, 'plain.txt')
      legacy = File.join(dir, 'legacy.rbs')
      output = File.join(dir, 'output.txt')
      File.write(input, 'legacy')

      _stdout, stderr, status = run_cli('encode', '--key', KEY, input, legacy)
      assert status.success?, stderr

      _stdout, stderr, status = run_cli('unpack', '--no-legacy', '--key', KEY, legacy, output)
      refute status.success?
      assert_includes stderr, 'Legacy headerless RbShard payload rejected'
    end
  end
end
