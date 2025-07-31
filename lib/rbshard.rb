require 'twofish'
require_relative 'rbshard/version'

module RbShard
  class LZW
    def self.compress(input)
      dict_size = 256
      dictionary = Hash[Array(0..255).map { |i| [i.chr, i] }]
      w = ''
      result = []
      input.each_char do |c|
        wc = w + c
        if dictionary.key?(wc)
          w = wc
        else
          result << dictionary[w]
          dictionary[wc] = dict_size
          dict_size += 1
          w = c
        end
      end
      result << dictionary[w] unless w.empty?
      result.pack('S*')
    end

    def self.decompress(compressed)
      compressed_codes = compressed.unpack('S*')
      dict_size = 256
      dictionary = Hash[Array(0..255).map { |i| [i, i.chr] }]
      w = dictionary[compressed_codes.shift]
      result = w.dup
      compressed_codes.each do |k|
        entry = dictionary[k] || (k == dict_size ? w + w[0] : nil)
        raise "Bad compressed k: #{k}" unless entry
        result << entry
        dictionary[dict_size] = w + entry[0]
        dict_size += 1
        w = entry
      end
      result
    end
  end

  def self.encrypt(data, key)
    cipher = Twofish.new(key, padding: Twofish::Padding::PKCS7)
    cipher.encrypt(data)
  end

  def self.decrypt(data, key)
    cipher = Twofish.new(key, padding: Twofish::Padding::PKCS7)
    cipher.decrypt(data)
  end

  def self.encode(data, key)
    encrypt(LZW.compress(data), key)
  end

  def self.decode(data, key)
    LZW.decompress(decrypt(data, key))
  end

  def self.save_rbs(path, data, key)
    File.binwrite(path, encode(data, key))
  end

  def self.load_rbs(path, key)
    decode(File.binread(path), key)
  end
end
