require_relative 'lib/rbshard/version'
Gem::Specification.new do |spec|
  spec.name          = 'rbshard'
  spec.version       = RbShard::VERSION
  spec.authors       = ['Unknown']
  spec.email         = ['unknown@example.com']
  spec.summary       = 'Compression and encryption toolkit'
  spec.files         = Dir['lib/**/*'] + ['README.md', 'LICENSE']
  spec.require_paths = ['lib']
  spec.add_runtime_dependency 'twofish', '~> 1.0'
end
