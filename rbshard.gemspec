require_relative 'lib/rbshard/version'
Gem::Specification.new do |spec|
  spec.name          = 'rbshard'
  spec.version       = RbShard::VERSION
  spec.authors       = ['Unknown']
  spec.email         = ['unknown@example.com']
  spec.summary       = 'Compression and encryption toolkit'
  spec.files         = Dir['lib/**/*'] + ['README.md', 'LICENSE', 'bin/rbshard_desktop', 'bin/rbshard_ui']
  spec.require_paths = ['lib']
  spec.add_runtime_dependency 'twofish', '~> 1.0'
  spec.add_runtime_dependency 'gtk3', '>= 4.0'
  spec.add_development_dependency 'minitest', '~> 5'
  spec.add_development_dependency 'rake', '~> 13'
end
