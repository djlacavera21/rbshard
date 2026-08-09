require_relative 'lib/rbshard/version'

Gem::Specification.new do |spec|
  spec.name          = 'rbshard'
  spec.version       = RbShard::VERSION
  spec.authors       = ['djlacavera21']
  spec.summary       = 'Binary-safe compression and encrypted RBS container toolkit'
  spec.description   = 'RbShard provides LZW compression, authenticated versioned .rbs containers, streaming large-file workflows, file helpers, and a command-line interface.'
  spec.homepage      = 'https://github.com/djlacavera21/rbshard'
  spec.license       = 'MIT'
  spec.required_ruby_version = '>= 3.0'

  spec.metadata = {
    'source_code_uri' => spec.homepage,
    'changelog_uri' => "#{spec.homepage}/blob/main/CHANGELOG.md"
  }

  spec.files = Dir['lib/**/*', 'docs/**/*', 'bin/*'] + ['README.md', 'LICENSE', 'CHANGELOG.md', 'SECURITY.md']
  spec.bindir        = 'bin'
  spec.executables   = ['rbshard']
  spec.require_paths = ['lib']

  spec.add_runtime_dependency 'twofish', '~> 1.0'
  spec.add_runtime_dependency 'webrick', '~> 1.8'

  spec.add_development_dependency 'minitest', '~> 5'
  spec.add_development_dependency 'rake', '~> 13'
end
