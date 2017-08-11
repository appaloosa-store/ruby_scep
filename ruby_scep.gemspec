# encoding: utf-8
# frozen_string_literal: true
$LOAD_PATH.unshift File.expand_path('../lib', __FILE__)
require 'ruby_scep/version'

Gem::Specification.new do |s|
  s.name = 'ruby_scep'
  s.version = RubyScep::Version::STRING
  s.platform = Gem::Platform::RUBY
  s.required_ruby_version = '>= 2.3.0'
  s.authors = ['Christophe Valentin']
  s.description = <<-EOF
   Ruby implementation of SCEP
  EOF
  s.email = 'dev@appaloosa-store.com'
  s.files = `git ls-files`.split($RS).reject do |file|
    file =~ %r{^(?:
   spec/.*
   |Gemfile
   |\.rspec
   |\.gitignore
   )$}x
  end
  s.extra_rdoc_files = %w(README.md)
  s.homepage = 'https://github.com/appaloosa-store/ruby_scep'
  s.licenses = ['MIT']
  s.require_paths = ['lib']

  s.summary = 'Ruby implementation of SCEP'

  s.add_development_dependency('rspec', '~> 3.6')
  s.add_development_dependency('rspec-its', '~> 1.2.0')
  s.add_development_dependency('timecop', '~> 0.9.1')
end