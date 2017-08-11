# frozen_string_literal: true
require 'rspec'
require 'rspec/its'
require_relative '../lib/ruby_scep'
require 'factories'

RubyScep.configure do |config|
  config.ca_cert_path = 'spec/fixtures/certs/ca.pem'
  config.ca_key_path = 'spec/fixtures/certs/passwordless.key'
end