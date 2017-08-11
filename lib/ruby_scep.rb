# frozen_string_literal: true
require 'ruby_scep/version'
require 'ruby_scep/configuration'
require 'ruby_scep/certificate_builder'
require 'ruby_scep/pki_message'
require 'ruby_scep/pki_message/degenerate'
require 'ruby_scep/pki_message/enveloped_data'
require 'ruby_scep/pki_message/signed_data'
require 'ruby_scep/pki_operation'

module RubyScep
  attr_accessor :configuration

  def self.configuration
    @configuration ||= Configuration.new
  end

  def self.configure
    yield(configuration)
  end
end