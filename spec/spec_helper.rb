# frozen_string_literal: true
require 'rspec'
require 'rspec/its'
require_relative '../lib/ruby_scep'
require 'factories'

RubyScep.configure do |config|
  config.ca_cert_path = 'spec/fixtures/certs/ca.pem'
  config.ca_key_path = 'spec/fixtures/certs/passwordless.key'
end

def signed_attributes_from_asn1(asn1)
  signed_data_sequence = asn1.value[1].value.first.value[3].value.first.value[3].value
  values = {}
  values[:content_type] = signed_data_sequence[0].value[1].value.first.value
  values[:signing_time] = signed_data_sequence[1].value[1].value.first.value
  values[:message_digest] = signed_data_sequence[2].value[1].value.first.value
  values[:message_type] = signed_data_sequence[3].value[1].value.first.value
  values[:pki_status] = signed_data_sequence[4].value[1].value.first.value
  values[:sender_nonce] = signed_data_sequence[5].value[1].value.first.value
  values[:recipient_nonce] = signed_data_sequence[6].value[1].value.first.value
  values[:transaction_id] = signed_data_sequence[7].value[1].value.first.value
  values
end