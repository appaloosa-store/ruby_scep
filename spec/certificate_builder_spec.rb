# frozen_string_literal: true
require 'spec_helper'
require 'timecop'

describe RubyScep::CertificateBuilder do
  describe 'build' do
    before(:all) { Timecop.freeze(Time.now) }

    let(:decrypted_csr) { Factories.build(:decrypted_csr, raw_csr: Factories.build(:raw_csr)) }

    subject { RubyScep::CertificateBuilder.build(decrypted_csr) }

    its(:version) { is_expected.to eq 1 }
    its('public_key.to_s') { is_expected.to eq decrypted_csr.public_key.to_s }
    its(:issuer) { is_expected.to eq RubyScep.configuration.ca.subject }
    its(:subject) { is_expected.to eq decrypted_csr.subject }
    its('not_before.utc') { is_expected.to be_within(1).of(Time.now.utc) }
    its('not_after.utc') { is_expected.to be_within(1).of((Time.now + 31536000).utc) }
    its('extensions.first.value') { is_expected.to eq 'Digital Signature, Key Encipherment' }

    after(:all) { Timecop.return }
  end
end