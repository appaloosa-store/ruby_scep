# frozen_string_literal: true
require 'spec_helper'

describe RubyScep::PkiOperation do
  describe 'parse_pki_message' do
    let(:transaction_id) { SecureRandom.hex }
    let(:sender_nonce) { [SecureRandom.hex].pack('H*') }
    let(:cert_subject) { 'CN=MDM SCEP SIGNER/C=US' }
    let(:cert_serial) { 123 }
    let(:csr) do
      Factories.build(
        :raw_csr,
        transaction_id: transaction_id,
        sender_nonce: sender_nonce,
        cert_subject: cert_subject,
        cert_serial: cert_serial
      )
    end
    let(:cert_store) do
      store = OpenSSL::X509::Store.new
      store.add_cert RubyScep.configuration.ca
    end

    subject { RubyScep::PkiOperation.send(:parse_pki_message, csr) }

    it { is_expected.to be_a(RubyScep::PkiMessage) }
    it { expect(subject.instance_variable_get(:@message_type)).to eq 'PKCSReq' }
    it { expect(subject.instance_variable_get(:@transaction_id)).to eq transaction_id }
    it { expect(subject.instance_variable_get(:@sender_nonce)).to eq sender_nonce }
    it { expect(subject.instance_variable_get(:@p7).signers.first.name).to eq OpenSSL::X509::Name.parse(cert_subject) }
    it { expect(subject.instance_variable_get(:@p7).signers.first.serial).to eq cert_serial }
    it { expect(OpenSSL::PKCS7.new(csr).verify([RubyScep.configuration.ca], cert_store, nil, OpenSSL::PKCS7::NOVERIFY)).to eq true }
  end

  describe 'decrypt_pki_envelope' do
    let(:csr_subject) { '/CN=SUBJECT SIGNER/C=ME' }
    let(:csr_private_key) { OpenSSL::PKey::RSA.new 2048 }
    let(:pki_message) { Factories.build(:pki_message, csr_subject: csr_subject, csr_private_key: csr_private_key) }

    subject { RubyScep::PkiOperation.send(:decrypt_pki_envelope, pki_message) }

    its('subject.to_s') { is_expected.to eq csr_subject }
    its(:version) { is_expected.to eq 0 }
    its(:signature_algorithm) { is_expected.to eq 'sha1WithRSAEncryption' }
    it { expect(subject.verify(csr_private_key)).to eq true }
    it { is_expected.to be_a(OpenSSL::X509::Request) }
  end
end