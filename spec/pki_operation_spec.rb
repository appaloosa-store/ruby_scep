# frozen_string_literal: true
require 'spec_helper'

describe RubyScep::PkiOperation do
  describe 'build_response' do
    let(:transaction_id) { SecureRandom.hex }
    let(:sender_nonce) { [SecureRandom.hex].pack('H*') }
    let(:cert_subject) { 'CN=MDM SCEP SIGNER/C=US' }
    let(:cert_serial) { 123 }
    let(:raw_csr) do
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

    subject { RubyScep::PkiOperation.build_response(raw_csr) }

    it { expect(subject.device_certificate.verify(RubyScep.configuration.ca_key)).to eq true }
    it { expect(subject.device_certificate.serial).not_to eq '' }
    it do
      response = subject.enrollment_response
      p7 = OpenSSL::PKCS7.new(response)
      asn1 = OpenSSL::ASN1.decode(p7)
      attributes = signed_attributes_from_asn1(asn1)
      expect(p7.verify([RubyScep.configuration.ca], cert_store, nil, OpenSSL::PKCS7::NOVERIFY)).to eq true
      expect(attributes[:content_type]).to eq 'pkcs7-data'
      expect(attributes[:signing_time]).to be_within(1).of(Time.now)
      expect(attributes[:message_type]).to eq RubyScep::PkiMessage::SCEP_MESSAGE_TYPES['CertRep'].to_s
      expect(attributes[:pki_status]).to eq RubyScep::PkiMessage::SCEP_PKI_STATUSES['SUCCESS'].to_s
      expect(attributes[:sender_nonce]).not_to eq ''
      expect(attributes[:sender_nonce]).to eq attributes[:recipient_nonce]
      expect(attributes[:recipient_nonce]).to eq attributes[:sender_nonce]
      expect(attributes[:transaction_id]).to eq transaction_id
    end
  end

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