# frozen_string_literal: true
require 'spec_helper'

describe RubyScep::PkiMessage do
  describe 'initialize' do
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
    let(:p7) do
      p7 = OpenSSL::PKCS7.new(csr)
      flags = OpenSSL::PKCS7::BINARY | OpenSSL::PKCS7::NOVERIFY
      p7.verify(nil, RubyScep.configuration.certificates_store, nil, flags)
      p7
    end
    let(:asn1) { OpenSSL::ASN1.decode(p7.to_der) }
    let(:cert_store) do
      store = OpenSSL::X509::Store.new
      store.add_cert RubyScep.configuration.ca
    end

    subject { RubyScep::PkiMessage.new(asn1, p7) }

    it { is_expected.to be_a(RubyScep::PkiMessage) }
    it { expect(subject.instance_variable_get(:@message_type)).to eq 'PKCSReq' }
    it { expect(subject.instance_variable_get(:@transaction_id)).to eq transaction_id }
    it { expect(subject.instance_variable_get(:@sender_nonce)).to eq sender_nonce }
    it { expect(subject.instance_variable_get(:@p7).signers.first.name).to eq OpenSSL::X509::Name.parse(cert_subject) }
    it { expect(subject.instance_variable_get(:@p7).signers.first.serial).to eq cert_serial }
  end

  describe 'build_enrollement_response' do
    require 'timecop'

    let(:cert_private_key) { OpenSSL::PKey::RSA.new 2048 }
    let(:csr_private_key) { OpenSSL::PKey::RSA.new 2048 }
    let(:transaction_id) { SecureRandom.hex }
    let(:sender_nonce) { [SecureRandom.hex].pack('H*') }
    let(:pki_message) do
      Factories.build(
        :pki_message,
        cert_private_key: cert_private_key,
        csr_private_key: csr_private_key,
        cert_subject: 'CN=GOOD SUBJECT/C=FR',
        transaction_id: transaction_id,
        sender_nonce: sender_nonce
      )
    end
    let(:csr) { Factories.build(:decrypted_csr, pki_message: pki_message) }
    let(:cert_store) do
      store = OpenSSL::X509::Store.new
      store.add_cert RubyScep.configuration.ca
    end

    before(:all) { Timecop.freeze(Time.now) }

    it 'should generate a valid response with the SCEP attributes expected by an iDevice' do
      pki_message.build_enrollment_response!(csr)
      response = pki_message.enrollment_response
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

    it 'should set @enrollment_response and @device_certificate' do
      pki_message.build_enrollment_response!(csr)
      expect(pki_message.enrollment_response).not_to be_nil
      expect(pki_message.device_certificate).not_to be_nil
    end

    after(:all) { Timecop.return }
  end
end
