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

    it do
      response = pki_message.build_enrollment_response(csr)
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

    after(:all) { Timecop.return }
  end

  def signed_attributes_from_asn1(asn1)
    # enveloped_data_sequence = OpenSSL::ASN1.decode(der.value[1].value.first.value[2].value[1].value.first.value)
    # publicly_encrypted_encryption_key = enveloped_data_sequence.value[1].value.first.value[1].value.first.value[3].value
    # encryption_key = cert.private_decrypt(publicly_encrypted_encryption_key)
    # encryption_iv = enveloped_data_sequence.value[1].value.first.value[2].value[1].value[1].value
    # des = OpenSSL::Cipher::Cipher.new('des-ede3-cbc')
    # des.decrypt
    # des.key = encryption_key
    # des.iv = encryption_iv
    # encrypted_payload = enveloped_data_sequence.value[1].value.first.value[2].value[2].value
    # payload = des.update(encrypted_payload) + des.final
    # degenerate_sequence = OpenSSL::ASN1.decode(payload)
    # certificate = degenerate_sequence.value[1].value.first.value[3].value.first
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
end
