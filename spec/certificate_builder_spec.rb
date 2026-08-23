# frozen_string_literal: true
require 'spec_helper'
require 'timecop'

describe RubyScep::CertificateBuilder do
  describe 'build' do
    before(:all) { Timecop.freeze(Time.now) }

    let(:decrypted_csr) { Factories.build(:decrypted_csr, raw_csr: Factories.build(:raw_csr)) }

    subject { RubyScep::CertificateBuilder.build(decrypted_csr) }

    # 2 is X.509 v3: the version field is zero-indexed. The extensions below
    # are only legal in v3, so this and they have to move together.
    its(:version) { is_expected.to eq 2 }
    its('public_key.to_s') { is_expected.to eq decrypted_csr.public_key.to_s }
    its(:issuer) { is_expected.to eq RubyScep.configuration.ca.subject }
    its(:subject) { is_expected.to eq decrypted_csr.subject }
    its('not_before.utc') { is_expected.to be_within(1).of(Time.now.utc) }
    its('not_after.utc') { is_expected.to be_within(1).of((Time.now + 31536000).utc) }

    describe 'serial number' do
      it 'is positive' do
        expect(subject.serial.to_i).to be > 0
      end

      it 'fits in 20 octets, as RFC 5280 requires' do
        expect(subject.serial.to_i.bit_length).to be <= 160
      end

      it 'is not repeated across certificates' do
        serials = Array.new(5) { RubyScep::CertificateBuilder.build(decrypted_csr).serial.to_i }
        expect(serials.uniq.size).to eq 5
      end
    end

    describe 'extensions' do
      let(:extensions) do
        subject.extensions.each_with_object({}) { |extension, all| all[extension.oid] = extension }
      end

      it 'sets every extension a client certificate needs' do
        expect(extensions.keys).to include(
          'basicConstraints', 'keyUsage',
          'subjectKeyIdentifier', 'authorityKeyIdentifier'
        )
      end

      # Restricting EKU to clientAuth makes OpenSSL's PKCS7#verify reject the
      # certificate for S/MIME signing, which breaks how a device's signed
      # requests are authenticated. See the note in CertificateBuilder.
      it 'leaves extendedKeyUsage unset so PKCS7#verify still accepts it' do
        expect(extensions.keys).not_to include('extendedKeyUsage')
      end

      it 'is not a CA' do
        expect(extensions['basicConstraints'].value).to eq 'CA:FALSE'
        expect(extensions['basicConstraints']).to be_critical
      end

      it 'restricts key usage' do
        expect(extensions['keyUsage'].value).to eq 'Digital Signature, Key Encipherment'
        expect(extensions['keyUsage']).to be_critical
      end

      it 'carries key identifiers so chains can be built' do
        expect(extensions['subjectKeyIdentifier'].value).not_to be_empty
        expect(extensions['authorityKeyIdentifier'].value).not_to be_empty
      end
    end

    after(:all) { Timecop.return }
  end
end
