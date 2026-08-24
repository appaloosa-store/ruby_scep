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

      # RFC 7093 method 1, matching the CA and micromdm's
      # cryptoutil.GenerateSubjectKeyID, rather than OpenSSL's SHA-1 `hash`.
      it 'derives the subjectKeyIdentifier from SHA-256' do
        bit_string = OpenSSL::ASN1.decode(decrypted_csr.public_key.to_der).value[1].value
        expected = OpenSSL::Digest::SHA256.digest(bit_string)[0, 20]
                                         .unpack1('H*').upcase.scan(/../).join(':')
        expect(extensions['subjectKeyIdentifier'].value).to eq expected
      end

      it 'does not derive the subjectKeyIdentifier from SHA-1' do
        bit_string = OpenSSL::ASN1.decode(decrypted_csr.public_key.to_der).value[1].value
        sha1 = OpenSSL::Digest::SHA1.digest(bit_string).unpack1('H*').upcase.scan(/../).join(':')
        expect(extensions['subjectKeyIdentifier'].value).not_to eq sha1
      end
    end

    describe 'extensions requested by the CSR' do
      let(:factory) { OpenSSL::X509::ExtensionFactory.new }

      def csr_requesting(*requested)
        key = OpenSSL::PKey::RSA.new(2048)
        csr = OpenSSL::X509::Request.new
        csr.version = 0
        csr.subject = OpenSSL::X509::Name.parse('/CN=device-1234/O=Appaloosa')
        csr.public_key = key.public_key
        unless requested.empty?
          csr.add_attribute(
            OpenSSL::X509::Attribute.new(
              'extReq', OpenSSL::ASN1::Set.new([OpenSSL::ASN1::Sequence.new(requested)])
            )
          )
        end
        csr.sign(key, OpenSSL::Digest.new('SHA256'))
        csr
      end

      def extensions_of(csr)
        RubyScep::CertificateBuilder.build(csr)
                                    .extensions
                                    .each_with_object({}) { |e, all| (all[e.oid] ||= []) << e }
      end

      it 'carries over a requested subjectAltName' do
        found = extensions_of(
          csr_requesting(factory.create_extension('subjectAltName', 'DNS:device.example.com'))
        )
        expect(found['subjectAltName'].first.value).to eq 'DNS:device.example.com'
      end

      it 'marks a carried subjectAltName non-critical, since the subject is populated' do
        found = extensions_of(
          csr_requesting(factory.create_extension('subjectAltName', 'DNS:device.example.com', true))
        )
        expect(found['subjectAltName'].first).not_to be_critical
      end

      # The security property this allowlist exists for: a CSR will ask to
      # become a CA, and must never be granted it.
      it 'refuses a requested basicConstraints CA:TRUE' do
        found = extensions_of(
          csr_requesting(factory.create_extension('basicConstraints', 'CA:TRUE', true))
        )
        expect(found['basicConstraints'].map(&:value)).to eq ['CA:FALSE']
      end

      it 'refuses a request to widen keyUsage' do
        found = extensions_of(
          csr_requesting(factory.create_extension('keyUsage', 'keyCertSign,cRLSign', true))
        )
        expect(found['keyUsage'].map(&:value)).to eq ['Digital Signature, Key Encipherment']
      end

      it 'refuses a requested extendedKeyUsage' do
        found = extensions_of(
          csr_requesting(factory.create_extension('extendedKeyUsage', 'serverAuth'))
        )
        expect(found).not_to have_key 'extendedKeyUsage'
      end

      it 'emits one subjectAltName even when two are requested' do
        found = extensions_of(
          csr_requesting(
            factory.create_extension('subjectAltName', 'DNS:a.example.com'),
            factory.create_extension('subjectAltName', 'DNS:b.example.com')
          )
        )
        expect(found['subjectAltName'].size).to eq 1
      end

      it 'builds when the CSR requests nothing' do
        expect(extensions_of(csr_requesting)).not_to have_key 'subjectAltName'
      end
    end

    after(:all) { Timecop.return }
  end
end
