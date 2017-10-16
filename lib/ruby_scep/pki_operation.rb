# frozen_string_literal: true
module RubyScep
  class PkiOperation
    class << self
      # @param raw_csr [String] The binary encoded CSR
      # @return pki_message [PkiMessage], PkiMessage with the following attributes set:
      #   @enrollment_response: represented in an OpenSSL::ASN1 structure containing the
      #     device's MDM certificate to be installed
      #   @device_certificate: the certificate the device will use to identify itself to the MDM server
      def build_response(raw_csr)
        pki_message = parse_pki_message(raw_csr)
        csr = decrypt_pki_envelope(pki_message)
        pki_message.build_enrollment_response!(csr)
        pki_message
      end

      private

      # @param raw_csr [String] The binary encoded CSR
      # @return [RubyScep::PkiMessage], containing the CSR info
      def parse_pki_message(raw_csr)
        p7 = OpenSSL::PKCS7.new(raw_csr)
        flags = OpenSSL::PKCS7::BINARY | OpenSSL::PKCS7::NOVERIFY
        # OpenSSL::PKCS7::NOVERIFY is necessary otherwise the verify step fails
        p7.verify(nil, RubyScep.configuration.certificates_store, nil, flags) # necessary to populate the p7 data field
        asn1 = OpenSSL::ASN1.decode(p7.to_der)
        PkiMessage.new(asn1, p7)
      end

      # @param pki_message [RubyScep::PkiMessage] The PkiMessage containing the CSR info sent by the iOS device
      # @return [OpenSSL::X509::Request], the decrypted CSR
      def decrypt_pki_envelope(pki_message)
        encrypted_p7 = OpenSSL::PKCS7.new(pki_message.p7.data)
        raw_csr = encrypted_p7.decrypt(RubyScep.configuration.ca_key, RubyScep.configuration.ca, OpenSSL::PKCS7::BINARY)
        OpenSSL::X509::Request.new(raw_csr)
      end
    end
  end
end
