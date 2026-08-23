# frozen_string_literal: true
require 'securerandom'

module RubyScep
  class CertificateBuilder
    ONE_YEAR_IN_NUMBER_OF_SECONDS = 31_536_000

    # Serial numbers must be positive and fit in 20 octets (RFC 5280 4.1.2.2).
    SERIAL_BITS = 159

    class << self
      # @param csr [OpenSSL::X509::Request] the decrypted certificate request
      # @return [OpenSSL::X509::Certificate] an unsigned certificate
      def build(csr)
        ca = RubyScep.configuration.ca
        now = Time.now

        certificate = OpenSSL::X509::Certificate.new
        # 2 means X.509 v3: the version field is zero-indexed, and the
        # extensions added below are only legal in v3.
        certificate.version = 2
        certificate.serial = generate_serial
        certificate.public_key = csr.public_key
        certificate.issuer = ca.subject
        certificate.subject = csr.subject
        certificate.not_before = now
        certificate.not_after = now + ONE_YEAR_IN_NUMBER_OF_SECONDS

        add_extensions(certificate, csr, ca)

        certificate
      end

      private

      def add_extensions(certificate, csr, ca)
        factory = OpenSSL::X509::ExtensionFactory.new
        factory.subject_certificate = certificate
        factory.subject_request = csr
        factory.issuer_certificate = ca

        certificate.add_extension(factory.create_extension('basicConstraints', 'CA:FALSE', true))
        certificate.add_extension(
          factory.create_extension('keyUsage', 'digitalSignature,keyEncipherment', true)
        )
        # No extendedKeyUsage here, deliberately. Restricting EKU to clientAuth
        # makes OpenSSL's PKCS7#verify reject the certificate for S/MIME
        # signing, which is the purpose it checks by default -- and that is how
        # a device's signed requests are authenticated. Adding it requires the
        # verifying side to set `store.purpose = OpenSSL::X509::PURPOSE_ANY`
        # first, which keeps chain validation while dropping the purpose check.
        certificate.add_extension(factory.create_extension('subjectKeyIdentifier', 'hash'))
        certificate.add_extension(factory.create_extension('authorityKeyIdentifier', 'keyid,issuer'))
      end

      # SecureRandom rather than Random: Random is a Mersenne Twister, so its
      # output is predictable from observed serials. random_number can return 0,
      # which is not a valid serial.
      def generate_serial
        SecureRandom.random_number((1 << SERIAL_BITS) - 1) + 1
      end
    end
  end
end
