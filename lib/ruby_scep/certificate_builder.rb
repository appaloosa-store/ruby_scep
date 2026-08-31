# frozen_string_literal: true
require 'securerandom'

module RubyScep
  class CertificateBuilder
    ONE_YEAR_IN_NUMBER_OF_SECONDS = 31_536_000

    # Serial numbers must be positive and fit in 20 octets (RFC 5280 4.1.2.2).
    SERIAL_BITS = 159

    # RFC 7093 method 1 truncates the subjectKeyIdentifier to the leftmost
    # 160 bits.
    SKI_LENGTH = 20

    # Extensions a CSR is allowed to influence. A device may legitimately ask
    # for the names it will be known by; it may not ask to become a CA, nor to
    # widen its own key usage. Everything outside this list is dropped rather
    # than honoured -- a CSR requesting `basicConstraints CA:TRUE` must never
    # produce a certificate that can sign others, and it will ask.
    COPYABLE_EXTENSIONS = %w[subjectAltName].freeze

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
        certificate.add_extension(
          factory.create_extension('subjectKeyIdentifier', subject_key_identifier(certificate.public_key))
        )
        # keyid here is a copy of the issuer's own subjectKeyIdentifier, so this
        # follows whatever derivation the CA certificate used.
        certificate.add_extension(factory.create_extension('authorityKeyIdentifier', 'keyid,issuer'))

        server_set = certificate.extensions.map(&:oid)
        copyable_extensions(csr, server_set).each { |extension| certificate.add_extension(extension) }
      end

      # @param already_set [Array<String>] OIDs this builder has already decided
      def copyable_extensions(csr, already_set)
        requested_extensions(csr)
          .select { |extension| COPYABLE_EXTENSIONS.include?(extension.oid) }
          .reject { |extension| already_set.include?(extension.oid) }
          .uniq(&:oid)
          .each { |extension| extension.critical = false }
      end

      # Extensions the CSR asked for through its extensionRequest attribute.
      # A malformed attribute is ignored rather than raised on: this builder
      # decides policy, it does not validate the request.
      def requested_extensions(csr)
        attribute = csr.attributes.find do |candidate|
          %w[extReq extensionRequest msExtReq].include?(candidate.oid)
        end
        return [] if attribute.nil?

        attribute.value.value.first.value.map { |asn1| OpenSSL::X509::Extension.new(asn1) }
      rescue StandardError
        []
      end

      def generate_serial
        SecureRandom.random_number((1 << SERIAL_BITS) - 1) + 1
      end

      # RFC 7093 method 1: the leftmost 160 bits of SHA-256 over the
      # subjectPublicKey BIT STRING contents, excluding the tag, length and
      # unused-bits octet. OpenSSL's `hash` keyword would derive this with SHA-1
      # instead (RFC 5280 4.2.1.2 method 1). This matches the derivation the CA
      # uses, and micromdm's cryptoutil.GenerateSubjectKeyID.
      #
      # The BIT STRING contents are the second element of SubjectPublicKeyInfo,
      # which for RSA is the RSAPublicKey DER -- already stripped of exactly what
      # the RFC excludes.
      def subject_key_identifier(public_key)
        bit_string = OpenSSL::ASN1.decode(public_key.to_der).value[1].value
        OpenSSL::Digest::SHA256.digest(bit_string)[0, SKI_LENGTH]
                               .unpack1('H*').upcase.scan(/../).join(':')
      end
    end
  end
end
