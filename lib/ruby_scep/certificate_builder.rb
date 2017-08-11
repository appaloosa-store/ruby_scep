# frozen_string_literal: true
module RubyScep
  class CertificateBuilder
    class << self
      ONE_YEAR_IN_NUMBER_OF_SECONDS = 31536000
      def build(csr)
        certificate = OpenSSL::X509::Certificate.new
        certificate.serial = Random.rand(730750818665451459101842416358141509827966271488) # will need to improve that
        certificate.version = 1
        certificate.public_key = csr.public_key
        certificate.issuer = RubyScep.configuration.ca.subject
        certificate.subject = csr.subject
        certificate.not_before = Time.now
        certificate.not_after = Time.now + ONE_YEAR_IN_NUMBER_OF_SECONDS
        extension_factory = OpenSSL::X509::ExtensionFactory.new
        extension_factory.subject_certificate = certificate
        extension_factory.subject_request = csr
        extension_factory.issuer_certificate = RubyScep.configuration.ca
        certificate.add_extension(
          extension_factory.create_extension(
            'keyUsage', 'digitalSignature,keyEncipherment'
          )
        )
        certificate
      end
    end
  end
end
