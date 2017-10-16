# frozen_string_literal: true
require 'openssl'

module RubyScep
  class PkiMessage
    include OpenSSL::ASN1

    # get OID corresponding name http://oid-info.com/get/<the oid>
    # get possible values for a given OID in the CMS RFC https://www.ietf.org/rfc/rfc3369.txt
    OID_MESSAGE_TYPE = '2.16.840.1.113733.1.9.2'
    OID_PKI_STATUS = '2.16.840.1.113733.1.9.3'
    OID_FAIL_INFO = '2.16.840.1.113733.1.9.4'
    OID_SENDER_NONCE = '2.16.840.1.113733.1.9.5'
    OID_RECIPIENT_NOUNCE = '2.16.840.1.113733.1.9.6'
    OID_TRANSACTION_ID = '2.16.840.1.113733.1.9.7'
    OID_EXTENSION_REQUEST = '2.16.840.1.113733.1.9.8'
    OID_SIGNED_DATA = '1.2.840.113549.1.7.2'
    OID_DATA = '1.2.840.113549.1.7.1'
    OID_ENVELOPED_DATA = '1.2.840.113549.1.7.3'
    OID_RSA_ENCRYPTION = '1.2.840.113549.1.1.1'
    OID_DES_ALGO = '1.2.840.113549.3.7'
    OID_CONTENT_TYPE = '1.2.840.113549.1.9.3'
    OID_SIGNING_TIME = '1.2.840.113549.1.9.5'
    OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4'
    OID_HASH_ALGO_IDENTIFIER = '1.3.14.3.2.26'

    # complete list of possible SCEP values can be found in CISCO's documentation
    # https://www.cisco.com/c/en/us/support/docs/security-vpn/public-key-infrastructure-pki/116167-technote-scep-00.html
    SCEP_MESSAGE_TYPES = { 'PKCSReq' => 19, 'CertRep' => 3, 'GetCertInitial' => 20, 'GetCert' => 21, 'GetCRL' => 22 }
    SCEP_PKI_STATUSES = { 'SUCCESS' => 0, 'FAILURE' => 2, 'PENDING' => 3 }
    SCEP_FAIL_INFOS = { 'badAlg' => 0, 'badMessageCheck' => 1, 'badRequest' => 2, 'badTime' => 3, 'badCertId' => 4 }

    attr_accessor :p7, :device_certificate, :enrollment_response, :challenge_password

    def initialize(asn1, p7)
      signed_attributes = retrieve_signed_attributes(asn1)
      @message_type = SCEP_MESSAGE_TYPES.key(signed_attributes[OID_MESSAGE_TYPE].to_i)
      @transaction_id = signed_attributes[OID_TRANSACTION_ID]
      @sender_nonce = signed_attributes[OID_SENDER_NONCE]
      @p7 = p7
    end

    # We are building a SCEP Secure Message Object with a valid PKCS7 structure, as referenced
    #   in https://tools.ietf.org/html/draft-nourse-scep-23#section-3
    # To see a graphical representation of the final PKCS7 structure, go to
    #   https://www.cisco.com/c/dam/en/us/support/docs/security-vpn/public-key-infrastructure-pki/116167-technote-scep-00-01.jpeg
    # Structure:
    #   1. degenerate
    #     a. version
    #     b. x509
    #   2. enveloped data
    #     a. version
    #     b. list of recepients
    #     c. encrypted data (aka 1. degenerate)
    #   3. signed data
    #     a. version
    #     b. hashing algo
    #     c. signed (unencrypted) data (aka 2. enveloped data)
    #     d. ca certificate
    #     e. digital signature
    def build_enrollment_response!(csr)
      extract_challenge_password!(csr)
      generate_device_certificate!(csr)
      degenerate_sequence = build_degenerate_sequence
      enveloped_data_sequence = build_enveloped_data_sequence(degenerate_sequence)
      @enrollment_response = build_signed_data_sequence(enveloped_data_sequence)
    end

    private

    def retrieve_signed_attributes(asn1)
      # cheers AppBlade! https://github.com/AppBlade/TestHub/blob/master/app/controllers/scep_controller.rb#L92-L112
      raw_signed_attributes = asn1.value[1].value.first.value[4].first.value[3].value
      raw_signed_attributes.inject({}) do |hash, raw_signed_attribute|
        hash.merge(raw_signed_attribute.value.first.value => raw_signed_attribute.value.last.value.first.value)
      end
    end

    def extract_challenge_password!(csr)
      raw_attribute = csr.attributes.find { |a| a.oid == 'challengePassword' }
      if raw_attribute.nil?
        @challenge_password = nil
      else
        @challenge_password = raw_attribute.value.value.first.value
      end
    end

    # Generates and sets the certificate the device will use to identify itself to the MDM server.
    # The certificate will be embedded in the PKIMessage response to complete the SCEP process.
    def generate_device_certificate!(csr)
      certificate = CertificateBuilder.build(csr)
      certificate.sign(RubyScep.configuration.ca_key, OpenSSL::Digest::SHA1.new)
      @device_certificate = certificate
    end

    def build_degenerate_sequence
      PkiMessage::Degenerate.new(@device_certificate).to_der
    end

    def build_enveloped_data_sequence(degenerate_sequence)
      encrypted_payload, encryption_key, encryption_iv = encrypt_payload(degenerate_sequence)
      PkiMessage::EnvelopedData.new(@p7, encryption_key, encryption_iv, encrypted_payload).to_der
    end

    def encrypt_payload(der)
      des = OpenSSL::Cipher::Cipher.new('des-ede3-cbc')
      des.encrypt
      encryption_key = des.random_key
      encryption_iv = des.random_iv
      des.key = encryption_key
      des.iv = encryption_iv
      [des.update(der) + des.final, encryption_key, encryption_iv]
    end

    def build_signed_data_sequence(enveloped_data_sequence)
      PkiMessage::SignedData.new(
        enveloped_data_sequence,
        RubyScep.configuration.ca,
        RubyScep.configuration.ca_key,
        @sender_nonce,
        @transaction_id
      ).to_der
    end
  end
end
