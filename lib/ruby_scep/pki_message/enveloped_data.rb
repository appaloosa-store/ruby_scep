# frozen_string_literal: true
module RubyScep
  class PkiMessage
    class EnvelopedData

      def initialize(p7, encryption_key, encryption_iv, encrypted_payload)
        @p7 = p7
        @encryption_key = encryption_key
        @encryption_iv = encryption_iv
        @encrypted_payload = encrypted_payload
      end

      def to_der
        OpenSSL::ASN1::Sequence.new(
          [
            OpenSSL::ASN1::ObjectId.new(OID_ENVELOPED_DATA),
            OpenSSL::ASN1::ASN1Data.new(
              [
                OpenSSL::ASN1::Sequence.new(
                  [
                    OpenSSL::ASN1::Integer.new(0),
                    OpenSSL::ASN1::Set.new(
                      [
                        OpenSSL::ASN1::Sequence.new(
                          [
                            OpenSSL::ASN1::Integer.new(0),
                            OpenSSL::ASN1::Sequence.new(
                              [
                                OpenSSL::ASN1::decode(@p7.certificates.first.subject.to_der),
                                OpenSSL::ASN1::Integer.new(@p7.certificates.first.serial.to_i)
                              ]
                            ),
                            OpenSSL::ASN1::Sequence.new(
                              [
                                OpenSSL::ASN1::ObjectId.new(OID_RSA_ENCRYPTION),
                                OpenSSL::ASN1::Null.new(nil)
                              ]
                            ),
                            OpenSSL::ASN1::OctetString.new(@p7.certificates.first.public_key.public_encrypt(@encryption_key))
                          ]
                        )
                      ]
                    ),
                    OpenSSL::ASN1::Sequence.new(
                      [
                        OpenSSL::ASN1::ObjectId.new(OID_DATA),
                        OpenSSL::ASN1::Sequence.new(
                          [
                            OpenSSL::ASN1::ObjectId.new(OID_DES_ALGO),
                            OpenSSL::ASN1::OctetString.new(@encryption_iv)
                          ]
                        ),
                        OpenSSL::ASN1::ASN1Data.new(@encrypted_payload, 0, :CONTEXT_SPECIFIC)
                      ]
                    )
                  ]
                )
              ],
              0,
              :CONTEXT_SPECIFIC
            )
          ]
        ).to_der
      end
    end
  end
end