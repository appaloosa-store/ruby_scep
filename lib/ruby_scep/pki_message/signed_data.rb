# frozen_string_literal: true
module RubyScep
  class PkiMessage
    class SignedData

      def initialize(envelop_sequence, ca, ca_key, sender_nonce, transaction_id)
        @envelop_sequence = envelop_sequence
        @ca = ca
        @ca_key = ca_key
        @sender_nonce = sender_nonce
        @transaction_id = transaction_id
        @sha1 = OpenSSL::Digest::SHA1.new
      end

      def to_der
        signed_attributes = signed_attributes_sequence
        signed_attributes_digest = @ca_key.private_encrypt(
          algo_identifier_sequence(signed_attributes, @sha1).to_der
        )
        OpenSSL::ASN1::Sequence.new(
          [
            OpenSSL::ASN1::ObjectId.new(OID_SIGNED_DATA),
            OpenSSL::ASN1::ASN1Data.new(
              [
                OpenSSL::ASN1::Sequence.new(
                  [
                    OpenSSL::ASN1::Integer.new(1),
                    OpenSSL::ASN1::Set.new(
                      [
                        OpenSSL::ASN1::Sequence.new(
                          [
                            OpenSSL::ASN1::ObjectId.new(OID_HASH_ALGO_IDENTIFIER),
                            OpenSSL::ASN1::Null.new(nil)
                          ]
                        )
                      ]
                    ),
                    OpenSSL::ASN1::Sequence.new(
                      [
                        OpenSSL::ASN1::ObjectId.new(OID_DATA),
                        OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::OctetString.new(@envelop_sequence)], 0, :CONTEXT_SPECIFIC)]
                    ),
                    OpenSSL::ASN1::Set.new(
                      [
                        OpenSSL::ASN1::Sequence.new(
                          [
                            OpenSSL::ASN1::Integer.new(1),
                            OpenSSL::ASN1::Sequence.new(
                              [
                                OpenSSL::ASN1::decode(@ca.subject.to_der),
                                OpenSSL::ASN1::Integer.new(@ca.serial)
                              ]
                            ),
                            OpenSSL::ASN1::Sequence.new(
                              [
                                OpenSSL::ASN1::ObjectId.new(OID_HASH_ALGO_IDENTIFIER),
                                OpenSSL::ASN1::Null.new(nil)
                              ]
                            ),
                            signed_attributes,
                            OpenSSL::ASN1::Sequence.new(
                              [
                                OpenSSL::ASN1::ObjectId.new(OID_RSA_ENCRYPTION),
                                OpenSSL::ASN1::Null.new(nil)
                              ]
                            ),
                            OpenSSL::ASN1::OctetString.new(signed_attributes_digest)
                          ]
                        ),
                      ]
                    )
                  ]
                )],
              0,
              :CONTEXT_SPECIFIC
            )
          ]
        ).to_der
      end

      def signed_attributes_sequence
        OpenSSL::ASN1::ASN1Data.new(
          [
            OpenSSL::ASN1::Sequence.new(
              [
                OpenSSL::ASN1::ObjectId.new(OID_CONTENT_TYPE),
                OpenSSL::ASN1::Set.new([OpenSSL::ASN1::ObjectId.new(OID_DATA)])
              ]
            ),
            OpenSSL::ASN1::Sequence.new(
              [
                OpenSSL::ASN1::ObjectId.new(OID_SIGNING_TIME),
                OpenSSL::ASN1::Set.new([OpenSSL::ASN1::UTCTime.new(Time.now)])
              ]
            ),
            OpenSSL::ASN1::Sequence.new(
              [
                OpenSSL::ASN1::ObjectId.new(OID_MESSAGE_DIGEST),
                OpenSSL::ASN1::Set.new([OpenSSL::ASN1::OctetString.new(@sha1.digest(@envelop_sequence))])
              ]
            ),
            OpenSSL::ASN1::Sequence.new(
              [
                OpenSSL::ASN1::ObjectId.new(OID_MESSAGE_TYPE),
                OpenSSL::ASN1::Set.new([OpenSSL::ASN1::PrintableString.new(SCEP_MESSAGE_TYPES['CertRep'].to_s)])
              ]
            ),
            OpenSSL::ASN1::Sequence.new(
              [
                OpenSSL::ASN1::ObjectId.new(OID_PKI_STATUS),
                OpenSSL::ASN1::Set.new([OpenSSL::ASN1::PrintableString.new(SCEP_PKI_STATUSES['SUCCESS'].to_s)])
              ]
            ),
            OpenSSL::ASN1::Sequence.new(
              [
                OpenSSL::ASN1::ObjectId.new(OID_RECIPIENT_NOUNCE),
                OpenSSL::ASN1::Set.new([OpenSSL::ASN1::OctetString.new([@sender_nonce].pack('H*'))])
              ]
            ),
            OpenSSL::ASN1::Sequence.new(
              [
                OpenSSL::ASN1::ObjectId.new(OID_SENDER_NONCE),
                OpenSSL::ASN1::Set.new([OpenSSL::ASN1::OctetString.new([@sender_nonce].pack('H*'))])
              ]
            ),
            OpenSSL::ASN1::Sequence.new(
              [
                OpenSSL::ASN1::ObjectId.new(OID_TRANSACTION_ID),
                OpenSSL::ASN1::Set.new([OpenSSL::ASN1::PrintableString.new(@transaction_id)])
              ]
            )
          ],
          0,
          :CONTEXT_SPECIFIC
        )
      end

      def algo_identifier_sequence(signed_attributes, sha1)
        OpenSSL::ASN1::Sequence.new(
          [
            OpenSSL::ASN1::Sequence.new(
              [
                OpenSSL::ASN1::ObjectId.new(OID_HASH_ALGO_IDENTIFIER),
                OpenSSL::ASN1::Null.new(nil)
              ]
            ),
            OpenSSL::ASN1::OctetString.new(sha1.digest(OpenSSL::ASN1::Set.new(signed_attributes.value[0..-1]).to_der))
          ]
        )
      end
    end
  end
end