# frozen_string_literal: true
module RubyScep
  class PkiMessage
    class Degenerate

      def initialize(certificate)
        @certificate = certificate
      end

      def to_der
        OpenSSL::ASN1::Sequence.new(
          [
            OpenSSL::ASN1::ObjectId.new(OID_SIGNED_DATA),
            OpenSSL::ASN1::ASN1Data.new(
              [
                OpenSSL::ASN1::Sequence.new(
                  [
                    OpenSSL::ASN1::Integer.new(1),
                    OpenSSL::ASN1::Set.new([]),
                    OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::ObjectId.new(OID_DATA)]),
                    OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::decode(@certificate.to_der)], 0, :CONTEXT_SPECIFIC),
                    OpenSSL::ASN1::ASN1Data.new([], 1, :CONTEXT_SPECIFIC),
                    OpenSSL::ASN1::Set.new([])
                  ]
                )
              ],
              0,
              :CONTEXT_SPECIFIC)
          ]
        ).to_der
      end
    end
  end
end