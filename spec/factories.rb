# frozen_string_literal: true
require 'openssl'
require 'securerandom'

class Factories
  class << self
    include OpenSSL::ASN1

    def build(method_name, *arguments)
      send(method_name, *arguments)
    end

    private

    def raw_csr(
      transaction_id: nil,
      sender_nonce: nil,
      cert_subject: nil,
      cert_serial: nil,
      csr_subject: nil,
      cert_private_key: nil,
      csr_private_key: nil)
      transaction_id = transaction_id ? transaction_id : SecureRandom.hex
      sender_nonce = sender_nonce ? sender_nonce : SecureRandom.hex
      key = cert_private_key ? cert_private_key : OpenSSL::PKey::RSA.new(1024)
      sha1 = OpenSSL::Digest::SHA1.new
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = cert_serial ? cert_serial : Random.rand(2**159)
      cert.not_before = Time.now
      cert.not_after = Time.now + 600
      cert.public_key = key.public_key
      cert.subject = OpenSSL::X509::Name.parse(cert_subject ? cert_subject : 'CN=MDM SCEP SIGNER/C=US')
      cert.issuer = OpenSSL::X509::Name.parse(cert_subject ? cert_subject : 'CN=MDM SCEP SIGNER/C=US')
      cert.sign key, OpenSSL::Digest::SHA1.new

      csr_key = csr_private_key ? csr_private_key : OpenSSL::PKey::RSA.new(1024)
      csr = OpenSSL::X509::Request.new
      csr.public_key = csr_key.public_key
      csr.subject = OpenSSL::X509::Name.parse(csr_subject ? csr_subject : 'CN=iPhone/C=US')
      csr.version = 0
      csr.attributes = [
        OpenSSL::X509::Attribute.new(
          'challengePassword',
          Set.new([
                    PrintableString.new('2:cf31b62eca246c154b26286c9dec95ce6150ac6e19c041b6e9d166910ad38fe4')
                  ])
        )
      ]
      csr.sign csr_key, sha1

      now = Time.now

      des = OpenSSL::Cipher::Cipher.new('des-ede3-cbc')
      des.encrypt
      content_encryption_key = des.random_key
      content_encryption_iv = des.random_iv
      des.key = content_encryption_key
      des.iv = content_encryption_iv

      encrypted_payload = des.update(csr.to_der) + des.final

      recipient_information = Sequence.new([
                                             OpenSSL::ASN1.decode(RubyScep.configuration.ca.subject.to_der),
                                             Integer.new(RubyScep.configuration.ca.serial.to_i)
                                           ])

      envelope = Sequence.new([
                                ObjectId.new(RubyScep::PkiMessage::OID_ENVELOPED_DATA),
                                ASN1Data.new([
                                               Sequence.new([
                                                              Integer.new(0),
                                                              Set.new([
                                                                        Sequence.new([
                                                                                       Integer.new(0),
                                                                                       recipient_information,
                                                                                       Sequence.new([
                                                                                                      ObjectId.new(RubyScep::PkiMessage::OID_RSA_ENCRYPTION),
                                                                                                      Null.new(nil)
                                                                                                    ]),
                                                                                       OctetString.new(RubyScep.configuration.ca_key.public_encrypt content_encryption_key)
                                                                                     ])
                                                                      ]),
                                                              Sequence.new([
                                                                             ObjectId.new(RubyScep::PkiMessage::OID_DATA),
                                                                             Sequence.new([
                                                                                            ObjectId.new(RubyScep::PkiMessage::OID_DES_ALGO),
                                                                                            OctetString.new(content_encryption_iv)
                                                                                          ]),
                                                                             ASN1Data.new(encrypted_payload, 0, :CONTEXT_SPECIFIC)
                                                                           ])
                                                            ])
                                             ], 0, :CONTEXT_SPECIFIC)
                              ])

      text = envelope.to_der
      message_digest = sha1.digest text

      signed_attributes = ASN1Data.new([
                                         Sequence.new([
                                                        ObjectId.new(RubyScep::PkiMessage::OID_CONTENT_TYPE),
                                                        Set.new([
                                                                  ObjectId.new(RubyScep::PkiMessage::OID_DATA)
                                                                ])
                                                      ]),
                                         Sequence.new([
                                                        ObjectId.new(RubyScep::PkiMessage::OID_SIGNING_TIME),
                                                        Set.new([
                                                                  UTCTime.new(now)
                                                                ])
                                                      ]),
                                         Sequence.new([
                                                        ObjectId.new(RubyScep::PkiMessage::OID_MESSAGE_DIGEST),
                                                        Set.new([
                                                                  OctetString.new(message_digest)
                                                                ])
                                                      ]),
                                         Sequence.new([
                                                        ObjectId.new('challengePassword'),
                                                        Set.new([
                                                                  PrintableString.new('2:cf31b62eca246c154b26286c9dec95ce6150ac6e19c041b6e9d166910ad38fe4')
                                                                ])
                                                      ]),
                                         Sequence.new([
                                                        ObjectId.new(RubyScep::PkiMessage::OID_MESSAGE_TYPE),
                                                        Set.new([
                                                                  PrintableString.new(RubyScep::PkiMessage::SCEP_MESSAGE_TYPES['PKCSReq'].to_s)
                                                                ])
                                                      ]),
                                         Sequence.new([
                                                        ObjectId.new(RubyScep::PkiMessage::OID_SENDER_NONCE),
                                                        Set.new([
                                                                  OctetString.new(sender_nonce)
                                                                ])
                                                      ]),
                                         Sequence.new([
                                                        ObjectId.new(RubyScep::PkiMessage::OID_TRANSACTION_ID),
                                                        Set.new([
                                                                  PrintableString.new(transaction_id)
                                                                ])
                                                      ])
                                       ], 0, :CONTEXT_SPECIFIC)

      signed_attributes_digest = key.private_encrypt Sequence.new([
                                                                    Sequence.new([
                                                                                   ObjectId.new(RubyScep::PkiMessage::OID_HASH_ALGO_IDENTIFIER),
                                                                                   Null.new(nil)
                                                                                 ]),
                                                                    OctetString.new(sha1.digest Set.new(signed_attributes.value[0..-1]).to_der)
                                                                  ]).to_der

      pki_message = Sequence.new([
                                   ObjectId.new(RubyScep::PkiMessage::OID_SIGNED_DATA),
                                   ASN1Data.new([
                                                  Sequence.new([
                                                                 Integer.new(1),
                                                                 Set.new([
                                                                           Sequence.new([
                                                                                          ObjectId.new(RubyScep::PkiMessage::OID_HASH_ALGO_IDENTIFIER),
                                                                                          Null.new(nil)
                                                                                        ])
                                                                         ]),
                                                                 Sequence.new([
                                                                                ObjectId.new(RubyScep::PkiMessage::OID_DATA),
                                                                                ASN1Data.new([
                                                                                               OctetString.new(text)
                                                                                             ], 0, :CONTEXT_SPECIFIC)
                                                                              ]),
                                                                 ASN1Data.new([
                                                                                OpenSSL::ASN1.decode(cert.to_der)
                                                                              ], 0, :CONTEXT_SPECIFIC),
                                                                 Set.new([
                                                                           Sequence.new([
                                                                                          Integer.new(1),
                                                                                          Sequence.new([
                                                                                                         OpenSSL::ASN1.decode(cert.subject.to_der),
                                                                                                         Integer.new(cert.serial)
                                                                                                       ]),
                                                                                          Sequence.new([
                                                                                                         ObjectId.new(RubyScep::PkiMessage::OID_HASH_ALGO_IDENTIFIER),
                                                                                                         Null.new(nil)
                                                                                                       ]),
                                                                                          signed_attributes,
                                                                                          Sequence.new([
                                                                                                         ObjectId.new(RubyScep::PkiMessage::OID_RSA_ENCRYPTION),
                                                                                                         Null.new(nil)
                                                                                                       ]),
                                                                                          OctetString.new(signed_attributes_digest)
                                                                                        ])
                                                                         ])
                                                               ])
                                                ], 0, :CONTEXT_SPECIFIC)
                                 ])
      pki_message.to_der.force_encoding('UTF-8')
    end

    def pki_message(raw_csr: nil,
                    transaction_id: nil,
                    sender_nonce: nil,
                    cert_subject: nil,
                    cert_serial: nil,
                    csr_subject: nil,
                    csr_private_key: nil,
                    cert_private_key: nil)
      csr = if raw_csr
              raw_csr
            else
              Factories.send(:raw_csr,
                             cert_subject: cert_subject,
                             cert_serial: cert_serial,
                             csr_subject: csr_subject,
                             cert_private_key: cert_private_key,
                             csr_private_key: csr_private_key,
                             transaction_id: transaction_id,
                             sender_nonce: sender_nonce)
            end
      p7 = OpenSSL::PKCS7.new(csr)
      flags = OpenSSL::PKCS7::BINARY | OpenSSL::PKCS7::NOVERIFY
      p7.verify(nil, RubyScep.configuration.certificates_store, nil, flags)
      asn1 = OpenSSL::ASN1.decode(p7.to_der)
      RubyScep::PkiMessage.new(asn1, p7)
    end

    def decrypted_csr(pki_message: nil, raw_csr: nil)
      pki_message = Factories.send(:pki_message, raw_csr: raw_csr) if raw_csr && pki_message.nil?
      encrypted_p7 = OpenSSL::PKCS7.new(pki_message.p7.data)
      raw_csr = encrypted_p7.decrypt(RubyScep.configuration.ca_key, RubyScep.configuration.ca, OpenSSL::PKCS7::BINARY)
      OpenSSL::X509::Request.new(raw_csr)
    end
  end
end
