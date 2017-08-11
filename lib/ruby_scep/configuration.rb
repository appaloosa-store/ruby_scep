# frozen_string_literal: true
module RubyScep
  class Configuration
    attr_accessor :ca_cert_path, :ca_key_path,
                  :ca, :ca_key,
                  :certificates_store

    def ca
      @ca ||= OpenSSL::X509::Certificate.new(File.read(@ca_cert_path))
    end

    def ca_key
      @ca_key ||= OpenSSL::PKey::RSA.new(File.read(@ca_key_path))
    end

    def certificates_store
      return @certificates_store if defined?(@certificates_store)
      @certificates_store = OpenSSL::X509::Store.new
      @certificates_store.add_cert(ca)
    end
  end
end
