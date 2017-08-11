# frozen_string_literal: true
require 'sinatra'
require 'yaml'
require 'sinatra/base'
require 'webrick'
require 'webrick/https'
require 'openssl'
require 'ruby_scep'

RubyScep.configure do |config|
  config.ca_cert_path = 'certs/ca.pem'
  config.ca_key_path = 'certs/passwordless.key'
end

get '/scep' do
  p 'get scep'
  case params['operation']
  when 'GetCACert'
    p 'operation: GetCACert'
    # todo, verify signer
    content_type 'application/x-x509-ca-cert'
    RubyScep.configuration.ca.to_der
  when 'GetCACaps'
    p 'operation: GetCACaps'
    content_type 'text/plain'
    "SHA-1\nSHA-256\nAES\nDES3\nSCEPStandard\nPOSTPKIOperation"
    # see complete list of capabilities https://tools.ietf.org/html/draft-nourse-scep-23#appendix-C.2
  else
    'Invalid Action'
  end
end

post '/scep' do
  p 'post scep'
  if params['operation'] == 'PKIOperation'
    content_type 'application/x-pki-message'
    RubyScep::PkiOperation.build_response(request.body.read)
  else
    'Invalid Action'
  end
end
