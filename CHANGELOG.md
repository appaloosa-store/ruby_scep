Changelog
=========

Unreleased
----------

- Fix the test suite on Ruby 3: `Factories.build` now forwards keyword arguments,
  which Ruby 3 no longer converts from a trailing Hash. The whole suite was
  failing before this.
- Replace `OpenSSL::PKCS7::SignerInfo#name` with `#issuer` in the specs; the
  former was removed from the openssl gem.
- Replace the deprecated `OpenSSL::Cipher::Cipher` alias with `OpenSSL::Cipher`.
  Same class, no behaviour change.
- Stop committing the library `Gemfile.lock`, and declare development
  dependencies once, in the gemspec.
- Require Ruby >= 3.2 and test against 3.2, 3.3 and 3.4 in CI (was 2.3-2.5).

v0.2.1 (17/10/2017)
-------------------

- Extract the challenge password from the CSR and make it accessible in the PKI message (42f8069)
