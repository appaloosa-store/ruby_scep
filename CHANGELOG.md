Changelog
=========

v0.3.0 (24/08/2026)
-------------------

Issued certificates change. Nothing already issued is invalidated, and no
method signature changes, but a device enrolling against this version gets a
materially different certificate.

### Certificates

- Issue X.509 v3. `version` was set to 1, which encodes **v2**, while a
  `keyUsage` extension was attached -- and extensions are only legal in v3, so
  the certificate was structurally invalid. Relying parties that enforce the
  version/extension rule reject such a certificate.
- Sign certificates with SHA-256 instead of SHA-1.
- Add `basicConstraints CA:FALSE`, `subjectKeyIdentifier` and
  `authorityKeyIdentifier`, and mark `keyUsage` critical.
- Derive `subjectKeyIdentifier` per RFC 7093 method 1 -- the leftmost 160 bits of
  SHA-256 over the subjectPublicKey BIT STRING -- rather than OpenSSL's SHA-1
  `hash` keyword.
- Carry over a `subjectAltName` requested through the CSR's `extensionRequest`
  attribute, under an allowlist. Requests for `basicConstraints`, `keyUsage` or
  `extendedKeyUsage` are dropped: a CSR will ask to become a CA, and must not be
  granted it. A requested extension cannot displace one this gem sets, repeated
  OIDs collapse to one, and a carried `subjectAltName` is forced non-critical.
- `extendedKeyUsage` is deliberately still unset. Restricting it to `clientAuth`
  makes OpenSSL's `PKCS7#verify` reject the certificate for S/MIME signing, which
  is the purpose it checks by default and therefore how a device's signed
  requests are authenticated. Setting it requires the verifying side to use
  `store.purpose = OpenSSL::X509::PURPOSE_ANY` first.

### Tooling

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
