Ruby SCEP [![CircleCI](https://circleci.com/gh/appaloosa-store/ruby_scep.svg?style=svg)](https://circleci.com/gh/appaloosa-store/ruby_scep)
---
A Ruby gem to handle SCEP.

Installation
---
To install *Ruby Scep*:

```
$ gem install ruby_scep
```

Or you can include this in your project's `Gemfile`:

```
gem 'ruby_scep'
```

Then execute:

```
$ bundle
```
Usage
---

You must use a webserver (Webrick or related will do the trick) and declare two endpoints:
- `GET /scep`
- `POST /scep`
An example server is [included](https://github.com/appaloosa-store/ruby_scep/tree/master/example_server) in this gem.

Acknowledgements
---
This gem would not exist without the following repos:
- Nolan Browns's IosCertEnrollment. Non-working SCEP but the profiles generation part worked alright https://github.com/nolanbrown/ios-cert-enrollment
- MicroMDM's SCEP Go server. It worked perfectly, so we could use it as a reference https://github.com/micromdm/scep/
- OneLogin SCEP gem. The first instance of OpenSSL::ASN1 that led me to the AppBlade repo https://github.com/onelogin/scep-gem/blob/master/lib/scep/asn1.rb
- AppBlade's SCEP controller. The final pieces of the puzzle: the PKIMessage building using a ASN1 structure. I could'nt have done it without them. https://github.com/AppBlade/TestHub/blob/master/app/controllers/scep_controller.rb

We decided to open-source our solution to give back to the community that helped us greatly. Do the same with your projects!

Documentation
---
- CISCO's description of the SCEP protocol. Information about PKIMessage structure are also available here. https://www.cisco.com/c/en/us/support/docs/security-vpn/public-key-infrastructure-pki/116167-technote-scep-00.html
- SCEP RFC https://tools.ietf.org/html/draft-nourse-scep-23
- OID correspondance. A lifesaver to understand the ASN1 OIDs http://oid-info.com/

Contributing
---
1. Fork it ( https://github.com/appaloosa-store/ruby_scep )
2. Create your feature branch (git checkout -b my-new-feature)
3. Commit your changes (git commit -am 'Add some feature')
4. Push to the branch (git push origin my-new-feature)
5. Create a new Pull Request.