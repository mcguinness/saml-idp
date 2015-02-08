Simple SAMLP Identity Provider for node.js.

## Installation

    npm install
    bower install

## Introduction

This app provides a simple Identity Provider (IdP) to test SAML 2.0 Service Providers (SPs) with the [SAML 2.0 Web Browser SSO Profile](http://en.wikipedia.org/wiki/SAML_2.0#Web_Browser_SSO_Profile)

> SAML attribute mappings currently default to [Okta (Inbound SAML)](developer.okta.com)

## Usage

	node app.js --acs {POST URL} --aud {audience}

### Example

	node app.js --acs https://foo.okta.com/auth/saml20/example --aud https://www.okta.com/saml2/service-provider/spf5aFRRXFGIMAYXQPNV

## Assertion Statement Mappings

SAML Assertion statement mappings are configured in `simpleProfileMapper.js`

Property      | SAML Attribute Name
------------- | --------------------------------------------------------
userName      | Subject NameID
nameIdFormat  | Subject NameID Format
firstName     | 'FirstName'
lastName      | 'LastName'
displayName   | 'DisplayName'
email         | 'Email'
mobilePhone   | 'MobilePhone'
groups		  | 'Groups'


> The default user profile is specified in `config.js` 

## Assertion Encryption

Encrypted assertions require both a certificate and public key from the target service provider in the PEM format (base64 encoding of `.der`, `.cer`, `.cert`, `.crt`).  You can convert certificate formats with `openssl`

#### DER to PEM

`openssl x509 -inform der -in to-convert.der -out converted.pem`

> The following formats or extensions should be convertible to the pem format: `.der`, `.cer`, `.cert`, `.crt

#### PEM Certificate to Public Key

PEM files that contain the header `-----BEGIN CERTIFICATE-----` can also be converted to  just the public key which is a file with just the `-----BEGIN PUBLIC KEY-----` header

`openssl x509 -pubkey -noout -in cert.pem > pub.key`