# Introduction

This app provides a simple Identity Provider (IdP) to test SAML 2.0 Service Providers (SPs) with the [SAML 2.0 Web Browser SSO Profile](http://en.wikipedia.org/wiki/SAML_2.0#Web_Browser_SSO_Profile).

> **This sample is not intended for use with production systems!** 

## Installation

    npm install
    bower install
    
> [Bower](http://bower.io/), a front-end package manager, can be installed with `npm install -g bower`    

### Usage

	node app.js --acs {POST URL} --aud {audience}
	
Open `http://localhost:7000` in your browser to start an IdP initiated flow to your SP

#### Example

	node app.js --acs https://foo.okta.com/auth/saml20/example --aud https://www.okta.com/saml2/service-provider/spf5aFRRXFGIMAYXQPNV

#### Options

Most parameters can be defined with the following command-line arguments:

```
  --port, -p                        Web Server Listener Port                                                                             [required]  [default: 7000]
  --issuer, --iss                   IdP Issuer URI                                                                                       [required]  [default: "urn:example:idp"]
  --acsUrl, --acs                   SP Assertion Consumer URL                                                                            [required]
  --audience, --aud                 SP Audience URI                                                                                      [required]
  --relayState, --rs                Default SAML RelayState for SAMLResponse                                                           
  --disableRequestAcsUrl, --static  Disables ability for SP AuthnRequest to specify Assertion Consumer URL                               [default: false]
  --encryptionCert, --encCert       SP Certificate (pem) for Assertion Encryption                                                      
  --encryptionPublicKey, --encKey   SP RSA Public Key (pem) for Assertion Encryption (e.g. openssl x509 -pubkey -noout -in sp-cert.pem)
  --httpsPrivateKey                 Web Server TLS/SSL Private Key (pem)                                                               
  --httpsCert                       Web Server TLS/SSL Certificate (pem)                                                               
  --https                           Enables HTTPS Listener (requires httpsPrivateKey and httpsCert)                                      [required]  [default: false]
```

# IdP SAML Settings

## Issuer

The default IdP issuer is `urn:example:idp`.  You can change this with the `--iss` argument.

## Binding

Both SSO POST and Redirect bindings are available on the same endpoint which by default is `http://localhost:7000`

Binding       | URL
------------- | --------------------------------------------------------
HTTP-Redirect | `http://localhost:port`
HTTP-POST     | `http://localhost:port`

> http://localhost:port/idp will also work if your SP has weird URL validation rules

## Signing Certificate

A self-signed 2048-bit certificate is already generated and part of this project.

Parameter              |                                                             |
---------------------- | ------------------------------------------------------------|
Public Key Certificate | `idp-public-cert.pem`
Format                 | `PEM`
SHA1 Fingerprint       | `84:EA:56:58:95:24:AE:57:88:9D:B3:63:ED:65:30:1F:E2:5C:5B:B8`

> **DO NOT USE** `idp-private-key.pem` in your SP.  This is the private key used by the IdP to sign SAML messages
> 
> **DO NOT USE** this certificate on a production system!  [Generate your own keypair](https://devcenter.heroku.com/articles/ssl-certificate-self) and replace this test key-pair if you want to use this sample against a production system.

You can use openssl to view additional details on the certificate 

`openssl x509 -in idp-public-cert.pem -text -noout -fingerprint`

## SAML Metadata

IdP SAML metadata is available on http://localhost:port/metadata

## Assertion Statement Mappings

SAML Assertion statement mappings are configured in `simpleProfileMapper.js`

Property      | SAML Attribute Name
------------- | --------------------------------------------------------
userName      | Subject NameID
nameIdFormat  | Subject NameID Format
firstName     | `FirstName`
lastName      | `LastName`
displayName   | `DisplayName`
email         | `Email`
mobilePhone   | `MobilePhone`
groups		    | `Groups`

> The default user profile is specified in `config.js`

> SAML attribute mappings currently default to [Okta (Inbound SAML)](developer.okta.com)

## Assertion Encryption

Encrypted assertions require both a certificate and public key from the target service provider in the PEM format (base64 encoding of `.der`, `.cer`, `.cert`, `.crt`).  You can convert certificate formats with `openssl`

#### DER to PEM

`openssl x509 -inform der -in to-convert.der -out converted.pem`

> The following formats or extensions should be convertible to the pem format: `.der`, `.cer`, `.cert`, `.crt

#### PEM Certificate to Public Key

PEM files that contain the header `-----BEGIN CERTIFICATE-----` can also be converted to  just the public key which is a file with just the `-----BEGIN PUBLIC KEY-----` header

`openssl x509 -pubkey -noout -in cert.pem > pub.key`