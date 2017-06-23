# Introduction

This app provides a simple Identity Provider (IdP) to test SAML 2.0 Service Providers (SPs) with the [SAML 2.0 Web Browser SSO Profile](http://en.wikipedia.org/wiki/SAML_2.0#Web_Browser_SSO_Profile).

> **This sample is not intended for use with production systems!**

## Docker Installation and Startup

1. docker-compose build
2. docker-compose up

Simply modify Dockerfile to specify your own parameters.

## Manual Installation

1. `npm install`
2. `bower install`
3. `openssl req -x509 -new -newkey rsa:2048 -nodes -subj '/C=US/ST=California/L=San Francisco/O=JankyCo/CN=Test Identity Provider' -keyout idp-private-key.pem -out idp-public-cert.pem -days 7300`

> [Bower](http://bower.io/), a front-end package manager, can be installed with `npm install -g bower`

### Usage

```
node app.js --acs {POST URL} --aud {audience}
```

Open `http://localhost:7000` in your browser to start an IdP initiated flow to your SP

#### Example

```
node app.js --acs https://foo.okta.com/auth/saml20/example --aud https://www.okta.com/saml2/service-provider/spf5aFRRXFGIMAYXQPNV
```

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

You must generate a self-signed certificate for the IdP.

    openssl req -x509 -new -newkey rsa:2048 -nodes -subj '/C=US/ST=California/L=San Francisco/O=JankyCo/CN=Test Identity Provider' -keyout idp-private-key.pem -out idp-public-cert.pem -days 7300

## SAML Metadata

IdP SAML metadata is available on `http://localhost:port/metadata`

## Assertion Attributes

The IdP mints the user's profile as a SAML Assertion Attribute Statement using the `metadata` property in `config.js`.  Profile properties that match a metadata entry `id` property will be generated as a SAML Attribute with the same name.  The IdP UI will automatically render an input for each entry defined via a `metadata` entry in `config.js` with a default value from the matching `profile` property.

#### Profile Property

```json
{
  "email": "saml.jackson@example.com"
}
```

#### Metadata Entry

```json
{
  "id": "email",
  "optional": false,
  "displayName": "E-Mail Address",
  "description": "The e-mail address of the user",
  "multiValue": false
}
```

#### SAML Assertion Attribute Statement

```xml
<saml:Attribute Name="email"><saml:AttributeValue xsi:type="xs:anyType">saml.jackson@example.com</saml:AttributeValue>
```

### Default Attributes

The default profile mappings are defined in `config.js` as:

Profile Property      | SAML Attribute Name
--------------------- | --------------------------------------------------------
userName              | Subject NameID
nameIdFormat          | Subject NameID Format
nameIdNameQualifier   | Subject NameID Name Qualifer
nameIdSPNameQualifier | Subject NameID SP Name Qualifer
nameIdSPProvidedID    | Subject NameID SP ProvidedID
firstName             | `firstName`
lastName              | `lastName`
displayName           | `displayName`
email                 | `email`
mobilePhone           | `mobilePhone`
groups                | `groups`

> SAML attribute mappings currently default to [Okta (Inbound SAML)](developer.okta.com)

### Custom Attributes

New attributes can be defined at runtime in the IdP UI or statically by modifying the `profile` and `metadata` objects in `config.js`.

1. Add metadata entry for your new attributes.  The `id` property must be the name of the SAML Attribute

    ```json
    {
      "id": "customAttribute",
      "optional": false,
      "displayName": "Custom Attribute",
      "description": "My custom attribute",
      "multiValue": false
    }
```
2. Optionally add a default profile attribute value that will be used on startup


## Assertion Encryption

Encrypted assertions require both a certificate and public key from the target service provider in the PEM format (base64 encoding of `.der`, `.cer`, `.cert`, `.crt`).  You can convert certificate formats with `openssl`

#### DER to PEM

`openssl x509 -inform der -in to-convert.der -out converted.pem`

> The following formats or extensions should be convertible to the pem format: `.der`, `.cer`, `.cert`, `.crt

#### PEM Certificate to Public Key

PEM files that contain the header `-----BEGIN CERTIFICATE-----` can also be converted to  just the public key which is a file with just the `-----BEGIN PUBLIC KEY-----` header

`openssl x509 -pubkey -noout -in cert.pem > pub.key`


## Passing key/cert pairs from environment variables

Key/cert pairs can also be passed from environment variables.

```
node app.js --acs {POST URL} --aud {audience} --cert="$SAML_CERT" --key="$SAML_KEY"
```
