# Introduction

This app provides a simple SAML Identity Provider (IdP) to test SAML 2.0 Service Providers (SPs) with the [SAML 2.0 Web Browser SSO Profile](http://en.wikipedia.org/wiki/SAML_2.0#Web_Browser_SSO_Profile) or the Single Logout Profile.

> **This sample is not intended for use with production systems!**

## Installation

### Global Command Line Tool

``` shell
npm install --global saml-idp
```

### Manual

From inside a local copy of this repo

``` shell
npm install
# or
npm link
```

### Library

``` shell
npm install saml-idp
```

### Docker

1. docker-compose build
2. docker-compose up

Simply modify Dockerfile to specify your own parameters.

## Generating IdP Signing Certificate

You must generate a self-signed certificate for the IdP.

> The private key should be unique to your test IdP and not shared!

You can generate a keypair using the following command (requires openssl in your path):

``` shell
openssl req -x509 -new -newkey rsa:2048 -nodes -subj '/C=US/ST=California/L=San Francisco/O=JankyCo/CN=Test Identity Provider' -keyout idp-private-key.pem -out idp-public-cert.pem -days 7300
```

## Usage

### Library

An IdP server can be started using the exported `runServer` function. `runServer` accepts a config object which matches the interface of the `saml-idp` command.

``` javascript
const {runServer} = require('saml-idp');

runServer({
  acsUrl: `https://foo.okta.com/auth/saml20/assertion-consumer`,
  audience: `https://foo.okta.com/auth/saml20/metadata`,
});
```

#### Custom user config (claims)

``` javascript
const {runServer} = require('saml-idp');

runServer({
  acsUrl: `https://foo.okta.com/auth/saml20/assertion-consumer`,
  audience: `https://foo.okta.com/auth/saml20/metadata`,
  config: {
    user: userDefaults,
    // The auth-service requires at least one AttributeStatement in the SAML assertion.
    metadata: [{
      id: 'email',
      optional: false,
      displayName: 'E-Mail Address',
      description: 'The e-mail address of the user',
      multiValue: false
    }, {
      id: "userType",
      optional: true,
      displayName: 'User Type',
      description: 'The type of user',
      options: ['Admin', 'Editor', 'Commenter']
    }],
    user: {
      email: 'saml.jackson@example.com',
    },
  },
});
```

### Command Line

#### SSO Profile

``` shell
saml-idp --acs {POST URL} --aud {audience}
```

#### SSO & SLO Profile

```
saml-idp --acs {POST URL} --slo {POST URL} --aud {audience}
```

Open `http://localhost:7000` in your browser to start an IdP initiated flow to your SP

#### Example

```
saml-idp --acs https://foo.okta.com/auth/saml20/example --aud https://www.okta.com/saml2/service-provider/spf5aFRRXFGIMAYXQPNV
```

#### Options

Most parameters can be defined with the following command-line arguments:

```
Options:
  --help                            Show help                                                                                                                              [boolean]
  --version                         Show version number                                                                                                                    [boolean]
  --settings                        Path to JSON config file
  --port, -p                        IdP Web Server Listener Port                                                                                          [required] [default: 7000]
  --cert                            IdP Signature PublicKey Certificate                                                                [required] [default: "./idp-public-cert.pem"]
  --key                             IdP Signature PrivateKey Certificate                                                               [required] [default: "./idp-private-key.pem"]
  --issuer, --iss                   IdP Issuer URI                                                                                           [required] [default: "urn:example:idp"]
  --acsUrl, --acs                   SP Assertion Consumer URL                                                                                                             [required]
  --sloUrl, --slo                   SP Single Logout URL
  --audience, --aud                 SP Audience URI                                                                                                                       [required]
  --serviceProviderId, --spId       SP Issuer/Entity URI                                                                                                                    [string]
  --relayState, --rs                Default SAML RelayState for SAMLResponse
  --disableRequestAcsUrl, --static  Disables ability for SP AuthnRequest to specify Assertion Consumer URL                                                [boolean] [default: false]
  --encryptAssertion, --enc         Encrypts assertion with SP Public Key                                                                                 [boolean] [default: false]
  --encryptionCert, --encCert       SP Certificate (pem) for Assertion Encryption                                                                                           [string]
  --encryptionPublicKey, --encKey   SP RSA Public Key (pem) for Assertion Encryption (e.g. openssl x509 -pubkey -noout -in sp-cert.pem)                                     [string]
  --httpsPrivateKey                 Web Server TLS/SSL Private Key (pem)                                                                                                    [string]
  --httpsCert                       Web Server TLS/SSL Certificate (pem)                                                                                                    [string]
  --https                           Enables HTTPS Listener (requires httpsPrivateKey and httpsCert)                                            [boolean] [required] [default: false]
  --configFile, --conf              Path to a SAML attribute config file                                                  [required] [default: "/Users/karl/src/saml-idp/config.js"]
  --rollSession                     Create a new session for every authn request instead of reusing an existing session                                   [boolean] [default: false]
  --authnContextClassRef, --acr     Authentication Context Class Reference                   [string] [default: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"]
  --authnContextDecl, --acd         Authentication Context Declaration (XML FilePath)                                                                                       [string]
```

# IdP SAML Settings

## Issuer

The default IdP issuer is `urn:example:idp`.  You can change this with the `--iss` argument.

## Signing Certificate

The signing certificate public key must be specified as a file path or PEM string using the `cert` argument

The signing certificate private key must be specified as a file path or PEM string using the `key` argument

### Passing key/cert pairs from environment variables

Signing certificate key/cert pairs can also be passed from environment variables.

```
saml-idp --acs {POST URL} --aud {audience} --cert="$SAML_CERT" --key="$SAML_KEY"
```

## Single Sign-On Service Binding

Both SSO POST and Redirect bindings are available on the same endpoint which by default is `http://localhost:7000/saml/sso`

Binding       | URL
------------- | --------------------------------------------------------
HTTP-Redirect | `http://localhost:port/saml/sso`
HTTP-POST     | `http://localhost:port/saml/sso`

## Single Logout Service Binding

Both SSO POST and Redirect bindings are available on the same endpoint which by default is `http://localhost:7000/saml/slo`

Binding       | URL
------------- | --------------------------------------------------------
HTTP-Redirect | `http://localhost:port/saml/slo`
HTTP-POST     | `http://localhost:port/saml/slo`

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

### DER to PEM

`openssl x509 -inform der -in to-convert.der -out converted.pem`

> The following formats or extensions should be convertible to the pem format: `.der`, `.cer`, `.cert`, `.crt

### PEM Certificate to Public Key

PEM files that contain the header `-----BEGIN CERTIFICATE-----` can also be converted to just the public key which is a file with just the `-----BEGIN PUBLIC KEY-----` header

`openssl x509 -pubkey -noout -in cert.pem > pub.key`

