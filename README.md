Simple SAMLP Identity Provider for node.js.

## Installation

    npm install
    bower install

## Introduction

This app provides a simple Identity Provider (IdP) to test SAML 2.0 Service Providers (SPs) with the [SAML 2.0 Web Browser SSO Profile](http://en.wikipedia.org/wiki/SAML_2.0#Web_Browser_SSO_Profile)

> SAML attribute mappings currently default to [Okta SP (Inbound SAML)](developer.okta.com)

## Usage

	node app.js --acs {POST URL} --aud {audience}

### Example

	node app.js --acs https://foo.okta.com/auth/saml20/example --aud https://www.okta.com/saml2/service-provider/spf5aFRRXFGIMAYXQPNV

## Assertion Statement Mappings

SAML Assertion statement mappings are configured in `simpleProfileMapper.js`

Attribute     | Mapping
------------- | --------------------------------------------------------
NameID Format | `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`
First Name    | 'FirstName'
Last Name     | 'LastName'
Display Name  | 'Display Name'
Email         | 'Email'
MobilePhone   | 'MobilePhone'
Groups		  | 'Groups'


> The default user profile is specified in `config.js`   