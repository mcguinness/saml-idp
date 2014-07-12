Simple SAMLP Identity Provider for node.js.

## Installation

    npm install

## Introduction

This app provides a default identity provider to test SAML 2.0 Service Providers

> SAML attribute mappings currently default to [Okta SP (Inbound SAML)](www.okta.com)

## Usage

	node app.js --acs {POST URL } --aud {audience}

### Example

	node app.js --acs https://foo.okta.com/auth/saml20/example --aud https://www.okta.com/saml2/service-provider/spf5aFRRXFGIMAYXQPNV

## Assertion Statement Mappings

SAML Assertion statement mappings are configured in `simpleProfileMapper.js`

Attribute     | Mapping
------------- | --------------------------------------------------------
NameID Format | `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`
First Name    | 'FirstName'
Last Name     | 'Last Name'
Email         | 'Email' 


> The default user profile is specified in `config.js`   