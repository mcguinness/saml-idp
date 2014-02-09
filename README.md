Simple SAMLP identity provider for node.js.

## Installation

    npm install

## Introduction

This app provides a default identity provider to test SAML 2.0 Service Providers

> SAML attribute mappings currently default to [Okta SP (Inbound SAML)](www.okta.com)

## Usage

	node app.js --acs {POST URL } --aud {audience}

### Example

	node app.js --acs https://foo.okta.com/auth/saml20/example --aud https://www.okta.com/saml2/service-provider/spf5aFRRXFGIMAYXQPNV