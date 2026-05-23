#!/bin/sh
# Translate SAML_* env vars into mcguinness/saml-idp CLI flags. Also
# binds 0.0.0.0 so Dokploy/Traefik (in a different container) can
# actually reach the IdP — the upstream default is localhost which
# is the in-container loopback only.

set -e

CMD="node app.js --host 0.0.0.0 --port ${SAML_PORT:-7000}"

if [ -n "$SAML_ACS_URL" ]; then
  CMD="$CMD --acsUrl \"$SAML_ACS_URL\""
fi
if [ -n "$SAML_AUDIENCE" ]; then
  CMD="$CMD --audience \"$SAML_AUDIENCE\""
fi
if [ -n "$SAML_SLO_URL" ]; then
  CMD="$CMD --sloUrl \"$SAML_SLO_URL\""
fi
if [ -n "$SAML_ISSUER" ]; then
  CMD="$CMD --iss \"$SAML_ISSUER\""
fi

echo "Starting SAML IdP"
echo "  Host:     0.0.0.0:${SAML_PORT:-7000}"
echo "  ACS:      ${SAML_ACS_URL:-<not set>}"
echo "  Audience: ${SAML_AUDIENCE:-<not set>}"
echo "  SLO:      ${SAML_SLO_URL:-<not set>}"
echo "  Issuer:   ${SAML_ISSUER:-urn:example:idp}"

eval $CMD
