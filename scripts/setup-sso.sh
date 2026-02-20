#!/usr/bin/env bash
# Snapper SSO Setup Script
#
# Interactive script to configure OIDC or SAML SSO for a Snapper organization.
# Calls the local /api/v1/setup/configure-sso endpoint.
#
# Usage:
#   bash scripts/setup-sso.sh
#   SNAPPER_URL=http://localhost:8000 bash scripts/setup-sso.sh

set -euo pipefail

SNAPPER_URL="${SNAPPER_URL:-http://127.0.0.1:8000}"

echo "============================================"
echo "  Snapper SSO Configuration"
echo "============================================"
echo ""

# Step 1: Organization
read -r -p "Organization name (e.g. Acme Corp): " ORG_NAME
read -r -p "Organization slug (e.g. acme-corp): " ORG_SLUG

# Step 2: SSO type
echo ""
echo "SSO Type:"
echo "  1) OIDC (recommended for Okta, Auth0, Azure AD)"
echo "  2) SAML"
read -r -p "Choose [1/2]: " SSO_CHOICE

ENABLE_SCIM="false"
JSON_PAYLOAD=""

if [[ "$SSO_CHOICE" == "2" ]]; then
    SSO_TYPE="saml"
    echo ""
    echo "--- SAML Configuration ---"
    read -r -p "IdP Entity ID: " SAML_ENTITY_ID
    read -r -p "IdP SSO URL: " SAML_SSO_URL
    echo "Paste IdP X.509 Certificate (single line, base64):"
    read -r SAML_CERT
    read -r -p "IdP SLO URL (optional, press Enter to skip): " SAML_SLO_URL
    read -r -p "Enable SCIM provisioning? [y/N]: " SCIM_ANSWER
    [[ "$SCIM_ANSWER" == "y" || "$SCIM_ANSWER" == "Y" ]] && ENABLE_SCIM="true"

    JSON_PAYLOAD=$(cat <<JSONEOF
{
  "org_name": "${ORG_NAME}",
  "org_slug": "${ORG_SLUG}",
  "sso_type": "saml",
  "saml_idp_entity_id": "${SAML_ENTITY_ID}",
  "saml_idp_sso_url": "${SAML_SSO_URL}",
  "saml_idp_x509_cert": "${SAML_CERT}",
  "saml_idp_slo_url": "${SAML_SLO_URL}",
  "enable_scim": ${ENABLE_SCIM}
}
JSONEOF
    )
else
    SSO_TYPE="oidc"
    echo ""
    echo "--- OIDC Configuration ---"
    read -r -p "Okta domain (e.g. dev-12345.okta.com): " OKTA_DOMAIN
    read -r -p "Client ID: " OIDC_CLIENT_ID
    read -r -p "Client Secret: " OIDC_CLIENT_SECRET
    read -r -p "Scopes [openid email profile]: " OIDC_SCOPES
    OIDC_SCOPES="${OIDC_SCOPES:-openid email profile}"
    read -r -p "Enable SCIM provisioning? [y/N]: " SCIM_ANSWER
    [[ "$SCIM_ANSWER" == "y" || "$SCIM_ANSWER" == "Y" ]] && ENABLE_SCIM="true"

    OIDC_ISSUER="https://${OKTA_DOMAIN}"

    JSON_PAYLOAD=$(cat <<JSONEOF
{
  "org_name": "${ORG_NAME}",
  "org_slug": "${ORG_SLUG}",
  "sso_type": "oidc",
  "oidc_issuer": "${OIDC_ISSUER}",
  "oidc_client_id": "${OIDC_CLIENT_ID}",
  "oidc_client_secret": "${OIDC_CLIENT_SECRET}",
  "oidc_scopes": "${OIDC_SCOPES}",
  "oidc_provider": "okta",
  "enable_scim": ${ENABLE_SCIM}
}
JSONEOF
    )
fi

echo ""
echo "Configuring SSO..."

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
    "${SNAPPER_URL}/api/v1/setup/configure-sso" \
    -H "Content-Type: application/json" \
    -d "${JSON_PAYLOAD}" 2>/dev/null)

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [[ "$HTTP_CODE" == "200" ]]; then
    echo ""
    echo "============================================"
    echo "  SSO Configured Successfully!"
    echo "============================================"
    echo ""
    echo "$BODY" | python3 -m json.tool 2>/dev/null || echo "$BODY"
    echo ""
    echo "--- Next Steps (Okta-side configuration) ---"
    echo ""
    if [[ "$SSO_TYPE" == "oidc" ]]; then
        echo "1. In your Okta admin console, create a new OIDC Web Application"
        echo "2. Set the Sign-in redirect URI to:"
        echo "     https://YOUR_SNAPPER_HOST/auth/oidc/callback"
        echo "3. Set the Sign-out redirect URI to:"
        echo "     https://YOUR_SNAPPER_HOST/auth/oidc/logout/${ORG_SLUG}"
        echo "4. Test login at:"
        echo "     https://YOUR_SNAPPER_HOST/auth/oidc/login/${ORG_SLUG}"
    else
        echo "1. In your IdP, create a new SAML application"
        echo "2. Set ACS URL to:"
        echo "     https://YOUR_SNAPPER_HOST/auth/saml/acs/${ORG_SLUG}"
        echo "3. Set Entity ID / Audience to:"
        echo "     https://YOUR_SNAPPER_HOST/auth/saml/metadata/${ORG_SLUG}"
    fi
    if [[ "$ENABLE_SCIM" == "true" ]]; then
        SCIM_TOKEN=$(echo "$BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('scim',{}).get('bearer_token',''))" 2>/dev/null)
        echo ""
        echo "5. SCIM Provisioning:"
        echo "     Base URL: https://YOUR_SNAPPER_HOST/scim/v2"
        echo "     API Token: ${SCIM_TOKEN}"
        echo "     Authentication: HTTP Header → Authorization: Bearer <token>"
    fi
    echo ""
else
    echo ""
    echo "ERROR: SSO configuration failed (HTTP $HTTP_CODE)"
    echo "$BODY"
    exit 1
fi
