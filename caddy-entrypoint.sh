#!/bin/sh
# Caddy entrypoint — generates the right Caddyfile based on environment.
#
# With SNAPPER_DOMAIN set:
#   Caddy serves on :80/:443 with auto Let's Encrypt certificate.
#   No more "Not Secure" browser warnings.
#
# Without SNAPPER_DOMAIN (default):
#   Caddy serves on :8443 with a self-signed internal certificate.
#   Good for local development and testing.

set -e

if [ -n "$SNAPPER_DOMAIN" ]; then
  echo "Caddy: domain mode — $SNAPPER_DOMAIN (Let's Encrypt)"
  cat > /etc/caddy/Caddyfile <<EOF
{
  servers {
    listener_wrappers {
      http_redirect
      tls
    }
  }
}

$SNAPPER_DOMAIN {
  header Strict-Transport-Security "max-age=31536000"
  reverse_proxy app:8000
}
EOF
else
  echo "Caddy: local mode — https://localhost:8443 (self-signed)"
  cat > /etc/caddy/Caddyfile <<EOF
{
  auto_https disable_redirects
  servers :8443 {
    listener_wrappers {
      http_redirect
      tls
    }
  }
}

:8443 {
  tls internal
  header Strict-Transport-Security "max-age=31536000"
  reverse_proxy app:8000
}
EOF
fi

exec caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
