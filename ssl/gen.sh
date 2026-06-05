#!/usr/bin/env bash
# Generate а local self-signed dev cert + private key.  NOT for production.
#
# Hardening notes:
#   * `umask 077` ensures generated `key.pem` is owner-readable only (0600)
#     even if the openssl invocation doesn't set explicit perms.
#   * `set -euo pipefail` aborts on any failure so partial output isn't
#     left behind.
#   * The .pem files are excluded от Docker context via `.dockerignore` к
#     prevent accidental leakage into a build context.

set -euo pipefail
umask 077

openssl req -x509 -newkey rsa:4096 -sha256 -days 365 \
  -nodes \
  -keyout ssl/key.pem \
  -out ssl/cert.pem \
  -subj "/CN=example.local" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth" \
  -addext "subjectAltName=DNS:example.local"

# Belt-and-braces: enforce 0600 on the private key in case the user's
# umask was already restrictive (no-op) или openssl created the file
# с broader perms (some versions ignore umask for -keyout).
chmod 600 ssl/key.pem
chmod 644 ssl/cert.pem
