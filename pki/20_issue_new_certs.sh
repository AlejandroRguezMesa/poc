#!/usr/bin/env bash
# Emite los certificados "nuevos": válidos 365 días.
# Representan la nueva remesa recibida desde la CA (GÉANT TCS, ADCS, etc.)
set -euo pipefail
cd "$(dirname "$0")"

mkdir -p new
CA=ca

issue() {
  local name=$1 cn=$2 sans=$3 days=$4

  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out "new/${name}.key" 2>/dev/null

  openssl req -new -key "new/${name}.key" -out "new/${name}.csr" \
    -subj "/C=ES/O=ULPGC/CN=${cn}" 2>/dev/null

  cat > "new/${name}.ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = ${sans}
EOF

  openssl x509 -req -in "new/${name}.csr" \
    -CA "${CA}/ca.crt" -CAkey "${CA}/ca.key" -CAcreateserial \
    -out "new/${name}.crt" -days "${days}" -sha256 \
    -extfile "new/${name}.ext" 2>/dev/null

  rm -f "new/${name}.csr" "new/${name}.ext"
  echo "  → new/${name}.crt (CN=${cn}, válido ${days} días)"
}

echo "Emitiendo certificados nuevos (recién renovados, 365 días):"
issue "apps"   "apps.lab.ulpgc.local"   "DNS:apps.lab.ulpgc.local,DNS:www.apps.lab.ulpgc.local" 365
issue "portal" "portal.lab.ulpgc.local" "DNS:portal.lab.ulpgc.local"                             365
issue "secure" "secure.lab.ulpgc.local" "DNS:secure.lab.ulpgc.local" 365
issue "internal" "internal.lab.ulpgc.local" "DNS:internal.lab.ulpgc.local" 365
