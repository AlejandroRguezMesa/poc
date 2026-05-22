#!/usr/bin/env bash
# Emite los certificados "antiguos": caducan en 7 días.
# Representan el estado actual del entorno (certs próximos a caducar).
set -euo pipefail
cd "$(dirname "$0")"

mkdir -p old
CA=ca

issue() {
  local name=$1 cn=$2 sans=$3 days=$4

  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out "old/${name}.key" 2>/dev/null

  openssl req -new -key "old/${name}.key" -out "old/${name}.csr" \
    -subj "/C=ES/O=ULPGC/CN=${cn}" 2>/dev/null

  cat > "old/${name}.ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = ${sans}
EOF

  openssl x509 -req -in "old/${name}.csr" \
    -CA "${CA}/ca.crt" -CAkey "${CA}/ca.key" -CAcreateserial \
    -out "old/${name}.crt" -days "${days}" -sha256 \
    -extfile "old/${name}.ext" 2>/dev/null

  rm -f "old/${name}.csr" "old/${name}.ext"
  echo "  → old/${name}.crt (CN=${cn}, válido ${days} días)"
}

echo "Emitiendo certificados antiguos (estado 'producción', caducan pronto):"
issue "apps"   "apps.lab.ulpgc.local"   "DNS:apps.lab.ulpgc.local,DNS:www.apps.lab.ulpgc.local" 7
issue "portal" "portal.lab.ulpgc.local" "DNS:portal.lab.ulpgc.local"                             7
issue "secure" "secure.lab.ulpgc.local" "DNS:secure.lab.ulpgc.local" 7
issue "internal" "internal.lab.ulpgc.local" "DNS:internal.lab.ulpgc.local" 7
