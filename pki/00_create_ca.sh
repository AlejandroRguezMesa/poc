#!/usr/bin/env bash
# Crea la CA root de laboratorio (representa GÉANT TCS / ADCS / Sectigo).
set -euo pipefail
cd "$(dirname "$0")"

mkdir -p ca
cd ca

if [[ -f ca.key && -f ca.crt ]]; then
  echo "CA ya existe en pki/ca/ — usa rm -rf pki/ca para regenerar."
  exit 0
fi

openssl genrsa -out ca.key 4096 2>/dev/null
openssl req -x509 -new -nodes -sha256 -days 3650 \
  -key ca.key -out ca.crt \
  -subj "/C=ES/ST=Las Palmas/O=ULPGC Lab CA/CN=ULPGC Lab Root CA" 2>/dev/null

echo "✓ CA creada en pki/ca/"
openssl x509 -in ca.crt -noout -subject -dates
