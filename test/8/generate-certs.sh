#!/usr/bin/env sh
set -eu

target_dir=${CERTS_DIR:-/certs}
mkdir -p "$target_dir"

if [ -f "$target_dir/ca.crt" ] && [ -f "$target_dir/tls.key" ] && [ -f "$target_dir/tls.crt" ]; then
  echo "Certificates already exist; skipping generation"
  exit 0
fi

echo "Generating self-signed CA and server certificate..."
openssl genrsa -out "$target_dir/ca.key" 4096
openssl req -x509 -new -nodes -key "$target_dir/ca.key" -sha256 -days 3650 -out "$target_dir/ca.crt" -subj "/CN=es-ca"

cat > "$target_dir/openssl.cnf" <<'CFG'
[ req ]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = req_ext

[ dn ]
CN = elasticsearch-shared

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = es01
DNS.2 = es02
DNS.3 = es03
DNS.4 = localhost
IP.1 = 127.0.0.1
CFG

openssl genrsa -out "$target_dir/tls.key" 2048
openssl req -new -key "$target_dir/tls.key" -out "$target_dir/tls.csr" -config "$target_dir/openssl.cnf"
openssl x509 -req -in "$target_dir/tls.csr" -CA "$target_dir/ca.crt" -CAkey "$target_dir/ca.key" -CAcreateserial -out "$target_dir/tls.crt" -days 1825 -sha256 -extensions req_ext -extfile "$target_dir/openssl.cnf"

chmod 600 "$target_dir"/tls.key "$target_dir"/ca.key
