#!/bin/bash
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

ANYTLS_LIB_ONLY=1 . ./anytls.sh

validate_port 1
validate_port 65535
! validate_port 0
! validate_port 65536
! validate_port abc

validate_password Abcdef12._~-
! validate_password short
! validate_password 'bad password'

[ "$(detect_arch x86_64)" = amd64 ]
[ "$(detect_arch aarch64)" = arm64 ]
[ "$(detect_arch armv7l)" = armv7 ]
! detect_arch mips >/dev/null 2>&1

[ "$(build_release_url v1.13.12 amd64)" = "https://github.com/SagerNet/sing-box/releases/download/v1.13.12/sing-box-1.13.12-linux-amd64.tar.gz" ]
! build_release_url latest amd64 >/dev/null 2>&1
! build_release_url v1.13.12 mips >/dev/null 2>&1
version_at_least 1.12.0 1.12.0
version_at_least 1.13.1 1.12.0
! version_at_least 1.11.9 1.12.0

LISTEN_PORT=8443; BIND_FAMILY=v6
[ "$(listen_address)" = "[::]:8443" ]
[ "$(render_uri '2001:db8::1' 8443 'Abcdef12' 'AnyTLS Test' 'www.example.com')" = "anytls://Abcdef12@[2001:db8::1]:8443?security=tls&sni=www.example.com&fp=chrome&insecure=1#AnyTLS%20Test" ]

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
ANYTLS_DIR="$tmp/etc"; ANYTLS_CONFIG="$ANYTLS_DIR/anytls.json"
ANYTLS_META="$ANYTLS_DIR/anytls-meta"; ANYTLS_CERT_DIR="$ANYTLS_DIR/anytls-cert"
ANYTLS_CERT="$ANYTLS_CERT_DIR/cert.pem"; ANYTLS_KEY="$ANYTLS_CERT_DIR/private.key"
LISTEN_PORT=8443; EXT_PORT=9443; PASSWORD=Abcdef12; NAT_MODE=1; BIND_FAMILY=v6
SERVER_NAME=www.example.com; MANAGED_SING_BOX=1; PUBLIC_IP=""; PUBLIC_IPV6=""
write_config
grep -q '"type": "anytls"' "$ANYTLS_CONFIG"
grep -q '"listen_port": 8443' "$ANYTLS_CONFIG"
grep -q '"server_name": "www.example.com"' "$ANYTLS_CONFIG"
LISTEN_PORT=""; EXT_PORT=""; PASSWORD=""; NAT_MODE=0; BIND_FAMILY=v4; SERVER_NAME=""; MANAGED_SING_BOX=0
read_config
[ "$LISTEN_PORT:$EXT_PORT:$PASSWORD:$NAT_MODE:$BIND_FAMILY:$SERVER_NAME:$MANAGED_SING_BOX" = "8443:9443:Abcdef12:1:v6:www.example.com:1" ]

SYSTEMD_SERVICE="$tmp/anytls.service"; ANYTLS_BIN=/usr/local/bin/anytls-server
write_systemd_service
grep -q '^ExecStart=/usr/local/bin/anytls-server$' "$SYSTEMD_SERVICE"

SING_BOX_BIN=/usr/local/bin/sing-box; ANYTLS_BIN="$tmp/anytls-server"
write_wrapper
grep -q '^exec "/usr/local/bin/sing-box" run -c ' "$ANYTLS_BIN"

printf '\177ELFtest' > "$tmp/server"
validate_elf "$tmp/server"
printf 'html' > "$tmp/bad"
! validate_elf "$tmp/bad"

echo "AnyTLS behavior validation passed."
