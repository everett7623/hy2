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
! detect_arch armv7l >/dev/null 2>&1

[ "$(build_release_url v0.0.13 amd64)" = "https://github.com/anytls/anytls-go/releases/download/v0.0.13/anytls_0.0.13_linux_amd64.zip" ]
! build_release_url latest amd64 >/dev/null 2>&1
! build_release_url v0.0.13 armv7 >/dev/null 2>&1

[ "$(listen_address)" = "0.0.0.0:" ]
LISTEN_PORT=8443; BIND_FAMILY=v6
[ "$(listen_address)" = "[::]:8443" ]
[ "$(render_uri '2001:db8::1' 8443 'Abcdef12' 'AnyTLS Test')" = "anytls://Abcdef12@[2001:db8::1]:8443/?insecure=1#AnyTLS%20Test" ]

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
ANYTLS_DIR="$tmp/etc"; ANYTLS_CONFIG="$ANYTLS_DIR/config.env"; ANYTLS_META="$ANYTLS_DIR/meta"
LISTEN_PORT=8443; EXT_PORT=9443; PASSWORD=Abcdef12; NAT_MODE=1; BIND_FAMILY=v6
write_config
LISTEN_PORT=""; EXT_PORT=""; PASSWORD=""; NAT_MODE=0; BIND_FAMILY=v4
read_config
[ "$LISTEN_PORT:$EXT_PORT:$PASSWORD:$NAT_MODE:$BIND_FAMILY" = "8443:9443:Abcdef12:1:v6" ]
[ -z "$PUBLIC_IP" ] && [ -z "$PUBLIC_IPV6" ]

SYSTEMD_SERVICE="$tmp/anytls.service"; ANYTLS_BIN=/usr/local/bin/anytls-server
write_systemd_service
grep -q '^ExecStart=/usr/local/bin/anytls-server -l \[::\]:8443 -p Abcdef12$' "$SYSTEMD_SERVICE"
case "$(uname -s)" in
    MINGW*|MSYS*) ;;
    *) [ "$(stat -c %a "$SYSTEMD_SERVICE")" = 600 ] ;;
esac

printf '\177ELFtest' > "$tmp/server"
validate_elf "$tmp/server"
printf 'html' > "$tmp/bad"
! validate_elf "$tmp/bad"

echo "AnyTLS behavior validation passed."
