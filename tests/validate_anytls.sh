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
validate_server_name www.example.com
! validate_server_name localhost
! validate_server_name bad..example.com
! validate_server_name -bad.example.com
validate_server_address 192.0.2.1
validate_server_address 2001:db8::1
! validate_server_address 'bad"address'

case "$(random_sni)" in
    www.cloudflare.com|www.microsoft.com|www.apple.com|www.amazon.com|www.amd.com|www.bing.com|www.mozilla.org|www.github.com) ;;
    *) exit 1 ;;
esac

NAT_MODE=0
printf '\n\n\n' | configure_anytls >/dev/null

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

PASSWORD=Abcdef12; SERVER_NAME=www.example.com
shadowrocket_uri=$(export_shadowrocket_anytls 192.0.2.1 8443 'AnyTLS Test' 'TestPin+/=')
[ "$shadowrocket_uri" = "anytls://Abcdef12@192.0.2.1:8443?idle_session_check_interval=30s&idle_session_timeout=30s&min_idle_session=5&insecure=0&security=tls&sni=www.example.com&tls_certificate_public_key_sha256=TestPin%2B%2F%3D&fp=chrome#AnyTLS%20Test" ]
certificate_public_key_sha256() { printf 'TestPin+/='; }
certificate_fingerprint_sha256() { printf 'AA:BB:CC:DD'; }
node_output=$(show_node 192.0.2.1 8443 v4)
echo "$node_output" | grep -q 'URI 分享链接'
echo "$node_output" | grep -q 'Throne URI'
echo "$node_output" | grep -q 'tls_certificate_public_key_sha256=TestPin%2B%2F%3D'
echo "$node_output" | grep -q 'type: anytls, server: 192.0.2.1, port: 8443'
echo "$node_output" | grep -q 'skip-cert-verify: false, fingerprint: "AA:BB:CC:DD"'
echo "$node_output" | grep -q '证书校验'
echo "$node_output" | grep -q '公钥 SHA256 Pin: TestPin+/='
echo "$node_output" | grep -q '证书 SHA256 指纹: AA:BB:CC:DD'
echo "$node_output" | grep -q '严格模式: Throne / Shadowrocket / Mihomo / Surfboard / Sing-box'
! echo "$node_output" | grep -q '当前模式: skip-cert-verify=true'
echo "$node_output" | grep -q 'Sing-box'
echo "$node_output" | grep -q '"outbounds"'
echo "$node_output" | grep -q '"type": "anytls"'
echo "$node_output" | grep -q 'Path to each client configuration file: /etc/sing-box/subscribe/'
echo "$node_output" | grep -q 'https://github.com/chika0801/sing-box-examples/tree/main/Tun'
! echo "$node_output" | grep -q '"type": "tun"'
! echo "$node_output" | grep -q '"inbounds"'
! echo "$node_output" | grep -q '"route"'
echo "$node_output" | grep -q 'Shadowrocket 配置'
! echo "$node_output" | grep -q 'Shadowrocket 暂不支持 AnyTLS URI 导入格式'
! echo "$node_output" | grep -q '"listen_port": 2080'

client_config=$(render_singbox_client_config 192.0.2.1 8443 Abcdef12 AnyTLS-Test www.example.com 'TestPin+/=')
echo "$client_config" | grep -q '"outbounds"'
echo "$client_config" | grep -q '"type": "anytls"'
echo "$client_config" | grep -q '"min_idle_session": 5'
! echo "$client_config" | grep -q '"inbounds"'
! echo "$client_config" | grep -q '"route"'
echo "$client_config" | grep -q '"certificate_public_key_sha256": \["TestPin+/="\]'

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
ANYTLS_DIR="$tmp/etc"; ANYTLS_CONFIG="$ANYTLS_DIR/anytls.json"
ANYTLS_META="$ANYTLS_DIR/anytls-meta"; ANYTLS_CERT_DIR="$ANYTLS_DIR/anytls-cert"
ANYTLS_CERT="$ANYTLS_CERT_DIR/cert.pem"; ANYTLS_KEY="$ANYTLS_CERT_DIR/private.key"
LISTEN_PORT=8443; EXT_PORT=9443; PASSWORD=Abcdef12; NAT_MODE=1; BIND_FAMILY=v6
LISTEN_HOST=::; SERVER_NAME=www.example.com; MANAGED_SING_BOX=1; PUBLIC_IP=""; PUBLIC_IPV6=""
case "$(uname -s)" in
    MINGW*|MSYS*) ;;
    *)
        generate_certificate force
        [ -s "$ANYTLS_CERT" ] && [ -s "$ANYTLS_KEY" ]
        openssl x509 -in "$ANYTLS_CERT" -noout -checkend 60 >/dev/null 2>&1
        ;;
esac
write_config
grep -q '"type": "anytls"' "$ANYTLS_CONFIG"
grep -q '"listen_port": 8443' "$ANYTLS_CONFIG"
grep -q '"listen": "::"' "$ANYTLS_CONFIG"
grep -q '"server_name": "www.example.com"' "$ANYTLS_CONFIG"
LISTEN_PORT=""; EXT_PORT=""; PASSWORD=""; NAT_MODE=0; BIND_FAMILY=v4; LISTEN_HOST=""; SERVER_NAME=""; MANAGED_SING_BOX=0
read_config
[ "$LISTEN_PORT:$EXT_PORT:$PASSWORD:$NAT_MODE:$BIND_FAMILY:$LISTEN_HOST:$SERVER_NAME:$MANAGED_SING_BOX" = "8443:9443:Abcdef12:1:v6::::www.example.com:1" ]
PUBLIC_IP=192.0.2.1; PUBLIC_IPV6=2001:db8::1
read_config

SYSTEMD_SERVICE="$tmp/anytls.service"; ANYTLS_BIN=/usr/local/bin/anytls-server
write_systemd_service
grep -q '^ExecStart=/usr/local/bin/anytls-server$' "$SYSTEMD_SERVICE"

SING_BOX_BIN=/usr/local/bin/sing-box; ANYTLS_BIN="$tmp/anytls-server"
write_wrapper
grep -q '^exec "/usr/local/bin/sing-box" run -c ' "$ANYTLS_BIN"

# 重装备份必须能恢复原配置和二进制。
INIT_SYS=none
SING_BOX_BIN="$tmp/sing-box"
printf '#!/bin/sh\necho "sing-box version 1.13.14"\n' > "$SING_BOX_BIN"
chmod +x "$SING_BOX_BIN"
ANYTLS_BIN="$tmp/anytls-server"
write_wrapper
backup_current_install
printf 'broken' > "$ANYTLS_CONFIG"
printf 'broken' > "$SING_BOX_BIN"
restore_current_install
grep -q '"type": "anytls"' "$ANYTLS_CONFIG"
grep -q 'sing-box version 1.13.14' "$SING_BOX_BIN"

# 已是最新版时不得重复下载或替换二进制。
get_latest_version() { LAST_VERSION_TAG=v1.13.14; return 0; }
upgrade_output=$(upgrade_core)
echo "$upgrade_output" | grep -q '已是最新版本 1.13.14'

# 卸载只能删除 AnyTLS 产物，存在其他 sing-box 配置时必须保留目录与核心。
printf '{}' > "$ANYTLS_DIR/other.json"
SYSTEMD_SERVICE="$tmp/anytls.service"
OPENRC_SERVICE="$tmp/anytls-openrc"
AUTO_UPDATE_SCRIPT="$tmp/anytls-autoupdate.sh"
AUTO_UPDATE_LOG="$tmp/anytls-autoupdate.log"
MANAGED_SING_BOX=1
sleep() { :; }
service_stop() { :; }
service_disable() { :; }
close_ports() { :; }
printf 'y\n' | uninstall_anytls >/dev/null
[ -f "$ANYTLS_DIR/other.json" ]
[ -f "$SING_BOX_BIN" ]
[ ! -e "$ANYTLS_CONFIG" ]
[ ! -e "$ANYTLS_META" ]
[ ! -e "$ANYTLS_CERT_DIR" ]

printf '\177ELFtest' > "$tmp/server"
validate_elf "$tmp/server"
printf 'html' > "$tmp/bad"
! validate_elf "$tmp/bad"

echo "AnyTLS behavior validation passed."
