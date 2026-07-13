#!/bin/bash
set -eu
trap 'echo "AnyTLS validation failed at line $LINENO" >&2' ERR

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
[ "$(normalize_version_tag 'https://github.com/SagerNet/sing-box/releases/tag/v1.13.14')" = "v1.13.14" ]
[ "$(normalize_version_tag '1.13.14')" = "v1.13.14" ]
! normalize_version_tag latest >/dev/null 2>&1
curl() { return 1; }
LAST_VERSION_TAG=""
get_latest_version >/dev/null
[ "$LAST_VERSION_TAG" = "$SING_BOX_STABLE_FALLBACK_TAG" ]
unset -f curl

# 公网地址接口返回格式异常时不得作为节点 IPv4。
is_valid_ipv4 '0.0.0.0'
is_valid_ipv4 '203.0.113.10'
is_valid_ipv4 '255.255.255.255'
! is_valid_ipv4 '256.0.0.1'
! is_valid_ipv4 '999.999.999.999'
! is_valid_ipv4 '1.2.3'
! is_valid_ipv4 '1.2.3.4.example'
is_valid_ipv6 '2001:db8::10'
! is_valid_ipv6 'upstream:error'
! is_valid_ipv6 '<html>:error'

# WARP 开启时必须绑定原生网卡查询公网入口，不能导出 WARP 出口地址。
ip() {
    case "$*" in
        '-4 route show default') printf '%s\n' 'default dev warp0' 'default via 192.0.2.1 dev eth0' ;;
        '-4 addr show dev eth0 scope global') printf '%s\n' '    inet 192.0.2.10/24 scope global eth0' ;;
        '-4 addr show scope global') printf '%s\n' '2: eth0: <UP>' '    inet 203.0.113.10/24 scope global eth0' ;;
        '-6 addr show scope global') return 0 ;;
        'addr show') printf '%s\n' '2: eth0    inet 203.0.113.10/24 scope global eth0' ;;
        'link show') printf '%s\n' '1: lo: <UP>' '3: warp0: <UP>' ;;
        *) return 0 ;;
    esac
}
curl() {
    case " $* " in
        *' --interface 192.0.2.10 '*) printf '%s' '203.0.113.10' ;;
        *' -s4 '*) printf '%s' '104.28.195.185' ;;
        *) return 1 ;;
    esac
}
detect_network >/dev/null
[ "$PUBLIC_IP" = "203.0.113.10" ]
[ "$PUBLIC_IP" != "104.28.195.185" ]
[ "$DEFAULT_EGRESS_IPV4" = "104.28.195.185" ]
[ "$WARP_ACTIVE" = "1" ]
[ "$NAT_MODE" = "0" ]
unset -f ip curl

LISTEN_PORT=8443; BIND_FAMILY=v6
[ "$(listen_address)" = "[::]:8443" ]
[ "$(render_uri '2001:db8::1' 8443 'Abcdef12' 'AnyTLS Test' 'www.example.com')" = "anytls://Abcdef12@[2001:db8::1]:8443?security=tls&sni=www.example.com&fp=chrome&insecure=1#AnyTLS%20Test" ]

PASSWORD=Abcdef12; SERVER_NAME=www.example.com
shadowrocket_uri=$(export_shadowrocket_anytls 192.0.2.1 8443 'AnyTLS Test' 'TestPin+/=')
[ "$shadowrocket_uri" = "anytls://Abcdef12@192.0.2.1:8443?security=tls&sni=www.example.com&fp=chrome&insecure=1#AnyTLS%20Test" ]
certificate_public_key_sha256() { printf 'TestPin+/='; }
certificate_fingerprint_sha256() { printf 'AA:BB:CC:DD'; }
node_output=$(show_node 192.0.2.1 8443 v4)
echo "$node_output" | grep -q 'URI 分享链接'
! echo "$node_output" | grep -q 'Throne URI'
! echo "$node_output" | grep -q 'tls_certificate_public_key_sha256='
echo "$node_output" | grep -q 'type: anytls, server: 192.0.2.1, port: 8443'
echo "$node_output" | grep -q "password: 'Abcdef12'"
echo "$node_output" | grep -q "sni: 'www.example.com'"
echo "$node_output" | grep -q "skip-cert-verify: false, fingerprint: 'AA:BB:CC:DD'"
! echo "$node_output" | grep -q 'password: "Abcdef12"'
[ "$(yaml_single_quote_escape "a'b")" = "a''b" ]
echo "$node_output" | grep -q '证书校验'
echo "$node_output" | grep -q '公钥 SHA256 Pin: TestPin+/='
echo "$node_output" | grep -q '证书 SHA256 指纹: AA:BB:CC:DD'
echo "$node_output" | grep -q '严格模式: Mihomo / Surfboard 可使用证书指纹'
echo "$node_output" | grep -q '兼容模式: URI / Shadowrocket / Loon 使用 skip-cert-verify=true'
! echo "$node_output" | grep -q '当前模式: skip-cert-verify=true'
! echo "$node_output" | grep -q 'Sing-box'
! echo "$node_output" | grep -q '"outbounds"'
! echo "$node_output" | grep -q '完整 Sing-box / SFA TUN'
echo "$node_output" | grep -q 'Shadowrocket 配置'
! echo "$node_output" | grep -q 'Shadowrocket 暂不支持 AnyTLS URI 导入格式'
! echo "$node_output" | grep -q '"listen_port": 2080'

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

# 升级后读取旧元数据时，应自动修正曾保存的 WARP 出口地址。
printf '%s' '104.28.195.185' > "$ANYTLS_META/public_ip"
PUBLIC_IP=""; PUBLIC_IPV6=""
detect_warp() { return 0; }
get_native_public_ipv4() { printf '%s' '203.0.113.10'; }
get_default_public_ipv4() { printf '%s' '104.28.195.185'; }
read_config_live
[ "$PUBLIC_IP" = '203.0.113.10' ]
[ "$(cat "$ANYTLS_META/public_ip")" = '203.0.113.10' ]

# 原生入口查询失败时，不得继续导出已确认的 WARP 出口。
printf '%s' '104.28.195.185' > "$ANYTLS_META/public_ip"
PUBLIC_IP=""; PUBLIC_IPV6=""
get_native_public_ipv4() { return 1; }
read_config_live
[ -z "$PUBLIC_IP" ]
[ ! -s "$ANYTLS_META/public_ip" ]
unset -f detect_warp get_native_public_ipv4 get_default_public_ipv4

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
service_is_active() { return 0; }
service_is_enabled() { return 0; }
service_stop() { : > "$tmp/stopped"; }
service_disable() { : > "$tmp/disabled"; }
service_enable() { : > "$tmp/enabled"; }
service_start() { : > "$tmp/restarted"; }
trap -p INT > "$tmp/int-trap-before"
backup_current_install
printf 'broken' > "$ANYTLS_CONFIG"
printf 'broken' > "$SING_BOX_BIN"
restore_current_install
grep -q '"type": "anytls"' "$ANYTLS_CONFIG"
grep -q 'sing-box version 1.13.14' "$SING_BOX_BIN"
[ -f "$tmp/disabled" ]
[ -f "$tmp/enabled" ]
[ -f "$tmp/restarted" ]
trap -p INT > "$tmp/int-trap-after"
cmp -s "$tmp/int-trap-before" "$tmp/int-trap-after"

# Ctrl+C/TERM 处理器必须回滚半成品并保留标准退出码。
rm -f "$tmp/stopped" "$tmp/disabled" "$tmp/enabled" "$tmp/restarted"
backup_current_install
printf 'interrupted' > "$ANYTLS_CONFIG"
trap - ERR
set +e
(rollback_install_on_signal 130) 2>/dev/null
rollback_status=$?
set -e
trap 'echo "AnyTLS validation failed at line $LINENO" >&2' ERR
[ "$rollback_status" = '130' ]
grep -q '"type": "anytls"' "$ANYTLS_CONFIG"
[ -f "$tmp/enabled" ]
[ -f "$tmp/restarted" ]
INSTALL_BACKUP_DIR=""
disarm_install_rollback

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
