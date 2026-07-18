#!/bin/bash
set -eu
trap 'echo "VLESS validation failed at line $LINENO" >&2' ERR

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

VLESS_LIB_ONLY=1 . ./vless.sh

TEST_UUID=bf000d23-0752-40b4-affe-68f7707a9661
TEST_PRIVATE_KEY=UuMBgl7MXTPx9inmQp2UC7Jcnwc6XYbwDNebonM-FCc
TEST_PUBLIC_KEY=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0
TEST_SHORT_ID=0123456789abcdef

validate_port 1
validate_port 65535
! validate_port 0
! validate_port 65536
! validate_port abc
random_port=$(generate_random_port)
validate_port "$random_port"
[ "$random_port" -ge 10000 ]
validate_uuid "$TEST_UUID"
! validate_uuid bad-uuid
validate_reality_key "$TEST_PRIVATE_KEY"
validate_reality_key "$TEST_PUBLIC_KEY"
! validate_reality_key short
validate_short_id 01
validate_short_id "$TEST_SHORT_ID"
! validate_short_id 0
! validate_short_id 0123456789abcdef00
! validate_short_id z1
validate_server_name www.example.com
! validate_server_name localhost
! validate_server_name bad..example.com
validate_server_address 192.0.2.1
validate_server_address 2001:db8::1
! validate_server_address 'bad"address'
! reality_target_candidates | grep -qE '(^|\.)(cn)$|github|bing'
ss() { printf '%s\n' 'Netid State Recv-Q Send-Q Local Address:Port' 'tcp LISTEN 0 128 0.0.0.0:45678'; }
port_is_listening 45678
! port_is_listening 45679
unset -f ss
curl() {
    case "$*" in
        '--help all') printf '%s\n' '--tls-max' ;;
        *'www.apple.com'*) return 0 ;;
        *) return 1 ;;
    esac
}
reality_target_usable www.apple.com 443
! reality_target_usable www.microsoft.com 443
unset -f curl
reality_target_usable() { [ "$1" = 'www.apple.com' ]; }
[ "$(select_reality_target 443)" = 'www.apple.com' ]
unset -f reality_target_usable

[ "$(detect_arch x86_64)" = amd64 ]
[ "$(detect_arch aarch64)" = arm64 ]
[ "$(detect_arch armv7l)" = armv7 ]
! detect_arch mips >/dev/null 2>&1
[ "$(build_release_url v1.13.14 amd64)" = "https://github.com/SagerNet/sing-box/releases/download/v1.13.14/sing-box-1.13.14-linux-amd64.tar.gz" ]
version_at_least 1.12.0 1.12.0
version_at_least 1.13.1 1.12.0
! version_at_least 1.11.9 1.12.0

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

# AnyTLS 与 VLESS 共用核心，升级锁必须拒绝并发任务。
UPGRADE_LOCK_FILE="$tmp/sing-box-tools-upgrade.lock"
lock_busy=0
flock() { [ "$1" = '-u' ] && return 0; [ "$lock_busy" = '0' ]; }
acquire_upgrade_lock
release_upgrade_lock
lock_busy=1
! acquire_upgrade_lock
lock_busy=0
unset -f flock

SING_BOX_BIN="$tmp/sing-box"
cat > "$SING_BOX_BIN" <<'EOF'
#!/bin/sh
case "${1:-} ${2:-}" in
  "generate uuid") echo "bf000d23-0752-40b4-affe-68f7707a9661" ;;
  "generate reality-keypair")
    echo "PrivateKey: UuMBgl7MXTPx9inmQp2UC7Jcnwc6XYbwDNebonM-FCc"
    echo "PublicKey: jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"
    ;;
  "check -c") exit 0 ;;
  *) echo "sing-box version 1.13.14" ;;
esac
EOF
chmod +x "$SING_BOX_BIN"

[ "$(generate_uuid)" = "$TEST_UUID" ]
REALITY_PRIVATE_KEY=""
REALITY_PUBLIC_KEY=""
generate_reality_keypair
[ "$REALITY_PRIVATE_KEY" = "$TEST_PRIVATE_KEY" ]
[ "$REALITY_PUBLIC_KEY" = "$TEST_PUBLIC_KEY" ]
generated_short_id=$(generate_short_id)
validate_short_id "$generated_short_id"

generate_uuid() { printf '%s' "$TEST_UUID"; }
generate_reality_keypair() {
    REALITY_PRIVATE_KEY="$TEST_PRIVATE_KEY"
    REALITY_PUBLIC_KEY="$TEST_PUBLIC_KEY"
}
generate_short_id() { printf '%s' "$TEST_SHORT_ID"; }
generate_random_port() { printf '45678'; }
select_reality_target() { printf 'www.apple.com'; }
NAT_MODE=0
configure_vless >/dev/null <<'EOF'




EOF
[ "$LISTEN_PORT:$EXT_PORT:$UUID:$SERVER_NAME:$HANDSHAKE_PORT:$SHORT_ID" = "45678:45678:$TEST_UUID:www.apple.com:443:$TEST_SHORT_ID" ]
unset -f generate_random_port select_reality_target

curl() { printf '1250000'; }
[ "$(probe_vps_download_mbps)" = '10.0' ]
unset -f curl

LISTEN_PORT=8443
BIND_FAMILY=v6
[ "$(listen_address)" = "[::]:8443" ]
uri=$(render_uri 2001:db8::1 8443 "$TEST_UUID" "VLESS Test" www.example.com "$TEST_PUBLIC_KEY" "$TEST_SHORT_ID")
[ "$uri" = "vless://$TEST_UUID@[2001:db8::1]:8443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.example.com&fp=chrome&pbk=$TEST_PUBLIC_KEY&sid=$TEST_SHORT_ID&type=tcp#VLESS%20Test" ]

UUID="$TEST_UUID"
REALITY_PRIVATE_KEY="$TEST_PRIVATE_KEY"
REALITY_PUBLIC_KEY="$TEST_PUBLIC_KEY"
SHORT_ID="$TEST_SHORT_ID"
SERVER_NAME=www.example.com
HANDSHAKE_PORT=443

mihomo=$(export_mihomo_vless 192.0.2.1 8443 "VLESS Test")
echo "$mihomo" | grep -q "type: vless"
echo "$mihomo" | grep -q "uuid: $TEST_UUID"
echo "$mihomo" | grep -q "flow: xtls-rprx-vision"
echo "$mihomo" | grep -q "public-key: $TEST_PUBLIC_KEY"
echo "$mihomo" | grep -q "short-id: $TEST_SHORT_ID"
loon=$(export_loon_vless 192.0.2.1 8443 "VLESS Test")
echo "$loon" | grep -q 'transport=tcp'
echo "$loon" | grep -q 'flow=xtls-rprx-vision'
quantumult=$(export_quantumultx_vless 2001:db8::1 8443 "VLESS Test")
echo "$quantumult" | grep -q "^vless=\[2001:db8::1\]:8443"
echo "$quantumult" | grep -q "reality-base64-pubkey=$TEST_PUBLIC_KEY"
echo "$quantumult" | grep -q "vless-flow=xtls-rprx-vision"
export_surfboard_vless | grep -q '暂无经官方文档确认'

VLESS_DIR="$tmp/etc"
VLESS_CONFIG="$VLESS_DIR/vless.json"
VLESS_META="$VLESS_DIR/vless-meta"
SING_BOX_MANAGED_MARKER="$VLESS_DIR/.singbox-tools-managed"
VLESS_BIN="$tmp/vless-server"
SYSTEMD_SERVICE="$tmp/vless.service"
OPENRC_SERVICE="$tmp/vless-openrc"
AUTO_UPDATE_SCRIPT="$tmp/vless-autoupdate.sh"
AUTO_UPDATE_LOG="$tmp/vless-autoupdate.log"
LISTEN_PORT=8443
EXT_PORT=9443
NAT_MODE=1
BIND_FAMILY=v6
LISTEN_HOST=::
MANAGED_SING_BOX=1
PUBLIC_IP=""
PUBLIC_IPV6=""

write_config
grep -q '"type": "vless"' "$VLESS_CONFIG"
grep -q '"uuid": "'"$TEST_UUID"'"' "$VLESS_CONFIG"
grep -q '"flow": "xtls-rprx-vision"' "$VLESS_CONFIG"
grep -q '"enabled": true' "$VLESS_CONFIG"
grep -q '"server": "www.example.com"' "$VLESS_CONFIG"
grep -q '"server_port": 443' "$VLESS_CONFIG"
grep -q '"private_key": "'"$TEST_PRIVATE_KEY"'"' "$VLESS_CONFIG"
grep -q '"short_id": \["'"$TEST_SHORT_ID"'"\]' "$VLESS_CONFIG"
! grep -q "$TEST_PUBLIC_KEY" "$VLESS_CONFIG"
[ -z "$(find "$VLESS_DIR" -type f -name '*.new.*' -print -quit)" ]

config_before=$(cat "$VLESS_CONFIG")
mktemp() { return 1; }
! write_config
unset -f mktemp
[ "$(cat "$VLESS_CONFIG")" = "$config_before" ]

LISTEN_PORT=""
EXT_PORT=""
UUID=""
REALITY_PRIVATE_KEY=""
REALITY_PUBLIC_KEY=""
SHORT_ID=""
NAT_MODE=0
BIND_FAMILY=v4
LISTEN_HOST=""
SERVER_NAME=""
HANDSHAKE_PORT=""
MANAGED_SING_BOX=0
read_config
[ "$LISTEN_PORT:$EXT_PORT:$UUID:$SHORT_ID:$NAT_MODE:$BIND_FAMILY:$LISTEN_HOST:$SERVER_NAME:$HANDSHAKE_PORT:$MANAGED_SING_BOX" = "8443:9443:$TEST_UUID:$TEST_SHORT_ID:1:v6::::www.example.com:443:1" ]

# 诊断正常路径：分别报告服务状态、监听地址、per-family REALITY 可达性和 VPS 直连结果。
(
read_config() { return 0; }
check_config() { return 0; }
service_is_active() { return 0; }
ss() { printf '%s\n' 'State Recv-Q Send-Q Local Address:Port' 'LISTEN 0 128 0.0.0.0:8443'; }
reality_target_usable_v4() { return 0; }
reality_target_usable_v6() { return 0; }
probe_vps_download_mbps() { printf '123.4'; }
sysctl() { printf 'bbr'; }
diagnose_output=$(diagnose_vless)
grep -q 'sing-box 配置有效' <<EOF
$diagnose_output
EOF
grep -q 'REALITY 握手目标' <<EOF
$diagnose_output
EOF
grep -q '监听地址' <<EOF
$diagnose_output
EOF
grep -q 'VPS 直连下载探测: 123.4 Mbps' <<EOF
$diagnose_output
EOF
grep -q 'TCP 拥塞控制: bbr' <<EOF
$diagnose_output
EOF
)

# 诊断：config 和 meta 均缺失时报告"均缺失"。
(
VLESS_CONFIG="$tmp/no-config.json"
VLESS_META="$tmp/no-meta-dir"
out=$(diagnose_vless 2>&1 || true)
grep -q '均缺失' <<EOF
$out
EOF
)

# 诊断：仅 config 缺失（meta 存在）时报告"配置文件缺失"。
(
VLESS_CONFIG="$tmp/no-config.json"
out=$(diagnose_vless 2>&1 || true)
grep -q '配置文件缺失' <<EOF
$out
EOF
)

# 诊断：仅 meta 缺失（config 存在）时报告"元数据缺失"。
(
VLESS_META="$tmp/no-meta-dir"
out=$(diagnose_vless 2>&1 || true)
grep -q '元数据缺失' <<EOF
$out
EOF
)

# 诊断：元数据字段校验失败时报告具体字段名（非密钥字段显示原值）。
(
_bad_meta="$tmp/bad-meta"
mkdir -p "$_bad_meta"
printf 'LISTEN_PORT=not_a_port\n' > "$_bad_meta/config.env"
touch "$tmp/dummy-vless.json"
VLESS_CONFIG="$tmp/dummy-vless.json"
VLESS_META="$_bad_meta"
out=$(diagnose_vless 2>&1 || true)
grep -q 'LISTEN_PORT' <<EOF
$out
EOF
)

# wait_for_health：第三次才成功时应正常返回，且恰好尝试了三次。
(
_attempt=0
service_is_healthy() { _attempt=$((_attempt + 1)); [ "$_attempt" -ge 3 ]; }
sleep() { :; }
wait_for_health 5
[ "$_attempt" = "3" ]
)

# wait_for_health：达到轮询上限仍失败时返回非零。
(
service_is_healthy() { return 1; }
sleep() { :; }
! wait_for_health 3
)

# wait_for_health：第二参数可传自定义判定函数（升级路径给共享 AnyTLS 用）。
(
_shared_attempt=0
shared_anytls_service_is_active() { _shared_attempt=$((_shared_attempt + 1)); [ "$_shared_attempt" -ge 2 ]; }
service_is_healthy() { return 1; }   # 确认走的是自定义判定而非默认
sleep() { :; }
wait_for_health 5 shared_anytls_service_is_active
[ "$_shared_attempt" = "2" ]
)

# reality_target_usable_v4 和 _v6 分别透传 -4 / -6 旗标给 curl。
(
curl() {
    case "$*" in
        '--help all') printf '%s\n' '--tls-max' ;;
        *'-4'*'www.apple.com'*) return 0 ;;
        *'-6'*'www.apple.com'*) return 1 ;;
        *) return 1 ;;
    esac
}
reality_target_usable_v4 www.apple.com 443
! reality_target_usable_v6 www.apple.com 443
! reality_target_usable_v4 www.microsoft.com 443
unset -f curl
)

# has_default_ipv6_route：有默认 IPv6 路由为真，无输出为假。
(
ip() { case "$*" in '-6 route show default') printf 'default via fe80::1 dev eth0\n' ;; *) return 0 ;; esac; }
has_default_ipv6_route
unset -f ip
ip() { return 0; }
! has_default_ipv6_route
unset -f ip
)

# detect_network：接口有全局 IPv6 但外网不可达且无默认路由 → 判纯 IPv4，
# 避免向客户端下发死 IPv6 节点、避免 sing-box 握手拨向死 IPv6。
(
detect_warp() { return 1; }
get_default_public_ipv4() { printf '203.0.113.5'; }
get_native_public_ipv4() { printf '203.0.113.5'; }
curl() { return 1; }
has_default_ipv6_route() { return 1; }
ip() {
    case "$*" in
        '-6 addr show scope global') printf '2: eth0\n    inet6 2001:db8::5/64 scope global\n' ;;
        '-4 addr show scope global') printf '2: eth0\n    inet 203.0.113.5/24 scope global\n' ;;
        'addr show') printf '    inet 203.0.113.5/24\n' ;;
        *) return 1 ;;
    esac
}
detect_network >/dev/null 2>&1
[ "$HAS_IPV6" = "0" ]
[ "$HAS_IPV4" = "1" ]
[ "$LISTEN_HOST" = "0.0.0.0" ]
[ "$BIND_FAMILY" = "v4" ]
[ -z "$PUBLIC_IPV6" ]
)

# detect_network：接口有全局 IPv6 且存在默认路由 → 仍判双栈（正常机不受影响）。
(
detect_warp() { return 1; }
get_default_public_ipv4() { printf '203.0.113.5'; }
get_native_public_ipv4() { printf '203.0.113.5'; }
curl() { return 1; }
has_default_ipv6_route() { return 0; }
ip() {
    case "$*" in
        '-6 addr show scope global') printf '2: eth0\n    inet6 2001:db8::5/64 scope global\n' ;;
        '-4 addr show scope global') printf '2: eth0\n    inet 203.0.113.5/24 scope global\n' ;;
        'addr show') printf '    inet 203.0.113.5/24\n' ;;
        *) return 1 ;;
    esac
}
detect_network >/dev/null 2>&1
[ "$HAS_IPV6" = "1" ]
[ "$PUBLIC_IPV6" = "2001:db8::5" ]
[ "$BIND_FAMILY" = "v4" ]
)

# 最新版不重复替换；候选核心导致配置校验失败时必须恢复旧二进制。
get_latest_version() { LAST_VERSION_TAG=v1.13.14; }
upgrade_output=$(upgrade_core)
echo "$upgrade_output" | grep -q '已是最新版本 1.13.14'
get_latest_version() { LAST_VERSION_TAG=v1.13.15; }
download_vless() {
    printf '#!/bin/sh\necho "sing-box version 1.13.15"\n' > "$SING_BOX_BIN"
    chmod +x "$SING_BOX_BIN"
    MANAGED_SING_BOX=1
}
check_config() { return 1; }
! upgrade_core >/dev/null 2>&1
grep -q 'sing-box version 1.13.14' "$SING_BOX_BIN"
check_config() { return 0; }
shared_anytls_service_is_active() { return 0; }
shared_anytls_service_restart() { : > "$tmp/shared-anytls-restarted"; }
upgrade_core >/dev/null
[ -f "$tmp/shared-anytls-restarted" ]
grep -q 'sing-box version 1.13.15' "$SING_BOX_BIN"

get_country_code() { printf 'UN'; }
generate_server_name() { printf 'test-host'; }
node_output=$(show_node 192.0.2.1 9443 v4)
echo "$node_output" | grep -q 'URI 分享链接'
echo "$node_output" | grep -q 'Mihomo / Clash Meta'
echo "$node_output" | grep -q 'Quantumult X 配置'
echo "$node_output" | grep -q "公钥 Public Key: $TEST_PUBLIC_KEY"
echo "$node_output" | grep -q "Short ID: $TEST_SHORT_ID"
! echo "$node_output" | grep -q "$TEST_PRIVATE_KEY"

write_wrapper
grep -q '^exec "'"$SING_BOX_BIN"'" run -c ' "$VLESS_BIN"
write_systemd_service
grep -q '^ExecStart='"$VLESS_BIN"'$' "$SYSTEMD_SERVICE"
write_openrc_service
grep -q '^name="vless-server"$' "$OPENRC_SERVICE"

cat > "$tmp/check-bin" <<'EOF'
#!/bin/sh
case "$1" in
  check) ! grep -q '"invalid": true' "$3" ;;
  *) exit 1 ;;
esac
EOF
chmod +x "$tmp/check-bin"
validate_shared_configs_with_bin "$tmp/check-bin"
printf '{"invalid": true}\n' > "$VLESS_DIR/other.json"
! validate_shared_configs_with_bin "$tmp/check-bin" >/dev/null 2>&1
printf '{}\n' > "$VLESS_DIR/other.json"

service_is_active() { return 0; }
service_stop() { :; }
service_disable() { :; }
close_ports() { :; }
sleep() { :; }
: > "$SING_BOX_MANAGED_MARKER"
printf 'y\n' | uninstall_vless >/dev/null
[ -f "$VLESS_DIR/other.json" ]
[ -f "$SING_BOX_BIN" ]
[ -f "$SING_BOX_MANAGED_MARKER" ]
[ ! -e "$VLESS_CONFIG" ]
[ ! -e "$VLESS_META" ]

rm -f "$VLESS_DIR/other.json"
printf 'y\n' | uninstall_vless >/dev/null
[ ! -e "$SING_BOX_BIN" ]
[ ! -e "$SING_BOX_MANAGED_MARKER" ]

printf '\177ELFtest' > "$tmp/server"
validate_elf "$tmp/server"
printf 'html' > "$tmp/bad"
! validate_elf "$tmp/bad"

echo "VLESS behavior validation passed."
