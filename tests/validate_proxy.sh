#!/bin/bash
set -eu
trap 'echo "HTTP/SOCKS proxy validation failed at line $LINENO" >&2' ERR

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

PROXY_LIB_ONLY=1 . ./proxy.sh

validate_port 1
validate_port 65535
! validate_port 0
! validate_port 65536
! validate_port abc
random_port=$(generate_random_port)
validate_port "$random_port"
[ "$random_port" -ge 10000 ]

validate_username proxy_user
validate_username Abc._-
! validate_username ab
! validate_username 'bad user'
! validate_username 'bad@user'

validate_password Abcdef12._~-
! validate_password short
! validate_password 'bad password'
! validate_password 'bad@pass'
validate_server_address 192.0.2.1
validate_server_address 2001:db8::1
! validate_server_address 'bad"address'

NAT_MODE=0
generate_random_port() { printf '45679'; }
configure_proxy >/dev/null <<'EOF'



EOF
[ "$LISTEN_PORT:$EXT_PORT" = '45679:45679' ]
validate_username "$PROXY_USER"
validate_password "$PROXY_PASS"
unset -f generate_random_port

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
[ "$BIND_INTERFACE" = "eth0" ]
unset -f ip curl

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

PROXY_DIR="$tmp/etc"; PROXY_CONFIG="$PROXY_DIR/proxy.json"
PROXY_META="$PROXY_DIR/proxy-meta"
SING_BOX_MANAGED_MARKER="$PROXY_DIR/.singbox-tools-managed"
LISTEN_PORT=1080; EXT_PORT=1080; PROXY_USER=proxyuser; PROXY_PASS=Abcdef12
NAT_MODE=0; BIND_FAMILY=v4; LISTEN_HOST=::; MANAGED_SING_BOX=1
PUBLIC_IP=""; PUBLIC_IPV6=""; BIND_INTERFACE=""

get_native_egress_interface() { return 1; }
write_config
grep -q '"type": "mixed"' "$PROXY_CONFIG"
grep -q '"listen_port": 1080' "$PROXY_CONFIG"
grep -q '"listen": "::"' "$PROXY_CONFIG"
grep -q '"username": "proxyuser"' "$PROXY_CONFIG"
grep -q '"password": "Abcdef12"' "$PROXY_CONFIG"
grep -q '"type": "direct"' "$PROXY_CONFIG"
! grep -q 'bind_interface' "$PROXY_CONFIG"
[ -z "$(find "$PROXY_DIR" -type f -name '*.new.*' -print -quit)" ]

BIND_INTERFACE=eth0
write_config
grep -q '"type": "mixed"' "$PROXY_CONFIG"
grep -q '"username": "proxyuser"' "$PROXY_CONFIG"
grep -q '"password": "Abcdef12"' "$PROXY_CONFIG"
grep -q '"type": "direct"' "$PROXY_CONFIG"
grep -q '"bind_interface": "eth0"' "$PROXY_CONFIG"

# 临时文件创建失败时不得截断当前可用配置。
config_before=$(cat "$PROXY_CONFIG")
mktemp() { return 1; }
! write_config
unset -f mktemp
[ "$(cat "$PROXY_CONFIG")" = "$config_before" ]

LISTEN_PORT=""; EXT_PORT=""; PROXY_USER=""; PROXY_PASS=""; NAT_MODE=0
BIND_FAMILY=v4; LISTEN_HOST=""; BIND_INTERFACE=""; MANAGED_SING_BOX=0
read_config
[ "$LISTEN_PORT:$EXT_PORT:$PROXY_USER:$PROXY_PASS:$NAT_MODE:$BIND_FAMILY:$LISTEN_HOST:$BIND_INTERFACE:$MANAGED_SING_BOX" = "1080:1080:proxyuser:Abcdef12:0:v4::::eth0:1" ]

# check_config 依赖真实 sing-box；缺失时可被 mock，不要求本机安装核心。
SING_BOX_BIN="$tmp/missing-sing-box"
! check_config >/dev/null 2>&1
check_config() { return 0; }
check_config
unset -f check_config

SYSTEMD_SERVICE="$tmp/proxy.service"; PROXY_BIN=/usr/local/bin/proxy-server
write_systemd_service
grep -q '^ExecStart=/usr/local/bin/proxy-server$' "$SYSTEMD_SERVICE"
grep -q 'HTTP/SOCKS Proxy Server' "$SYSTEMD_SERVICE"

OPENRC_SERVICE="$tmp/proxy-openrc"
write_openrc_service
grep -q 'name="proxy-server"' "$OPENRC_SERVICE"
grep -q 'pidfile="/var/run/proxy-server.pid"' "$OPENRC_SERVICE"

SING_BOX_BIN=/usr/local/bin/sing-box; PROXY_BIN="$tmp/proxy-server"
write_wrapper
grep -q '^exec "/usr/local/bin/sing-box" run -c ' "$PROXY_BIN"

# 候选核心必须能加载共享目录内的全部 JSON，任一失败都要拒绝替换。
cat > "$tmp/shared-check-bin" <<'EOF'
#!/bin/sh
case "$1" in
  check) ! grep -q '"invalid": true' "$3" ;;
  *) exit 1 ;;
esac
EOF
chmod +x "$tmp/shared-check-bin"
validate_shared_configs_with_bin "$tmp/shared-check-bin"
printf '{"invalid": true}\n' > "$PROXY_DIR/anytls.json"
! validate_shared_configs_with_bin "$tmp/shared-check-bin" >/dev/null 2>&1
rm -f "$PROXY_DIR/anytls.json"

# active 但无 TCP 监听不得判定健康。
LISTEN_PORT=1080
service_is_active() { return 0; }
ss() { printf '%s\n' 'State Recv-Q Send-Q Local Address:Port' 'LISTEN 0 128 0.0.0.0:1080'; }
service_is_healthy
ss() { printf '%s\n' 'State Recv-Q Send-Q Local Address:Port' 'LISTEN 0 128 0.0.0.0:2080'; }
! service_is_healthy
unset -f ss service_is_active

# ensure_outbound_bind：memory 模式更新 BIND_INTERFACE；rewrite 在缺 bind 时回写 JSON。
LISTEN_PORT=1080; EXT_PORT=1080; PROXY_USER=proxyuser; PROXY_PASS=Abcdef12
NAT_MODE=0; BIND_FAMILY=v4; LISTEN_HOST=::; MANAGED_SING_BOX=1
BIND_INTERFACE=""; PUBLIC_IP=""; PUBLIC_IPV6=""
get_native_egress_interface() { return 1; }
write_config
! grep -q 'bind_interface' "$PROXY_CONFIG"
get_native_egress_interface() { printf 'eth0'; }
ensure_outbound_bind memory
[ "$BIND_INTERFACE" = "eth0" ]
! grep -q 'bind_interface' "$PROXY_CONFIG"
check_config() { return 0; }
ensure_outbound_bind rewrite >/dev/null
grep -q '"bind_interface": "eth0"' "$PROXY_CONFIG"
unset -f check_config get_native_egress_interface

printf '\177ELFtest' > "$tmp/server"
validate_elf "$tmp/server"
printf 'html' > "$tmp/bad"
! validate_elf "$tmp/bad"

echo 'HTTP/SOCKS proxy validation passed.'
