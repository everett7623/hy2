#!/bin/bash
set -eu
trap 'echo "HTTP/SOCKS proxy validation failed at line $LINENO" >&2' ERR

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

bash tests/validate_recovery.sh proxy

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


# ---------------------------------------------------------------------------
# 公网 IP 探测站不可达时的 IPv4 兜底判定
# ---------------------------------------------------------------------------
# is_private_ipv4 边界：私网/CGNAT 端点必须命中，相邻公网段不得误判，
# 否则要么把私网地址写进分享链接，要么把正常公网 IP 当成 NAT。
is_private_ipv4 10.0.0.1
is_private_ipv4 192.168.1.1
is_private_ipv4 172.16.0.1
is_private_ipv4 172.31.255.254
is_private_ipv4 100.64.0.1
is_private_ipv4 100.127.255.254
! is_private_ipv4 172.15.0.1
! is_private_ipv4 172.32.0.1
! is_private_ipv4 100.63.255.255
! is_private_ipv4 100.128.0.1
! is_private_ipv4 203.0.113.5
! is_private_ipv4 198.51.100.38

# 双栈机的 IPv4 探测站全部不可达时，必须按“本机全局 IPv4 + 默认 IPv4 路由”认定 IPv4 可用。
# 缺少这个兜底会误判纯 IPv6，节点只下发 IPv6 地址，IPv4 客户端全部连不上。
(
PROXY_LIB_ONLY=1 . ./proxy.sh
detect_warp() { return 1; }
curl() { case " $* " in *' -s6 '*) printf '2001:db8::5' ;; *) return 1 ;; esac; }
ip() {
    case "$*" in
        '-4 route show default') printf 'default via 203.0.113.1 dev eth0\n' ;;
        '-6 route show default') printf 'default via fe80::1 dev eth0\n' ;;
        '-4 addr show dev eth0 scope global') printf '    inet 203.0.113.5/24 scope global eth0\n' ;;
        '-4 addr show scope global') printf '2: eth0\n    inet 203.0.113.5/24 scope global eth0\n' ;;
        '-6 addr show scope global') printf '2: eth0\n    inet6 2001:db8::5/64 scope global\n' ;;
        'addr show') printf '    inet 203.0.113.5/24\n' ;;
        *) return 1 ;;
    esac
}
detect_network >/dev/null 2>&1
[ "$HAS_IPV4" = "1" ]
[ "$HAS_IPV6" = "1" ]
[ "$PUBLIC_IP" = "203.0.113.5" ]
[ "$NAT_MODE" = "0" ]
[ "$BIND_FAMILY" = "v4" ]
[ "$IPV4_UNVERIFIED" = "1" ]
)

# 同样探测失败，但本机只有私网 IPv4：认定有 IPv4 并按 NAT 处理，
# 且绝不能把私网地址写进 PUBLIC_IP —— 它会直接进入分享链接。
(
PROXY_LIB_ONLY=1 . ./proxy.sh
detect_warp() { return 1; }
curl() { return 1; }
ip() {
    case "$*" in
        '-4 route show default') printf 'default via 10.0.0.1 dev eth0\n' ;;
        '-4 addr show dev eth0 scope global') printf '    inet 10.0.0.5/24 scope global eth0\n' ;;
        '-4 addr show scope global') printf '2: eth0\n    inet 10.0.0.5/24 scope global eth0\n' ;;
        'addr show') printf '    inet 10.0.0.5/24\n' ;;
        *) return 1 ;;
    esac
}
detect_network >/dev/null 2>&1
[ "$HAS_IPV4" = "1" ]
[ "$NAT_MODE" = "1" ]
[ -z "$PUBLIC_IP" ]
)

# WARP 网卡持有的 IPv4 不是原生 IPv4，探测失败时不得当作可用 IPv4 兜底。
(
PROXY_LIB_ONLY=1 . ./proxy.sh
detect_warp() { return 0; }
curl() { return 1; }
ip() {
    case "$*" in
        '-4 route show default') printf 'default dev warp0\n' ;;
        '-4 addr show scope global') printf '3: warp0\n    inet 172.16.0.2/32 scope global warp0\n' ;;
        *) return 1 ;;
    esac
}
detect_network >/dev/null 2>&1
[ "$HAS_IPV4" = "0" ]
[ -z "$PUBLIC_IP" ]
)

# 无 IPv4 地址也无 IPv4 默认路由 → 仍判纯 IPv6，兜底不得放宽真实的纯 IPv6 机。
(
PROXY_LIB_ONLY=1 . ./proxy.sh
detect_warp() { return 1; }
curl() { case " $* " in *' -s6 '*) printf '2001:db8::5' ;; *) return 1 ;; esac; }
ip() {
    case "$*" in
        '-6 route show default') printf 'default via fe80::1 dev eth0\n' ;;
        '-6 addr show scope global') printf '2: eth0\n    inet6 2001:db8::5/64 scope global\n' ;;
        *) return 1 ;;
    esac
}
detect_network >/dev/null 2>&1
[ "$HAS_IPV4" = "0" ]
[ "$HAS_IPV6" = "1" ]
[ "$BIND_FAMILY" = "v6" ]
)


# ---------------------------------------------------------------------------
# 公网 IP 探测：响应解析与多站点回退
# ---------------------------------------------------------------------------
# 探测站响应有两种形态：纯地址，以及 Cloudflare trace 的 key=value 多行文本。
[ "$(printf '203.0.113.5\n' | extract_probe_ip)" = '203.0.113.5' ]
[ "$(printf '  203.0.113.5  \r\n' | extract_probe_ip)" = '203.0.113.5' ]
[ "$(printf 'fl=abc\nh=1.1.1.1\nip=203.0.113.5\nts=1\n' | extract_probe_ip)" = '203.0.113.5' ]
[ "$(printf 'fl=abc\nip=2001:db8::5\nts=1\n' | extract_probe_ip)" = '2001:db8::5' ]
[ -z "$(printf '' | extract_probe_ip)" ]
# HTML 错误页不得被当成地址，必须留给 is_valid_* 拦截。
! is_valid_ipv4 "$(printf '<html>\n<body>x</body>\n' | extract_probe_ip)"

# 探测站清单必须含免 DNS 的字面量地址端点：DNS 故障时仍能取到公网地址。
case "$IPV4_PROBE_URLS" in *'https://1.1.1.1/cdn-cgi/trace'*) ;; *) exit 1 ;; esac
case "$IPV6_PROBE_URLS" in *'https://[2606:4700:4700::1111]/cdn-cgi/trace'*) ;; *) exit 1 ;; esac
# 清单不能全部落在同一个 CDN 之后，否则单点故障会让所有探测一起失败。
case "$IPV4_PROBE_URLS" in *'checkip.amazonaws.com'*) ;; *) exit 1 ;; esac

# 前面的站点全部失败时必须继续尝试后面的站点，而不是直接放弃。
(
PROXY_LIB_ONLY=1 . ./proxy.sh
IPV4_PROBE_URLS="https://probe-a.invalid https://probe-b.invalid https://probe-c.invalid"
probe_log=$(mktemp)
curl() {
    echo x >> "$probe_log"
    case " $* " in *' https://probe-c.invalid '*) printf '203.0.113.9' ;; *) return 1 ;; esac
}
[ "$(get_default_public_ipv4)" = '203.0.113.9' ]
[ "$(wc -l < "$probe_log")" -eq 3 ]
rm -f "$probe_log"
)

# 全部站点失败时返回非零，由调用方走本机路由兜底。
(
PROXY_LIB_ONLY=1 . ./proxy.sh
IPV4_PROBE_URLS="https://probe-a.invalid https://probe-b.invalid"
curl() { return 1; }
! get_default_public_ipv4
)

# IPv6 探测同样支持多站点回退，且只接受合法 IPv6 字面量。
(
PROXY_LIB_ONLY=1 . ./proxy.sh
IPV6_PROBE_URLS="https://probe-a.invalid https://probe-b.invalid"
curl() { case " $* " in *' https://probe-b.invalid '*) printf 'fl=x\nip=2001:db8::9\n' ;; *) return 1 ;; esac; }
[ "$(get_default_public_ipv6)" = '2001:db8::9' ]
)
(
PROXY_LIB_ONLY=1 . ./proxy.sh
IPV6_PROBE_URLS="https://probe-a.invalid"
curl() { printf 'upstream error'; }
! get_default_public_ipv6
)

echo 'HTTP/SOCKS proxy validation passed.'
