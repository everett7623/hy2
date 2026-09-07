#!/bin/bash
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
EXPORT_LIB_ONLY=1 . ./hy2.sh

is_valid_ipv4 203.0.113.10
! is_valid_ipv4 999.999.999.999
is_valid_ipv6 2001:db8::10
! is_valid_ipv6 'upstream:error'
! is_valid_ipv6 '<html>:error'
random_port=$(generate_random_port)
valid_port "$random_port"
[ "$random_port" -ge 10000 ]

ip() {
    case "$*" in
        '-4 route show default') printf '%s\n' 'default dev warp0' 'default via 192.0.2.1 dev eth0' ;;
        '-4 addr show dev eth0 scope global') printf '%s\n' 'inet 192.0.2.10/24 scope global eth0' ;;
        'link show') printf '%s\n' '3: warp0: <UP>' ;;
        'addr show') printf '%s\n' 'inet 203.0.113.10/24 scope global eth0' ;;
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
[ "$PUBLIC_IP" = '203.0.113.10' ]
[ "$PUBLIC_IP" != '104.28.195.185' ]

# 下载器必须在 wget 不可用时使用 curl，适配极简 VPS。
download_tmp=$(mktemp)
download_attempts=0
sleep() { :; }
curl() {
    local _dest=""
    download_attempts=$((download_attempts + 1))
    [ "$download_attempts" -lt 3 ] && return 1
    while [ "$#" -gt 0 ]; do
        [ "$1" = '-o' ] && { shift; _dest="$1"; }
        shift
    done
    printf '%s' 'curl-download' > "$_dest"
}
wget() { return 1; }
download_file 'https://example.invalid/hysteria' "$download_tmp"
[ "$(cat "$download_tmp")" = 'curl-download' ]
[ "$download_attempts" -eq 3 ]
rm -f "$download_tmp"
retry_attempts=0
eventually_succeeds() { retry_attempts=$((retry_attempts + 1)); [ "$retry_attempts" -ge 3 ]; }
retry_command eventually_succeeds
[ "$retry_attempts" -eq 3 ]
curl() {
    case " $* " in
        *' --interface 192.0.2.10 '*) printf '%s' '203.0.113.10' ;;
        *' -s4 '*) printf '%s' '104.28.195.185' ;;
        *) return 1 ;;
    esac
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

# 升级锁必须拒绝并发任务，并在释放后允许重试。
UPGRADE_LOCK_FILE="$tmp/hy2-upgrade.lock"; lock_busy=0
flock() { [ "$1" = '-u' ] && return 0; [ "$lock_busy" = '0' ]; }
acquire_upgrade_lock
release_upgrade_lock
lock_busy=1
! acquire_upgrade_lock
lock_busy=0
acquire_upgrade_lock
release_upgrade_lock
unset -f flock

# active 但未监听 UDP 端口不得判定为健康；低磁盘空间必须提前拒绝。
LISTEN_PORT=8443
service_is_active() { return 0; }
ss() { printf '%s\n' 'State Recv-Q Send-Q Local Address:Port Peer Address:Port' 'UNCONN 0 0 0.0.0.0:8443 0.0.0.0:*'; }
service_is_healthy
ss() { printf '%s\n' 'State Recv-Q Send-Q Local Address:Port Peer Address:Port' 'UNCONN 0 0 0.0.0.0:9443 0.0.0.0:*'; }
! service_is_healthy
(
health_attempt=0
service_is_healthy() { health_attempt=$((health_attempt + 1)); [ "$health_attempt" -ge 3 ]; }
sleep() { :; }
wait_for_health 5
[ "$health_attempt" = '3' ]
)
df() { printf '%s\n' 'Filesystem 1024-blocks Used Available Capacity Mounted on' 'mock 100000 1 100000 1% /'; }
has_free_space_mb "$tmp" 48
df() { printf '%s\n' 'Filesystem 1024-blocks Used Available Capacity Mounted on' 'mock 100000 99999 1 99% /'; }
! has_free_space_mb "$tmp" 48
unset -f ss df service_is_active
HY_CONFIG="$tmp/config.yaml"; HY_META="$tmp/meta"
mkdir -p "$HY_META"

# 防火墙规则必须验证后记录所有权，失败不得误报成功。
firewall_log="$tmp/firewall.log"; firewall_state="$tmp/firewall-state"; firewall_fail=0; HAS_IPV6=0
mkdir -p "$firewall_state"
iptables() {
    local _action="$1" _port="" _proto=""
    shift
    while [ "$#" -gt 0 ]; do
        [ "$1" = '-p' ] && { shift; _proto="$1"; shift; continue; }
        [ "$1" = '--dport' ] && { shift; _port="$1"; break; }
        shift
    done
    case "$_action" in
        -C) [ -f "$firewall_state/${_port}-${_proto}" ] ;;
        -I) [ "$firewall_fail" = '0' ] || return 1; : > "$firewall_state/${_port}-${_proto}"; echo "add ${_port}-${_proto}" >> "$firewall_log" ;;
        -D) rm -f "$firewall_state/${_port}-${_proto}"; echo "delete ${_port}-${_proto}" >> "$firewall_log" ;;
    esac
}
open_firewall_port 8443 udp >/dev/null
[ -f "$HY_META/firewall/iptables4-udp-port-8443-0" ]
close_all_owned_firewall_rules
[ ! -e "$firewall_state/8443-udp" ]
firewall_fail=1
! open_firewall_port 10443 udp >/dev/null 2>&1
[ ! -e "$HY_META/firewall/iptables4-udp-port-10443-0" ]
firewall_fail=0

printf '%s\n' 'listen: :8443' 'auth:' '  type: password' '  password: testpass' > "$HY_CONFIG"
printf '%s' '8443' > "$HY_META/ext_port"
printf '%s' '0' > "$HY_META/nat_mode"
printf '%s' '' > "$HY_META/public_ipv6"
printf '%s' '50' > "$HY_META/bw_up"
printf '%s' '100' > "$HY_META/bw_down"
printf '%s' '' > "$HY_META/port_hop"
printf '%s' '104.28.195.185' > "$HY_META/public_ip"
PUBLIC_IP=""; PUBLIC_IPV6=""
read_config_vars
[ "$PUBLIC_IP" = '203.0.113.10' ]
[ "$(cat "$HY_META/public_ip")" = '203.0.113.10' ]

get_native_public_ipv4() { return 1; }
printf '%s' '104.28.195.185' > "$HY_META/public_ip"
PUBLIC_IP=""; PUBLIC_IPV6=""
read_config_vars
[ -z "$PUBLIC_IP" ]
[ ! -s "$HY_META/public_ip" ]

# 重装备份必须恢复旧二进制、配置、证书与元数据。
INIT_SYS=none
HY_BIN="$tmp/hysteria"; HY_CERT_DIR="$tmp/cert"; SERVICE_FILE="$tmp/hy2.service"; OPENRC_SERVICE="$tmp/hy2.openrc"
mkdir -p "$HY_CERT_DIR"
printf '%s' 'old-bin' > "$HY_BIN"
printf '%s' 'old-config' > "$HY_CONFIG"
printf '%s' 'old-cert' > "$HY_CERT_DIR/server.crt"
printf '%s' 'old-meta' > "$HY_META/marker"
service_is_active() { return 0; }
service_is_enabled() { return 0; }
service_stop() { return 0; }
service_disable() { : > "$tmp/disabled"; }
service_enable() { : > "$tmp/enabled"; }
service_start() { : > "$tmp/restarted"; }
trap -p INT > "$tmp/int-trap-before"
backup_current_install
open_firewall_port 9443 udp >/dev/null
[ -f "$firewall_state/9443-udp" ]
printf '%s' 'new-bin' > "$HY_BIN"
printf '%s' 'new-config' > "$HY_CONFIG"
printf '%s' 'new-cert' > "$HY_CERT_DIR/server.crt"
printf '%s' 'new-meta' > "$HY_META/marker"
restore_current_install
[ "$(cat "$HY_BIN")" = 'old-bin' ]
[ "$(cat "$HY_CONFIG")" = 'old-config' ]
[ "$(cat "$HY_CERT_DIR/server.crt")" = 'old-cert' ]
[ "$(cat "$HY_META/marker")" = 'old-meta' ]
[ ! -e "$firewall_state/9443-udp" ]
[ -f "$tmp/restarted" ]
[ -f "$tmp/disabled" ]
[ -f "$tmp/enabled" ]
trap -p INT > "$tmp/int-trap-after"
cmp -s "$tmp/int-trap-before" "$tmp/int-trap-after"

# Ctrl+C/TERM 处理器必须回滚半成品并保留标准退出码。
rm -f "$tmp/restarted" "$tmp/disabled" "$tmp/enabled"
backup_current_install
printf '%s' 'interrupted-bin' > "$HY_BIN"
set +e
(rollback_install_on_signal 130) 2>/dev/null
rollback_status=$?
set -e
[ "$rollback_status" = '130' ]
[ "$(cat "$HY_BIN")" = 'old-bin' ]
[ -f "$tmp/restarted" ]
[ -f "$tmp/enabled" ]
INSTALL_BACKUP_DIR=""
disarm_install_rollback
unset -f iptables

PASSWORD=testpass; BW_UP=50; BW_DOWN=100; SNI=example.com
write_hy2_config ':8443'
grep -q '^listen: :8443$' "$HY_CONFIG"
grep -q 'password: "testpass"' "$HY_CONFIG"
case "$(uname -s)" in MINGW*|MSYS*) ;; *) [ "$(stat -c %a "$HY_CONFIG")" = '600' ] ;; esac

# 配置修改后的服务验证失败必须恢复配置、元数据和既有 trap。
printf '%s' '50' > "$HY_META/bw_up"
printf '%s' '100' > "$HY_META/bw_down"
service_restart() { return 1; }
service_is_active() { return 1; }
service_logs() { :; }
sleep() { :; }
trap -p INT > "$tmp/change-trap-before"
printf '%s\n' 'new-password' | change_password >/dev/null
grep -q 'password: "testpass"' "$HY_CONFIG"
printf '%s\n' '75' '150' | change_bandwidth >/dev/null
grep -q 'up: 50 mbps' "$HY_CONFIG"
grep -q 'down: 100 mbps' "$HY_CONFIG"
[ "$(cat "$HY_META/bw_up")" = '50' ]
[ "$(cat "$HY_META/bw_down")" = '100' ]
trap -p INT > "$tmp/change-trap-after"
cmp -s "$tmp/change-trap-before" "$tmp/change-trap-after"
[ -z "$(find "$(dirname "$HY_CONFIG")" -maxdepth 1 -type f -name 'config.yaml.*.??????' -print -quit)" ]


# ---------------------------------------------------------------------------
# 公网 IP 探测站不可达时的 IPv4 兜底判定
# ---------------------------------------------------------------------------
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

# 双栈机的 IPv4 探测站全部不可达时，必须按“本机全局 IPv4 + 默认 IPv4 路由”认定 IPv4 可用。
# 缺少这个兜底会误判纯 IPv6，节点只下发 IPv6 地址，IPv4 客户端全部连不上。
(
detect_warp() { return 1; }
curl() { case " $* " in *' -s6 '*) printf '2001:db8::5' ;; *) return 1 ;; esac; }
ip() {
    case "$*" in
        '-4 route show default') printf 'default via 203.0.113.1 dev eth0\n' ;;
        '-4 addr show dev eth0 scope global') printf '    inet 203.0.113.5/24 scope global eth0\n' ;;
        'addr show') printf '    inet 203.0.113.5/24\n' ;;
        *) return 1 ;;
    esac
}
detect_network >/dev/null 2>&1
[ "$HAS_IPV4" = "1" ]
[ "$HAS_IPV6" = "1" ]
[ "$IPV6_ONLY" = "0" ]
[ "$PUBLIC_IP" = "203.0.113.5" ]
[ "$NAT_MODE" = "0" ]
[ "$IPV4_UNVERIFIED" = "1" ]
)

# 同样探测失败，但本机只有私网 IPv4：认定有 IPv4 并按 NAT 处理，
# 且绝不能把私网地址写进 PUBLIC_IP —— 它会直接进入分享链接。
(
detect_warp() { return 1; }
curl() { return 1; }
ip() {
    case "$*" in
        '-4 route show default') printf 'default via 10.0.0.1 dev eth0\n' ;;
        '-4 addr show dev eth0 scope global') printf '    inet 10.0.0.5/24 scope global eth0\n' ;;
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
detect_warp() { return 0; }
curl() { return 1; }
ip() {
    case "$*" in
        '-4 route show default') printf 'default dev warp0\n' ;;
        *) return 1 ;;
    esac
}
detect_network >/dev/null 2>&1
[ "$HAS_IPV4" = "0" ]
[ -z "$PUBLIC_IP" ]
)

# 无 IPv4 地址也无 IPv4 默认路由 → 仍判纯 IPv6，兜底不得放宽真实的纯 IPv6 机。
(
detect_warp() { return 1; }
curl() { case " $* " in *' -s6 '*) printf '2001:db8::5' ;; *) return 1 ;; esac; }
ip() { return 1; }
detect_network >/dev/null 2>&1
[ "$HAS_IPV4" = "0" ]
[ "$HAS_IPV6" = "1" ]
[ "$IPV6_ONLY" = "1" ]
)


# ---------------------------------------------------------------------------
# 版本获取：格式校验与多级回退
# ---------------------------------------------------------------------------
normalize_hy2_tag app/v2.6.1 >/dev/null
[ "$(normalize_hy2_tag app/v2.6.1)" = 'app/v2.6.1' ]
[ "$(normalize_hy2_tag v2.6.1)" = 'app/v2.6.1' ]
[ "$(normalize_hy2_tag 2.6.1)" = 'app/v2.6.1' ]
[ "$(normalize_hy2_tag 'https://github.com/apernet/hysteria/releases/tag/app/v2.6.1')" = 'app/v2.6.1' ]
# 重定向兜底失败时 curl 会输出原始请求 URL；它必须被拒绝，
# 否则会拼进下载 URL，并让二进制版本校验必然失败、连官方镜像也用不了。
! normalize_hy2_tag 'https://github.com/apernet/hysteria/releases/latest'
! normalize_hy2_tag ''
! normalize_hy2_tag app/vlatest
! normalize_hy2_tag v2.6

# API 可用时直接采用。
(
curl() { case " $* " in *' https://api.github.com/'*) printf '{"tag_name": "app/v2.6.1"}' ;; *) return 1 ;; esac; }
get_latest_version >/dev/null
[ "$LAST_VERSION_TAG" = 'app/v2.6.1' ]
[ "$LAST_VERSION" = 'v2.6.1' ]
)

# API 限频 + github.com 不可达时，必须继续走镜像重定向而不是直接失败。
(
curl() {
    case " $* " in
        *' https://api.github.com/'*) return 1 ;;
        *' https://github.com/apernet/hysteria/releases/latest '*) printf 'https://github.com/apernet/hysteria/releases/latest' ;;
        *' https://kkgithub.com/apernet/hysteria/releases/latest '*) printf 'https://kkgithub.com/apernet/hysteria/releases/tag/app/v2.6.2' ;;
        *) return 1 ;;
    esac
}
get_latest_version >/dev/null
[ "$LAST_VERSION_TAG" = 'app/v2.6.2' ]
[ "$LAST_VERSION" = 'v2.6.2' ]
)

# 重定向层全部只回原始 URL 时，落到 HTML 抓取层。
(
curl() {
    case " $* " in
        *' https://api.github.com/'*) return 1 ;;
        *'/releases/latest '*) printf 'https://github.com/apernet/hysteria/releases/latest' ;;
        *' https://github.com/apernet/hysteria/releases '*) printf '<a href="/apernet/hysteria/releases/tag/app/v2.6.3">x</a>' ;;
        *) return 1 ;;
    esac
}
get_latest_version >/dev/null
[ "$LAST_VERSION_TAG" = 'app/v2.6.3' ]
)

# 全部来源失败必须返回非零且不残留脏值，由调用方中止安装。
(
curl() { return 1; }
! get_latest_version >/dev/null 2>&1
[ -z "$LAST_VERSION_TAG" ]
[ -z "$LAST_VERSION" ]
)


# ---------------------------------------------------------------------------
# GitHub 全线不可达时的全新安装路径
# ---------------------------------------------------------------------------
# 官方永久镜像 download.hysteria.network 不依赖版本号，GitHub 取不到版本时
# 仍应能完成全新安装；此前 install_hy2 在这里直接 return，本可用的路径被浪费。
(
HY_BIN="$tmp/hy-mirror"
LAST_VERSION_TAG=""
LAST_VERSION=""
downloaded_from=""
download_file() {
    case "$1" in
        *download.hysteria.network*)
            downloaded_from=mirror
            printf '#!/bin/sh\necho "hysteria version v2.6.9"\n' > "$2"
            return 0 ;;
        *) return 1 ;;
    esac
}
download_hy2 >/dev/null 2>&1
[ "$downloaded_from" = mirror ]
# 版本必须回填为二进制自报值，供后续元数据与升级比对使用。
[ "$LAST_VERSION" = 'v2.6.9' ]
[ "$LAST_VERSION_TAG" = 'app/v2.6.9' ]
rm -f "$HY_BIN"
)

# 版本已知时仍必须严格比对：镜像给出不同版本要判失败，不能静默接受。
(
HY_BIN="$tmp/hy-mismatch"
LAST_VERSION_TAG="app/v2.6.1"
LAST_VERSION="v2.6.1"
download_file() {
    case "$1" in
        *download.hysteria.network*)
            printf '#!/bin/sh\necho "hysteria version v2.6.9"\n' > "$2"
            return 0 ;;
        *) return 1 ;;
    esac
}
! download_hy2 >/dev/null 2>&1
[ ! -f "$HY_BIN" ]
)

# 下载物读不出版本号说明拿到的不是可用二进制，必须失败而不是当成未知版本放行。
(
HY_BIN="$tmp/hy-garbage"
LAST_VERSION_TAG=""
LAST_VERSION=""
download_file() { printf '<html>not a binary</html>' > "$2"; return 0; }
! download_hy2 >/dev/null 2>&1
[ ! -f "$HY_BIN" ]
)

echo 'Hysteria 2 network validation passed.'
