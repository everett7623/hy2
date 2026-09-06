#!/bin/bash
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
EXPORT_LIB_ONLY=1 . ./ss.sh

is_valid_ipv4 203.0.113.10
! is_valid_ipv4 256.0.0.1
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
        *' -s6 '*) printf '%s' '2001:db8::10' ;;
        *' --interface 192.0.2.10 '*) printf '%s' '203.0.113.10' ;;
        *' -s4 '*) printf '%s' '104.28.195.185' ;;
        *) return 1 ;;
    esac
}

detect_network >/dev/null
[ "$PUBLIC_IP" = '203.0.113.10' ]
[ "$PUBLIC_IPV6" = '2001:db8::10' ]
[ "$PUBLIC_IP" != '104.28.195.185' ]

# 纯 IPv4 警告被拒绝时只取消当前安装，不得 exit 整个管理脚本。
curl() {
    case " $* " in
        *' -s4 '*|*' --interface 192.0.2.10 '*) printf '%s' '203.0.113.10' ;;
        *) return 1 ;;
    esac
}
if printf 'n\n' | detect_network >/dev/null; then
    echo 'IPv4-only cancellation unexpectedly succeeded' >&2
    exit 1
fi
curl() {
    case " $* " in
        *' -s6 '*) printf '%s' '2001:db8::10' ;;
        *' --interface 192.0.2.10 '*) printf '%s' '203.0.113.10' ;;
        *' -s4 '*) printf '%s' '104.28.195.185' ;;
        *) return 1 ;;
    esac
}

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
download_file 'https://example.invalid/shadowsocks' "$download_tmp"
[ "$(cat "$download_tmp")" = 'curl-download' ]
[ "$download_attempts" -eq 3 ]
rm -f "$download_tmp"
retry_attempts=0
eventually_succeeds() { retry_attempts=$((retry_attempts + 1)); [ "$retry_attempts" -ge 3 ]; }
retry_command eventually_succeeds
[ "$retry_attempts" -eq 3 ]
curl() {
    case " $* " in
        *' -s6 '*) printf '%s' '2001:db8::10' ;;
        *' --interface 192.0.2.10 '*) printf '%s' '203.0.113.10' ;;
        *' -s4 '*) printf '%s' '104.28.195.185' ;;
        *) return 1 ;;
    esac
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

# 升级锁必须拒绝并发任务，并在释放后允许重试。
UPGRADE_LOCK_FILE="$tmp/ss-upgrade.lock"; lock_busy=0
flock() { [ "$1" = '-u' ] && return 0; [ "$lock_busy" = '0' ]; }
acquire_upgrade_lock
release_upgrade_lock
lock_busy=1
! acquire_upgrade_lock
lock_busy=0
acquire_upgrade_lock
release_upgrade_lock
unset -f flock

# active 但无 TCP/UDP 监听不得判定健康；低磁盘空间必须提前拒绝。
LISTEN_PORT=8443
service_is_active() { return 0; }
ss() { printf '%s\n' 'Netid State Recv-Q Send-Q Local Address:Port' 'tcp LISTEN 0 128 0.0.0.0:8443'; }
service_is_healthy
ss() { printf '%s\n' 'Netid State Recv-Q Send-Q Local Address:Port' 'tcp LISTEN 0 128 0.0.0.0:9443'; }
! service_is_healthy
(
health_attempt=0
service_is_healthy() { health_attempt=$((health_attempt + 1)); [ "$health_attempt" -ge 3 ]; }
sleep() { :; }
wait_for_health 5
[ "$health_attempt" = '3' ]
)
df() { printf '%s\n' 'Filesystem 1024-blocks Used Available Capacity Mounted on' 'mock 200000 1 200000 1% /'; }
has_free_space_mb "$tmp" 128
df() { printf '%s\n' 'Filesystem 1024-blocks Used Available Capacity Mounted on' 'mock 100000 99999 1 99% /'; }
! has_free_space_mb "$tmp" 128
unset -f ss df service_is_active
SS_CONFIG="$tmp/config.json"; SS_META="$tmp/meta"
mkdir -p "$SS_META"

# 只删除脚本实际创建的规则，用户预先存在的规则不得被接管。
firewall_log="$tmp/firewall.log"; firewall_state="$tmp/firewall-state"; firewall_existing=0; firewall_fail=0; HAS_IPV6=0
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
        -C) [ "$firewall_existing" = '1' ] || [ -f "$firewall_state/${_port}-${_proto}" ] ;;
        -I) [ "$firewall_fail" = '0' ] || return 1; : > "$firewall_state/${_port}-${_proto}"; echo "add ${_port}-${_proto}" >> "$firewall_log" ;;
        -D) rm -f "$firewall_state/${_port}-${_proto}"; echo "delete ${_port}-${_proto}" >> "$firewall_log" ;;
    esac
}
open_ports 8443 >/dev/null
[ -f "$SS_META/firewall/iptables4-8443-tcp" ]
[ -f "$SS_META/firewall/iptables4-8443-udp" ]
close_ports 8443
[ "$(grep -c '^delete 8443-' "$firewall_log")" = '2' ]
: > "$firewall_log"; firewall_existing=1
open_ports 9443 >/dev/null
[ ! -e "$SS_META/firewall/iptables4-9443-tcp" ]
close_ports 9443
[ ! -s "$firewall_log" ]
firewall_existing=0; firewall_fail=1
! open_ports 10443 >/dev/null 2>&1
[ ! -e "$SS_META/firewall/iptables4-10443-tcp" ]
unset -f iptables
printf '%s\n' '{"server_port":8443,"password":"testpass","method":"aes-256-gcm"}' > "$SS_CONFIG"
printf '%s' '8443' > "$SS_META/ext_port"
printf '%s' '0' > "$SS_META/nat_mode"
printf '%s' '8443' > "$SS_META/listen_port"
printf '%s' 'testpass' > "$SS_META/password"
printf '%s' 'aes-256-gcm' > "$SS_META/method"
printf '%s' '' > "$SS_META/public_ipv6"
printf '%s' '104.28.195.185' > "$SS_META/public_ip"
PUBLIC_IP=""; PUBLIC_IPV6=""
read_config_vars
[ "$PUBLIC_IP" = '203.0.113.10' ]
[ "$(cat "$SS_META/public_ip")" = '203.0.113.10' ]

get_native_public_ipv4() { return 1; }
printf '%s' '104.28.195.185' > "$SS_META/public_ip"
PUBLIC_IP=""; PUBLIC_IPV6=""
read_config_vars
[ -z "$PUBLIC_IP" ]
[ ! -s "$SS_META/public_ip" ]

# 重装备份必须恢复二进制、配置、元数据和原运行状态标记。
INIT_SYS=none
SS_BIN="$tmp/ssserver"; SERVICE_FILE="$tmp/ss.service"; OPENRC_SERVICE="$tmp/ss.openrc"
printf '%s' 'old-bin' > "$SS_BIN"
printf '%s' 'old-config' > "$SS_CONFIG"
printf '%s' 'old-password' > "$SS_META/password"
service_is_active() { return 0; }
service_is_enabled() { return 0; }
service_stop() { return 0; }
service_disable() { : > "$tmp/disabled"; }
service_enable() { : > "$tmp/enabled"; }
service_start() { : > "$tmp/restarted"; }
trap -p INT > "$tmp/int-trap-before"
backup_current_install
printf '%s' 'new-bin' > "$SS_BIN"
printf '%s' 'new-config' > "$SS_CONFIG"
printf '%s' 'new-password' > "$SS_META/password"
restore_current_install
[ "$(cat "$SS_BIN")" = 'old-bin' ]
[ "$(cat "$SS_CONFIG")" = 'old-config' ]
[ "$(cat "$SS_META/password")" = 'old-password' ]
[ -f "$tmp/restarted" ]
[ -f "$tmp/disabled" ]
[ -f "$tmp/enabled" ]
trap -p INT > "$tmp/int-trap-after"
cmp -s "$tmp/int-trap-before" "$tmp/int-trap-after"

# Ctrl+C/TERM 处理器必须回滚半成品并保留标准退出码。
rm -f "$tmp/restarted" "$tmp/disabled" "$tmp/enabled"
backup_current_install
printf '%s' 'interrupted-bin' > "$SS_BIN"
set +e
(rollback_install_on_signal 143) 2>/dev/null
rollback_status=$?
set -e
[ "$rollback_status" = '143' ]
[ "$(cat "$SS_BIN")" = 'old-bin' ]
[ -f "$tmp/restarted" ]
[ -f "$tmp/enabled" ]
INSTALL_BACKUP_DIR=""
disarm_install_rollback

HAS_IPV6=1; LISTEN_PORT=8443; PASSWORD=testpass; METHOD=aes-256-gcm
_write_config
grep -q '"server": "::"' "$SS_CONFIG"
grep -q '"server_port": 8443' "$SS_CONFIG"
case "$(uname -s)" in MINGW*|MSYS*) ;; *) [ "$(stat -c %a "$SS_CONFIG")" = '600' ] ;; esac


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
detect_network >/dev/null 2>&1 <<'EOF'
y
EOF
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
detect_network >/dev/null 2>&1 <<'EOF'
y
EOF
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
detect_network >/dev/null 2>&1 <<'EOF'
y
EOF
[ "$HAS_IPV4" = "0" ]
[ -z "$PUBLIC_IP" ]
)

# 无 IPv4 地址也无 IPv4 默认路由 → 仍判纯 IPv6，兜底不得放宽真实的纯 IPv6 机。
(
detect_warp() { return 1; }
curl() { case " $* " in *' -s6 '*) printf '2001:db8::5' ;; *) return 1 ;; esac; }
ip() { return 1; }
detect_network >/dev/null 2>&1 <<'EOF'
y
EOF
[ "$HAS_IPV4" = "0" ]
[ "$HAS_IPV6" = "1" ]
[ "$IPV6_ONLY" = "1" ]
)


# ---------------------------------------------------------------------------
# 版本获取：格式校验与多级回退
# ---------------------------------------------------------------------------
[ "$(normalize_ss_tag v1.23.1)" = 'v1.23.1' ]
[ "$(normalize_ss_tag 1.23.1)" = 'v1.23.1' ]
[ "$(normalize_ss_tag 'https://github.com/shadowsocks/shadowsocks-rust/releases/tag/v1.23.1')" = 'v1.23.1' ]
# 重定向兜底失败时 curl 会输出原始请求 URL；它必须被拒绝，
# 否则会被拼进下载 URL 和压缩包文件名。
! normalize_ss_tag 'https://github.com/shadowsocks/shadowsocks-rust/releases/latest'
! normalize_ss_tag ''
! normalize_ss_tag vlatest
! normalize_ss_tag v1.23

# API 可用时直接采用。
(
curl() { case " $* " in *' https://api.github.com/'*) printf '{"tag_name": "v1.23.1"}' ;; *) return 1 ;; esac; }
get_latest_version >/dev/null
[ "$LAST_VERSION" = 'v1.23.1' ]
)

# API 限频 + github.com 不可达时，必须继续走镜像重定向而不是直接失败。
(
curl() {
    case " $* " in
        *' https://api.github.com/'*) return 1 ;;
        *' https://github.com/shadowsocks/shadowsocks-rust/releases/latest '*) printf 'https://github.com/shadowsocks/shadowsocks-rust/releases/latest' ;;
        *' https://kkgithub.com/shadowsocks/shadowsocks-rust/releases/latest '*) printf 'https://kkgithub.com/shadowsocks/shadowsocks-rust/releases/tag/v1.23.2' ;;
        *) return 1 ;;
    esac
}
get_latest_version >/dev/null
[ "$LAST_VERSION" = 'v1.23.2' ]
)

# 重定向层全部只回原始 URL 时，落到 HTML 抓取层。
(
curl() {
    case " $* " in
        *' https://api.github.com/'*) return 1 ;;
        *'/releases/latest '*) printf 'https://github.com/shadowsocks/shadowsocks-rust/releases/latest' ;;
        *' https://github.com/shadowsocks/shadowsocks-rust/releases '*) printf '<a href="/shadowsocks/shadowsocks-rust/releases/tag/v1.23.3">x</a>' ;;
        *) return 1 ;;
    esac
}
get_latest_version >/dev/null
[ "$LAST_VERSION" = 'v1.23.3' ]
)

# 全部来源失败必须返回非零且不残留脏值。
(
curl() { return 1; }
! get_latest_version >/dev/null 2>&1
[ -z "$LAST_VERSION" ]
)

echo 'Shadowsocks network validation passed.'
