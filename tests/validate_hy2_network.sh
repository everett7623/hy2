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

echo 'Hysteria 2 network validation passed.'
