#!/bin/bash
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
EXPORT_LIB_ONLY=1 . ./ss.sh

is_valid_ipv4 203.0.113.10
! is_valid_ipv4 256.0.0.1

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

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
SS_CONFIG="$tmp/config.json"; SS_META="$tmp/meta"
mkdir -p "$SS_META"
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
service_stop() { return 0; }
service_start() { : > "$tmp/restarted"; }
backup_current_install
printf '%s' 'new-bin' > "$SS_BIN"
printf '%s' 'new-config' > "$SS_CONFIG"
printf '%s' 'new-password' > "$SS_META/password"
restore_current_install
[ "$(cat "$SS_BIN")" = 'old-bin' ]
[ "$(cat "$SS_CONFIG")" = 'old-config' ]
[ "$(cat "$SS_META/password")" = 'old-password' ]
[ -f "$tmp/restarted" ]

HAS_IPV6=1; LISTEN_PORT=8443; PASSWORD=testpass; METHOD=aes-256-gcm
_write_config
grep -q '"server": "::"' "$SS_CONFIG"
grep -q '"server_port": 8443' "$SS_CONFIG"
case "$(uname -s)" in MINGW*|MSYS*) ;; *) [ "$(stat -c %a "$SS_CONFIG")" = '600' ] ;; esac

echo 'Shadowsocks network validation passed.'
