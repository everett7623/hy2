#!/bin/bash
#====================================================================================
# 项目：VLESS Management Script
# 作者：everettlabs
# 版本：v2.0.19
# GitHub: https://github.com/everett7623/hy2
# Seedloc博客: https://seedloc.com
# VPSknow网站：https://vpsknow.com
# Nodeloc论坛: https://nodeloc.com
# 更新日期: 2026-07-17
#
# 支持系统: Debian / Ubuntu / CentOS / Rocky / Alma / Fedora / Arch / Alpine
# 支持环境: 标准 VPS / NAT 机器 / IPv6 单栈 / 双栈机器
# 实现方式: 使用 sing-box >= 1.12.0 原生 VLESS 入站
#====================================================================================

# ============================================================
# 自举：确保以 bash 运行
# ============================================================
if [ -z "$BASH_VERSION" ]; then
    if command -v bash >/dev/null 2>&1; then
        exec bash "$0" "$@"
    else
        if command -v apk >/dev/null 2>&1; then
            apk add --no-cache bash >/dev/null 2>&1
        elif command -v apt-get >/dev/null 2>&1; then
            apt-get update -qq >/dev/null 2>&1
            apt-get install -y -qq bash >/dev/null 2>&1
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y bash >/dev/null 2>&1
        elif command -v yum >/dev/null 2>&1; then
            yum install -y bash >/dev/null 2>&1
        fi
        command -v bash >/dev/null 2>&1 || { echo "错误: 无法安装 bash，请手动安装后重试"; exit 1; }
        exec bash "$0" "$@"
    fi
fi

SCRIPT_PATH="${BASH_SOURCE[0]:-$0}"

[ "${VLESS_LIB_ONLY:-0}" != "1" ] && [ ! -t 0 ] && [ -c /dev/tty ] && exec < /dev/tty

if [ -f "$SCRIPT_PATH" ] && grep -q $'\r' "$SCRIPT_PATH" 2>/dev/null; then
    sed -i 's/\r$//' "$SCRIPT_PATH"
    exec bash "$SCRIPT_PATH" "$@"
fi

# ============================================================
# VLESS_LIB_ONLY=1：仅加载函数库，不执行任何副作用（供测试 source）
# ============================================================
[ "${VLESS_LIB_ONLY:-0}" = "1" ] && _VLESS_LIB_ONLY=1 || _VLESS_LIB_ONLY=0

# --- 颜色 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
SKYBLUE='\033[0;36m'
PLAIN='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'

clear_screen() {
    [ -t 1 ] || return 0
    command -v clear >/dev/null 2>&1 && clear 2>/dev/null && return 0
    printf '\033[2J\033[H'
}

disk_tmp_dir() {
    if [ -d /var/tmp ] && [ -w /var/tmp ]; then
        printf '%s' /var/tmp
    else
        printf '%s' "${TMPDIR:-/tmp}"
    fi
}

# --- 路径 ---
VLESS_BIN="${VLESS_BIN:-/usr/local/bin/vless-server}"
SING_BOX_BIN="${SING_BOX_BIN:-/usr/local/bin/sing-box}"
VLESS_DIR="${VLESS_DIR:-/etc/sing-box}"
VLESS_CONFIG="${VLESS_CONFIG:-${VLESS_DIR}/vless.json}"
VLESS_META="${VLESS_META:-${VLESS_DIR}/vless-meta}"
SING_BOX_MANAGED_MARKER="${SING_BOX_MANAGED_MARKER:-${VLESS_DIR}/.singbox-tools-managed}"
SYSTEMD_SERVICE="${SYSTEMD_SERVICE:-/etc/systemd/system/vless-server.service}"
OPENRC_SERVICE="/etc/init.d/vless-server"
AUTO_UPDATE_SCRIPT="/usr/local/bin/vless-autoupdate.sh"
AUTO_UPDATE_LOG="/var/log/vless-autoupdate.log"

# --- 运行时变量 ---
RELEASE="unknown"
INIT_SYS="none"
NAT_MODE=0
HAS_IPV4=0
HAS_IPV6=0
PUBLIC_IP=""
PUBLIC_IPV6=""
DEFAULT_EGRESS_IPV4=""
WARP_ACTIVE=0
BIND_FAMILY="v4"
LISTEN_HOST="::"
LISTEN_PORT=""
EXT_PORT=""
UUID=""
REALITY_PRIVATE_KEY=""
REALITY_PUBLIC_KEY=""
SHORT_ID=""
NODE_NAME=""
SERVER_NAME="www.example.com"
HANDSHAKE_PORT="443"
MANAGED_SING_BOX=0
LAST_VERSION_TAG=""
SING_BOX_STABLE_FALLBACK_TAG="${SING_BOX_STABLE_FALLBACK_TAG:-v1.13.14}"
INSTALL_BACKUP_DIR=""
INSTALL_ROLLBACK_ARMED=0
INSTALL_PREV_INT_TRAP=""
INSTALL_PREV_TERM_TRAP=""
UPGRADE_LOCK_FILE="${UPGRADE_LOCK_FILE:-/var/lock/sing-box-tools-upgrade.lock}"
UPGRADE_LOCK_MODE=""


# ============================================================
# 基础检测
# ============================================================
check_root() {
    [ "$EUID" -ne 0 ] && echo -e "${RED}错误: 请以 root 权限运行${PLAIN}" && exit 1
}

check_sys() {
    if [ -f /etc/alpine-release ]; then
        RELEASE="alpine"
    elif [ -f /etc/os-release ]; then
        . /etc/os-release
        case "$ID" in
            debian|ubuntu|linuxmint|kali) RELEASE="debian" ;;
            centos|rhel)                  RELEASE="centos" ;;
            fedora)                       RELEASE="fedora" ;;
            rocky|almalinux|ol)           RELEASE="rocky"  ;;
            arch|manjaro|endeavouros)     RELEASE="arch"   ;;
            *)
                case "${ID_LIKE:-}" in
                    *rhel*|*centos*|*fedora*) RELEASE="rocky"  ;;
                    *debian*|*ubuntu*)        RELEASE="debian" ;;
                    *)                        RELEASE="unknown" ;;
                esac
                ;;
        esac
    else
        RELEASE="unknown"
    fi
}

detect_init() {
    if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
        INIT_SYS="systemd"
    elif command -v rc-service >/dev/null 2>&1; then
        INIT_SYS="openrc"
    else
        INIT_SYS="none"
    fi
}

retry_command() {
    local _attempt=1 _max=3 _delay=2
    while [ "$_attempt" -le "$_max" ]; do
        "$@" && return 0
        [ "$_attempt" -ge "$_max" ] && break
        echo -e "${YELLOW}命令执行失败或包管理器被占用，${_delay} 秒后重试 (${_attempt}/${_max})...${PLAIN}" >&2
        sleep "$_delay"
        _attempt=$((_attempt + 1)); _delay=$((_delay * 2))
    done
    return 1
}

install_dependencies() {
    local _cmd _ready=1
    for _cmd in curl tar openssl ip; do
        command -v "$_cmd" >/dev/null 2>&1 || _ready=0
    done
    if [ "$_ready" = "1" ]; then
        echo -e "${GREEN}✓ 核心依赖已就绪，跳过软件源刷新${PLAIN}"
        return 0
    fi

    echo -e "${YELLOW}正在补齐必要依赖...${PLAIN}"
    case "$RELEASE" in
        alpine)
            retry_command apk update -q >/dev/null 2>&1
            retry_command apk add --no-cache bash curl wget ca-certificates tar openssl iproute2 procps >/dev/null 2>&1
            apk add --no-cache libqrencode >/dev/null 2>&1 || true
            ;;
        centos)
            retry_command yum install -y curl wget ca-certificates tar openssl iproute procps-ng >/dev/null 2>&1
            yum install -y qrencode >/dev/null 2>&1 || true
            ;;
        fedora|rocky)
            retry_command dnf install -y curl wget ca-certificates tar openssl iproute procps-ng >/dev/null 2>&1
            dnf install -y qrencode >/dev/null 2>&1 || true
            ;;
        arch)
            retry_command pacman -Sy --noconfirm curl wget ca-certificates tar openssl iproute2 procps-ng >/dev/null 2>&1
            pacman -S --noconfirm qrencode >/dev/null 2>&1 || true
            ;;
        *)
            if command -v apt-get >/dev/null 2>&1; then
                retry_command apt-get update -qq >/dev/null 2>&1
                retry_command apt-get install -y -qq curl wget ca-certificates tar openssl iproute2 procps >/dev/null 2>&1
                apt-get install -y qrencode >/dev/null 2>&1 || true
            else
                echo -e "${RED}无法识别包管理器，请手动安装 curl wget tar openssl iproute2${PLAIN}"
                return 1
            fi
            ;;
    esac

    local _missing=0
    for _cmd in curl tar openssl ip; do
        if ! command -v "$_cmd" >/dev/null 2>&1; then
            echo -e "${RED}致命错误: 缺少组件 [ $_cmd ]，请手动安装后重试${PLAIN}"
            _missing=1
        fi
    done
    [ "$_missing" -eq 1 ] && return 1
    return 0
}

# ============================================================
# 输入校验
# ============================================================
validate_port() {
    local port="$1"
    [ -z "$port" ] && return 1
    case "$port" in
        *[!0-9]*) return 1 ;;
    esac
    case "$port" in
        0*) return 1 ;;
    esac
    [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
}

port_is_listening() {
    local _port="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -lntu 2>/dev/null | awk -v port="$_port" '
            NR > 1 { for (i=4; i<=NF; i++) if ($i ~ (":" port "$")) found=1 }
            END { exit(found ? 0 : 1) }
        '
    elif command -v netstat >/dev/null 2>&1; then
        netstat -lntu 2>/dev/null | awk -v port="$_port" '
            NR > 1 { for (i=4; i<=NF; i++) if ($i ~ (":" port "$")) found=1 }
            END { exit(found ? 0 : 1) }
        '
    else
        return 1
    fi
}

generate_random_port() {
    local _attempt=0 _number _port
    while [ "$_attempt" -lt 32 ]; do
        _number=$(od -An -N2 -tu2 /dev/urandom 2>/dev/null | tr -d ' ')
        [ -n "$_number" ] || _number=$(($(date +%s) + $$ + _attempt))
        _port=$((10000 + (_number % 55536)))
        if ! port_is_listening "$_port"; then
            printf '%s' "$_port"
            return 0
        fi
        _attempt=$((_attempt + 1))
    done
    return 1
}

validate_uuid() {
    printf '%s\n' "$1" | grep -qE '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$'
}

validate_reality_key() {
    printf '%s\n' "$1" | grep -qE '^[A-Za-z0-9_-]{43}$'
}

validate_short_id() {
    local _short_id="$1" _length
    _length="${#_short_id}"
    [ "$_length" -ge 2 ] && [ "$_length" -le 16 ] || return 1
    [ $((_length % 2)) -eq 0 ] || return 1
    printf '%s\n' "$_short_id" | grep -qE '^[0-9A-Fa-f]+$'
}

validate_server_name() {
    local _name="$1"
    [ -n "$_name" ] || return 1
    [ "${#_name}" -le 253 ] || return 1
    printf '%s\n' "$_name" | awk -F. '
        NF < 2 { exit 1 }
        {
            for (i = 1; i <= NF; i++) {
                if ($i == "" || length($i) > 63 || $i !~ /^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$/) exit 1
            }
        }
    '
}

validate_server_address() {
    local _address="$1"
    [ -n "$_address" ] || return 1
    case "$_address" in
        *[!A-Za-z0-9.:_-]*) return 1 ;;
    esac
    return 0
}

reality_target_candidates() {
    printf '%s\n' \
        "www.microsoft.com" \
        "www.apple.com" \
        "www.amazon.com" \
        "www.amd.com" \
        "www.mozilla.org" \
        "www.nvidia.com" \
        "www.samsung.com" \
        "www.cloudflare.com"
}

random_sni() {
    local _number
    _number=$(od -An -N2 -tu2 /dev/urandom 2>/dev/null | tr -d ' ')
    [ -z "$_number" ] && _number=$(date +%s)
    case $((_number % 8)) in
        0) echo "www.microsoft.com" ;;
        1) echo "www.apple.com" ;;
        2) echo "www.amazon.com" ;;
        3) echo "www.amd.com" ;;
        4) echo "www.mozilla.org" ;;
        5) echo "www.nvidia.com" ;;
        6) echo "www.samsung.com" ;;
        *) echo "www.cloudflare.com" ;;
    esac
}

reality_target_usable() {
    local _host="$1" _port="${2:-443}" _url
    validate_server_name "$_host" && validate_port "$_port" || return 1
    command -v curl >/dev/null 2>&1 || return 1
    _url="https://${_host}:${_port}/"
    if curl --help all 2>/dev/null | grep -q -- '--tls-max'; then
        curl --noproxy '*' -sSI --connect-timeout 4 --max-time 7 \
            --tlsv1.3 --tls-max 1.3 "$_url" >/dev/null 2>&1
    else
        curl --noproxy '*' -sSI --connect-timeout 4 --max-time 7 \
            "$_url" >/dev/null 2>&1
    fi
}

select_reality_target() {
    local _port="${1:-443}" _preferred _candidate _selected _tmp
    local _index=0 _checked=0
    _preferred=$(random_sni)
    _tmp=$(mktemp -d 2>/dev/null) || return 1
    for _candidate in "$_preferred" $(reality_target_candidates); do
        [ "$_index" -gt 0 ] && [ "$_candidate" = "$_preferred" ] && continue
        (
            reality_target_usable "$_candidate" "$_port" \
                && printf '%s' "$_candidate" > "$_tmp/result-${_index}"
        ) &
        _index=$((_index + 1))
    done
    wait || true
    while [ "$_checked" -lt "$_index" ]; do
        if [ -s "$_tmp/result-${_checked}" ]; then
            IFS= read -r _selected < "$_tmp/result-${_checked}"
            rm -f "$_tmp"/result-* 2>/dev/null
            rmdir "$_tmp" 2>/dev/null || true
            printf '%s' "$_selected"
            return 0
        fi
        _checked=$((_checked + 1))
    done
    rm -f "$_tmp"/result-* 2>/dev/null
    rmdir "$_tmp" 2>/dev/null || true
    return 1
}

probe_vps_download_mbps() {
    local _speed
    command -v curl >/dev/null 2>&1 || return 1
    _speed=$(curl --noproxy '*' -fsSL --connect-timeout 5 --max-time 15 \
        -o /dev/null -w '%{speed_download}' \
        'https://speed.cloudflare.com/__down?bytes=5000000') || return 1
    case "$_speed" in
        ''|*[!0-9.]*|*.*.*) return 1 ;;
    esac
    awk -v speed="$_speed" 'BEGIN { printf "%.1f", speed * 8 / 1000000 }'
}

generate_uuid() {
    local _uuid="" _hex
    if [ -x "$SING_BOX_BIN" ]; then
        _uuid=$("$SING_BOX_BIN" generate uuid 2>/dev/null | awk '/^[0-9A-Fa-f-]{36}$/ { print; exit }')
    fi
    if ! validate_uuid "$_uuid" && [ -r /proc/sys/kernel/random/uuid ]; then
        _uuid=$(tr -d '[:space:]' < /proc/sys/kernel/random/uuid)
    fi
    if ! validate_uuid "$_uuid"; then
        _hex=$(openssl rand -hex 16 2>/dev/null | tr -d '[:space:]')
        [ "${#_hex}" = "32" ] || return 1
        _uuid=$(printf '%s-%s-%s-%s-%s' \
            "$(printf '%s' "$_hex" | cut -c1-8)" \
            "$(printf '%s' "$_hex" | cut -c9-12)" \
            "$(printf '%s' "$_hex" | cut -c13-16)" \
            "$(printf '%s' "$_hex" | cut -c17-20)" \
            "$(printf '%s' "$_hex" | cut -c21-32)")
    fi
    validate_uuid "$_uuid" || return 1
    printf '%s' "$_uuid"
}

generate_reality_keypair() {
    local _output _private _public
    [ -x "$SING_BOX_BIN" ] || return 1
    _output=$("$SING_BOX_BIN" generate reality-keypair 2>/dev/null) || return 1
    _private=$(printf '%s\n' "$_output" | awk -F':[[:space:]]*' 'tolower($1) ~ /private/ { print $2; exit }')
    _public=$(printf '%s\n' "$_output" | awk -F':[[:space:]]*' 'tolower($1) ~ /public/ { print $2; exit }')
    validate_reality_key "$_private" || return 1
    validate_reality_key "$_public" || return 1
    REALITY_PRIVATE_KEY="$_private"
    REALITY_PUBLIC_KEY="$_public"
}

generate_short_id() {
    local _short_id
    _short_id=$(openssl rand -hex 8 2>/dev/null | tr -d '[:space:]')
    if ! validate_short_id "$_short_id"; then
        _short_id=$(od -An -N8 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n')
    fi
    validate_short_id "$_short_id" || return 1
    printf '%s' "$_short_id"
}

# ============================================================
# 架构 / URL 构建
# ============================================================
detect_arch() {
    local _machine="${1:-$(uname -m)}"
    case "$_machine" in
        x86_64)        echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        armv7l|armv7)  echo "armv7" ;;
        i386|i686)     echo "386" ;;
        s390x)         echo "s390x" ;;
        *)
            echo -e "${RED}不支持的架构: ${_machine}${PLAIN}" >&2
            return 1
            ;;
    esac
}

build_release_url() {
    local _tag="$1" _arch="$2"
    case "$_tag" in
        latest|"") echo -e "${RED}版本标签不能为 latest，请指定具体版本号${PLAIN}" >&2; return 1 ;;
    esac
    case "$_arch" in
        amd64|arm64|armv7|386|s390x) ;;
        *) echo -e "${RED}不支持的架构: ${_arch}${PLAIN}" >&2; return 1 ;;
    esac
    local _ver="${_tag#v}"
    printf 'https://github.com/SagerNet/sing-box/releases/download/v%s/sing-box-%s-linux-%s.tar.gz\n' \
        "$_ver" "$_ver" "$_arch"
}

version_at_least() {
    awk -v got="$1" -v need="$2" 'BEGIN {
        split(got, g, "."); split(need, n, ".")
        for (i = 1; i <= 3; i++) {
            if ((g[i] + 0) > (n[i] + 0)) exit 0
            if ((g[i] + 0) < (n[i] + 0)) exit 1
        }
        exit 0
    }'
}

normalize_version_tag() {
    local _tag="$1"
    _tag=$(printf '%s' "$_tag" | tr -d '[:space:]' | sed -E 's#^.*/tag/##; s#^.*/download/##; s#[?].*$##')
    [ -n "$_tag" ] || return 1
    case "$_tag" in
        v*) ;;
        *) _tag="v${_tag}" ;;
    esac
    printf '%s\n' "$_tag" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$' || return 1
    printf '%s' "$_tag"
}

set_latest_version_tag() {
    local _candidate _normalized
    for _candidate in "$@"; do
        _normalized=$(normalize_version_tag "$_candidate" 2>/dev/null || true)
        if [ -n "$_normalized" ]; then
            LAST_VERSION_TAG="$_normalized"
            return 0
        fi
    done
    return 1
}

# ============================================================
# 网络检测
# ============================================================
is_valid_ipv4() {
    echo "$1" | awk -F. '
        NF != 4 { exit 1 }
        {
            for (i = 1; i <= 4; i++) {
                if ($i !~ /^[0-9]+$/ || $i < 0 || $i > 255) exit 1
            }
        }
    '
}

is_valid_ipv6() {
    case "$1" in
        *:*) echo "$1" | grep -qE '^[0-9A-Fa-f:]+$' ;;
        *) return 1 ;;
    esac
}

get_native_public_ipv4() {
    command -v ip >/dev/null 2>&1 || return 1
    local _iface _local_ip _ip _url
    _iface=$(ip -4 route show default 2>/dev/null | awk '
        /default/ {
            for (i = 1; i <= NF; i++) {
                if ($i == "dev" && $(i + 1) !~ /wgcf|warp|^tun|^wg|tailscale|zt/) {
                    print $(i + 1)
                    exit
                }
            }
        }
    ')
    [ -n "$_iface" ] || return 1
    _local_ip=$(ip -4 addr show dev "$_iface" scope global 2>/dev/null | awk '
        /inet / { addr=$2; sub(/\/.*/, "", addr); print addr; exit }
    ')
    [ -n "$_local_ip" ] || return 1

    for _url in "https://api.ipify.org" "https://ip.gs" "https://ipv4.icanhazip.com"; do
        _ip=$(curl -s4 --interface "$_local_ip" --connect-timeout 3 --max-time 6 "$_url" 2>/dev/null | tr -d '[:space:]')
        if is_valid_ipv4 "$_ip"; then
            printf '%s' "$_ip"
            return 0
        fi
    done
    return 1
}

get_default_public_ipv4() {
    local _ip _url
    for _url in "https://api.ipify.org" "https://ip.gs" "https://ipv4.icanhazip.com"; do
        _ip=$(curl -s4 --connect-timeout 3 --max-time 6 "$_url" 2>/dev/null | tr -d '[:space:]')
        if is_valid_ipv4 "$_ip"; then
            printf '%s' "$_ip"
            return 0
        fi
    done
    return 1
}

detect_warp() {
    if command -v ip >/dev/null 2>&1 && ip link show 2>/dev/null | grep -qE '^[0-9]+: (wgcf|warp|wg)[^:]*:'; then
        return 0
    fi
    if command -v warp-cli >/dev/null 2>&1 && warp-cli status 2>/dev/null | grep -qiE 'connected|已连接'; then
        return 0
    fi
    return 1
}

detect_network() {
    echo -e "${YELLOW}正在检测网络环境...${PLAIN}"
    NAT_MODE=0; HAS_IPV4=0; HAS_IPV6=0; PUBLIC_IP=""; PUBLIC_IPV6=""; DEFAULT_EGRESS_IPV4=""; WARP_ACTIVE=0; BIND_FAMILY="v4"; LISTEN_HOST="::"
    local _ip _url

    detect_warp && WARP_ACTIVE=1 || true
    DEFAULT_EGRESS_IPV4=$(get_default_public_ipv4 2>/dev/null || true)

    for _url in "https://api6.ipify.org" "https://ipv6.icanhazip.com"; do
        _ip=$(curl -s6 --max-time 6 "$_url" 2>/dev/null | tr -d '[:space:]')
        if is_valid_ipv6 "$_ip"; then PUBLIC_IPV6="$_ip"; HAS_IPV6=1; break; fi
    done

    if command -v ip >/dev/null 2>&1; then
        local _real_ipv6
        _real_ipv6=$(ip -6 addr show scope global 2>/dev/null | awk '
            /^[0-9]+:/ { iface=$2; sub(/:.*/,"",iface) }
            /inet6/ && iface !~ /wgcf|warp|^tun|^wg|tailscale|zt/ {
                addr=$2; sub(/\/.*/,"",addr)
                if (addr !~ /^fe80:/ && addr !~ /^f[cd][0-9a-f][0-9a-f]:/ && addr !~ /^2606:4700:/) { print addr; exit }
            }
        ')
        if [ -n "$_real_ipv6" ]; then
            HAS_IPV6=1
            PUBLIC_IPV6="$_real_ipv6"
        else
            HAS_IPV6=0
            PUBLIC_IPV6=""
        fi
    fi

    _ip=$(get_native_public_ipv4 2>/dev/null || true)
    if is_valid_ipv4 "$_ip"; then
        PUBLIC_IP="$_ip"
        HAS_IPV4=1
    elif [ "$WARP_ACTIVE" = "0" ] && is_valid_ipv4 "$DEFAULT_EGRESS_IPV4"; then
        PUBLIC_IP="$DEFAULT_EGRESS_IPV4"
        HAS_IPV4=1
    fi

    if [ "$HAS_IPV4" = "1" ] && command -v ip >/dev/null 2>&1; then
        local _real_ipv4
        _real_ipv4=$(ip -4 addr show scope global 2>/dev/null | awk '
            /^[0-9]+:/ { iface=$2; sub(/:.*/,"",iface) }
            /inet / && iface !~ /wgcf|warp|^tun|^wg|tailscale|zt/ { print "1"; exit }
        ')
        [ -z "$_real_ipv4" ] && { HAS_IPV4=0; PUBLIC_IP=""; }
    fi

    if [ "$HAS_IPV4" = "1" ] && command -v ip >/dev/null 2>&1; then
        local _local_ips
        _local_ips=$(ip addr show 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -v '^127\.' | grep -v '^169\.254\.')
        echo "$_local_ips" | grep -q "^${PUBLIC_IP}$" || NAT_MODE=1
    fi

    [ "$HAS_IPV4" = "0" ] && [ "$HAS_IPV6" = "1" ] && BIND_FAMILY="v6"
    [ "$HAS_IPV6" = "1" ] && [ "$HAS_IPV4" = "1" ] && BIND_FAMILY="v4"
    [ "$HAS_IPV6" = "0" ] && LISTEN_HOST="0.0.0.0"

    if   [ "$NAT_MODE"     = "1" ]; then echo -e "  机器类型: ${YELLOW}NAT 机器${PLAIN}（公网 IPv4: ${PUBLIC_IP}）"
    elif [ "$BIND_FAMILY"  = "v6" ]; then echo -e "  机器类型: ${YELLOW}纯 IPv6${PLAIN}（IPv6: ${PUBLIC_IPV6}）"
    elif [ "$HAS_IPV6"     = "1" ]; then echo -e "  机器类型: ${GREEN}双栈${PLAIN}（IPv6: ${PUBLIC_IPV6} | IPv4: ${PUBLIC_IP}）"
    elif [ "$HAS_IPV4"     = "1" ]; then echo -e "  机器类型: ${GREEN}标准 IPv4${PLAIN}（IP: ${PUBLIC_IP}）"
    else                                  echo -e "  机器类型: ${RED}无法检测，请手动输入节点地址${PLAIN}"
    fi
    if [ "$WARP_ACTIVE" = "1" ]; then
        echo -e "  WARP 状态: ${YELLOW}已检测到${PLAIN}（仅作为出站，不用于节点入口）"
        [ -n "$DEFAULT_EGRESS_IPV4" ] && echo -e "  默认出口 IPv4: ${YELLOW}${DEFAULT_EGRESS_IPV4}${PLAIN}"
        if [ -z "$PUBLIC_IP" ]; then
            echo -e "  ${RED}未能确认原生 IPv4，已拒绝使用 WARP 出口生成节点${PLAIN}"
        elif [ -n "$DEFAULT_EGRESS_IPV4" ] && [ "$DEFAULT_EGRESS_IPV4" != "$PUBLIC_IP" ]; then
            echo -e "  原生入口 IPv4: ${GREEN}${PUBLIC_IP}${PLAIN}"
        fi
    fi
}

open_ports() {
    local _port=$1
    local _fw_meta="$VLESS_META/firewall"
    mkdir -p "$_fw_meta" 2>/dev/null || true
    echo -e "${YELLOW}正在自动放行 TCP 端口 ${_port}...${PLAIN}"

    if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        if ! firewall-cmd --permanent --query-port="${_port}/tcp" >/dev/null 2>&1; then
            firewall-cmd --permanent --add-port="${_port}/tcp" >/dev/null 2>&1 && \
                : > "$_fw_meta/firewalld-${_port}-tcp"
        fi
        firewall-cmd --reload >/dev/null 2>&1
        echo -e "  ${GREEN}✓ firewalld 已放行 tcp/${_port}${PLAIN}"
        return
    fi

    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "active"; then
        if ! ufw status 2>/dev/null | grep -qE "^${_port}/tcp[[:space:]]+ALLOW"; then
            ufw allow "${_port}/tcp" >/dev/null 2>&1 && : > "$_fw_meta/ufw-${_port}-tcp"
        fi
        echo -e "  ${GREEN}✓ ufw 已放行 tcp/${_port}${PLAIN}"
        return
    fi

    if command -v iptables >/dev/null 2>&1; then
        if ! iptables -C INPUT -p tcp --dport "${_port}" -j ACCEPT >/dev/null 2>&1; then
            iptables -I INPUT -p tcp --dport "${_port}" -j ACCEPT >/dev/null 2>&1 && \
                : > "$_fw_meta/iptables4-${_port}-tcp"
        fi
        if [ "$HAS_IPV6" = "1" ] && command -v ip6tables >/dev/null 2>&1; then
            if ! ip6tables -C INPUT -p tcp --dport "${_port}" -j ACCEPT >/dev/null 2>&1; then
                ip6tables -I INPUT -p tcp --dport "${_port}" -j ACCEPT >/dev/null 2>&1 && \
                    : > "$_fw_meta/iptables6-${_port}-tcp"
            fi
        fi
        if command -v netfilter-persistent >/dev/null 2>&1; then
            netfilter-persistent save >/dev/null 2>&1
        elif [ -f /etc/sysconfig/iptables ] && command -v service >/dev/null 2>&1; then
            service iptables save >/dev/null 2>&1
        fi
        echo -e "  ${GREEN}✓ iptables 已放行 tcp/${_port}${PLAIN}"
    fi
}

close_ports() {
    local _port="$1"
    local _fw_meta="$VLESS_META/firewall"
    validate_port "$_port" || return 0

    if [ -f "$_fw_meta/firewalld-${_port}-tcp" ] && command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        firewall-cmd --permanent --remove-port="${_port}/tcp" >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
        rm -f "$_fw_meta/firewalld-${_port}-tcp"
    fi
    if [ -f "$_fw_meta/ufw-${_port}-tcp" ] && command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "active"; then
        ufw delete allow "${_port}/tcp" >/dev/null 2>&1 || true
        rm -f "$_fw_meta/ufw-${_port}-tcp"
    fi
    if [ -f "$_fw_meta/iptables4-${_port}-tcp" ] && command -v iptables >/dev/null 2>&1; then
        iptables -D INPUT -p tcp --dport "${_port}" -j ACCEPT >/dev/null 2>&1 || true
        rm -f "$_fw_meta/iptables4-${_port}-tcp"
    fi
    if [ -f "$_fw_meta/iptables6-${_port}-tcp" ] && command -v ip6tables >/dev/null 2>&1; then
        ip6tables -D INPUT -p tcp --dport "${_port}" -j ACCEPT >/dev/null 2>&1 || true
        rm -f "$_fw_meta/iptables6-${_port}-tcp"
    fi
    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save >/dev/null 2>&1 || true
    elif [ -f /etc/sysconfig/iptables ] && command -v service >/dev/null 2>&1; then
        service iptables save >/dev/null 2>&1 || true
    fi
}

# ============================================================
# 二进制下载 / 校验
# ============================================================
validate_elf() {
    local _file="$1"
    [ -z "$_file" ] && return 1
    [ -f "$_file" ] || return 1
    [ -s "$_file" ] || return 1
    local _magic
    _magic=$(od -A d -t x1 -N 4 "$_file" 2>/dev/null | awk 'NR==1 { print $2, $3, $4, $5 }')
    [ "$_magic" = "7f 45 4c 46" ] && return 0
    return 1
}

validate_shared_configs_with_bin() {
    local _bin="$1" _config
    [ -x "$_bin" ] || return 1
    for _config in "$VLESS_DIR"/*.json; do
        [ -f "$_config" ] || continue
        if ! "$_bin" check -c "$_config" >/dev/null 2>&1; then
            echo -e "${RED}新核心无法加载共享配置: ${_config}${PLAIN}"
            return 1
        fi
    done
    return 0
}

get_latest_version() {
    echo -e "${YELLOW}正在获取 sing-box 最新稳定版...${PLAIN}"
    LAST_VERSION_TAG=""

    local _candidate _page _url
    _candidate=$(curl -fsSL --connect-timeout 8 --max-time 15 \
        "https://api.github.com/repos/SagerNet/sing-box/releases/latest" 2>/dev/null \
        | awk -F'"' '/"tag_name":/ { print $4; exit }' 2>/dev/null || true)
    set_latest_version_tag "$_candidate" || true

    if [ -z "$LAST_VERSION_TAG" ]; then
        for _url in \
            "https://github.com/SagerNet/sing-box/releases/latest" \
            "https://kkgithub.com/SagerNet/sing-box/releases/latest" \
            "https://gh-proxy.com/https://github.com/SagerNet/sing-box/releases/latest"
        do
            _candidate=$(curl -Ls --connect-timeout 8 --max-time 15 -o /dev/null -w "%{url_effective}" "$_url" 2>/dev/null || true)
            set_latest_version_tag "$_candidate" && break
        done
    fi

    if [ -z "$LAST_VERSION_TAG" ]; then
        for _url in \
            "https://github.com/SagerNet/sing-box/releases" \
            "https://kkgithub.com/SagerNet/sing-box/releases"
        do
            _page=$(curl -fsSL --connect-timeout 8 --max-time 15 "$_url" 2>/dev/null || true)
            _candidate=$(printf '%s\n' "$_page" \
                | grep -oE 'SagerNet/sing-box/releases/(tag|download)/v[0-9]+\.[0-9]+\.[0-9]+' \
                | sed -E 's#.*/(tag|download)/##' | head -1)
            set_latest_version_tag "$_candidate" && break
        done
    fi

    if [ -z "$LAST_VERSION_TAG" ]; then
        if set_latest_version_tag "$SING_BOX_STABLE_FALLBACK_TAG"; then
            echo -e "${YELLOW}[WARN] 无法连接 GitHub 获取最新版本，使用内置稳定版 ${LAST_VERSION_TAG}${PLAIN}"
        else
            echo -e "${RED}获取版本失败或版本标签格式异常${PLAIN}"
            LAST_VERSION_TAG=""
            return 1
        fi
    fi

    echo -e "${GREEN}最新版本: ${LAST_VERSION_TAG}${PLAIN}"
}

get_installed_version() {
    [ -x "$SING_BOX_BIN" ] || return 1
    "$SING_BOX_BIN" version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1
}

download_file() {
    local _url="$1" _dest="$2" _attempt=1 _delay=2
    while [ "$_attempt" -le 3 ]; do
        if command -v curl >/dev/null 2>&1 && curl -fL --connect-timeout 15 --max-time 120 -o "$_dest" "$_url" 2>/dev/null; then return 0; fi
        if command -v wget >/dev/null 2>&1 && wget -q --timeout=60 -O "$_dest" "$_url" 2>/dev/null; then return 0; fi
        rm -f "$_dest"
        [ "$_attempt" -ge 3 ] && break
        sleep "$_delay"; _attempt=$((_attempt + 1)); _delay=$((_delay * 2))
    done
    return 1
}

download_vless() {
    check_download_space || return 1
    local _arch
    _arch=$(detect_arch) || return 1

    local _ver="${LAST_VERSION_TAG#v}"
    local _asset="sing-box-${_ver}-linux-${_arch}.tar.gz"
    local _gh_path="SagerNet/sing-box/releases/download/v${_ver}/${_asset}"
    local _urls=(
        "https://github.com/${_gh_path}"
        "https://ghproxy.com/https://github.com/${_gh_path}"
        "https://kkgithub.com/${_gh_path}"
        "https://gh.api.99988866.xyz/https://github.com/${_gh_path}"
    )

    local _tmp_archive _tmp_dir _ok=0 _url _host
    _tmp_dir=$(mktemp -d "$(disk_tmp_dir)/sing-box-XXXXXX") || return 1
    _tmp_archive="${_tmp_dir}/${_asset}"

    for _url in "${_urls[@]}"; do
        _host=$(echo "$_url" | awk -F/ '{print $3}')
        echo -e "${YELLOW}正在下载 ${_asset}（来源: ${_host}）${PLAIN}"
        rm -f "$_tmp_archive"
        if download_file "$_url" "$_tmp_archive"; then
            if tar -tzf "$_tmp_archive" >/dev/null 2>&1; then
                _ok=1
                break
            fi
            echo -e "${YELLOW}  ↳ 下载内容不是有效压缩包，尝试下一个镜像...${PLAIN}"
            continue
        fi
        echo -e "${YELLOW}  ↳ 失败，尝试下一个镜像...${PLAIN}"
    done

    if [ "$_ok" = "0" ]; then
        rm -rf "$_tmp_dir"
        echo -e "${RED}所有下载源均失败，请检查网络后重试${PLAIN}"
        return 1
    fi

    tar -xzf "$_tmp_archive" -C "$_tmp_dir" || {
        rm -rf "$_tmp_dir"
        echo -e "${RED}解压失败，下载文件可能损坏，请重试${PLAIN}"
        return 1
    }

    local _bin
    _bin=$(find "$_tmp_dir" -type f -name "sing-box" | head -1)
    if [ -z "$_bin" ]; then
        rm -rf "$_tmp_dir"
        echo -e "${RED}未在压缩包中找到 sing-box 二进制${PLAIN}"
        return 1
    fi

    chmod +x "$_bin"
    if ! validate_elf "$_bin"; then
        rm -rf "$_tmp_dir"
        echo -e "${RED}二进制 ELF 校验失败（文件损坏或架构不匹配）${PLAIN}"
        return 1
    fi
    local _downloaded_version
    _downloaded_version=$("$_bin" version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    if [ "$_downloaded_version" != "$_ver" ]; then
        rm -rf "$_tmp_dir"
        echo -e "${RED}sing-box 执行或版本校验失败（期望 ${_ver}，得到 ${_downloaded_version:-未知}）${PLAIN}"
        return 1
    fi
    if ! validate_shared_configs_with_bin "$_bin"; then
        rm -rf "$_tmp_dir"
        echo -e "${RED}为保护现有 sing-box 服务，已拒绝替换共享核心${PLAIN}"
        return 1
    fi

    if ! mv -f "$_bin" "$SING_BOX_BIN" || ! chmod +x "$SING_BOX_BIN"; then
        rm -rf "$_tmp_dir"
        echo -e "${RED}替换 sing-box 二进制失败${PLAIN}"
        return 1
    fi
    MANAGED_SING_BOX=1
    rm -rf "$_tmp_dir"
    echo -e "${GREEN}sing-box 安装完成: $("$SING_BOX_BIN" version 2>/dev/null | head -1)${PLAIN}"
}

ensure_vless_bin() {
    local _preexisting=0
    if [ -x "$SING_BOX_BIN" ]; then
        _preexisting=1
        local _installed_version
        _installed_version=$(get_installed_version)
        if version_at_least "${_installed_version:-0.0.0}" "1.12.0"; then
            if [ -f "$VLESS_META/config.env" ]; then
                MANAGED_SING_BOX=$(awk -F= '$1 == "MANAGED_SING_BOX" { print $2; exit }' "$VLESS_META/config.env")
                [ "$MANAGED_SING_BOX" = "1" ] || MANAGED_SING_BOX=0
            fi
            return 0
        fi
        echo -e "${YELLOW}现有 sing-box ${_installed_version:-未知版本} 低于脚本最低版本 1.12.0，将安装最新版${PLAIN}"
    fi
    get_latest_version || return 1
    download_vless || return 1
    if [ "$_preexisting" = "1" ]; then
        MANAGED_SING_BOX=0
    else
        MANAGED_SING_BOX=1
        mkdir -p "$VLESS_DIR" || { echo -e "${RED}无法创建 sing-box 配置目录${PLAIN}"; return 1; }
        { : > "$SING_BOX_MANAGED_MARKER"; } || { echo -e "${RED}无法写入 sing-box 所有权标记${PLAIN}"; return 1; }
        chmod 600 "$SING_BOX_MANAGED_MARKER" || { echo -e "${RED}无法保护 sing-box 所有权标记${PLAIN}"; return 1; }
    fi
    return 0
}

# ============================================================
# 监听地址 / URI 构建
# ============================================================
listen_address() {
    if [ "${BIND_FAMILY:-v4}" = "v6" ]; then
        printf '[::]:' && printf '%s' "${LISTEN_PORT:-}"
    else
        printf '0.0.0.0:' && printf '%s' "${LISTEN_PORT:-}"
    fi
}

uri_encode() {
    local _in="$1" _out="" _i _c _hex
    local _len="${#_in}"
    _i=0
    while [ "$_i" -lt "$_len" ]; do
        _c="${_in:$_i:1}"
        case "$_c" in
            [a-zA-Z0-9.~_-]) _out="${_out}${_c}" ;;
            ' ') _out="${_out}%20" ;;
            *) _hex=$(printf '%s' "$_c" | od -An -tx1 | awk '{ for (i=1; i<=NF; i++) printf "%%%s", toupper($i) }'); _out="${_out}${_hex}" ;;
        esac
        _i=$(( _i + 1 ))
    done
    printf '%s' "$_out"
}

trim_string() {
    printf '%s' "$1" | tr -d '\r\n\t' | awk '{$1=$1; print}'
}

print_copy_block() {
    printf '%s\n' "$1"
}

get_ip_country() {
    local _ip="$1" _code=""
    [ -z "$_ip" ] && return 1
    _code=$(curl -s --connect-timeout 3 --max-time 4 "https://ipapi.co/${_ip}/country/" 2>/dev/null \
        | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]' | awk '/^[A-Z][A-Z]$/ { print; exit }')
    [ -z "$_code" ] && _code=$(curl -s --connect-timeout 3 --max-time 4 "https://ipinfo.io/${_ip}/country" 2>/dev/null \
        | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]' | awk '/^[A-Z][A-Z]$/ { print; exit }')
    [ -n "$_code" ] && printf '%s' "$_code"
}

get_country_code() {
    local _ipv4="$1" _ipv6="$2" _code=""
    [ -n "$_ipv4" ] && _code=$(get_ip_country "$_ipv4" 2>/dev/null || true)
    [ -z "$_code" ] && [ -n "$_ipv6" ] && _code=$(get_ip_country "$_ipv6" 2>/dev/null || true)
    [ -z "$_code" ] && _code="UN"
    printf '%s' "$_code"
}

get_country_name() {
    case "$1" in
        US) printf 'United States' ;; DE) printf 'Germany' ;; JP) printf 'Japan' ;; SG) printf 'Singapore' ;;
        HK) printf 'Hong Kong' ;; TW) printf 'Taiwan' ;; KR) printf 'South Korea' ;; GB) printf 'United Kingdom' ;;
        FR) printf 'France' ;; NL) printf 'Netherlands' ;; CA) printf 'Canada' ;; AU) printf 'Australia' ;;
        RU) printf 'Russia' ;; IN) printf 'India' ;; VN) printf 'Vietnam' ;; TH) printf 'Thailand' ;;
        UN) printf 'Unknown' ;; *) printf 'Unknown' ;;
    esac
}

get_country_flag() {
    case "$1" in
        US) printf '🇺🇸' ;; DE) printf '🇩🇪' ;; JP) printf '🇯🇵' ;; SG) printf '🇸🇬' ;;
        HK) printf '🇭🇰' ;; TW) printf '🇹🇼' ;; KR) printf '🇰🇷' ;; GB) printf '🇬🇧' ;;
        FR) printf '🇫🇷' ;; NL) printf '🇳🇱' ;; CA) printf '🇨🇦' ;; AU) printf '🇦🇺' ;;
        RU) printf '🇷🇺' ;; IN) printf '🇮🇳' ;; VN) printf '🇻🇳' ;; TH) printf '🇹🇭' ;;
        *) printf '🌐' ;;
    esac
}

generate_server_name() {
    local _name
    _name=$(hostname 2>/dev/null | tr -d '\n\r\t')
    _name=$(trim_string "$_name")
    [ -z "$_name" ] && _name="server.$(printf '%06X' "$(( (RANDOM << 1) ^ RANDOM ))")"
    printf '%s' "$_name"
}

generate_node_name() {
    local _country _flag _server _protocol _ip_type
    _country=$(printf '%s' "${1:-UN}" | tr '[:lower:]' '[:upper:]')
    case "$_country" in [A-Z][A-Z]) ;; *) _country="UN" ;; esac
    _flag=$(get_country_flag "$_country")
    _server=$(trim_string "${2:-}")
    [ -z "$_server" ] && _server=$(generate_server_name)
    _protocol=$(trim_string "${3:-VLESS}")
    _ip_type=$(trim_string "${4:-IPv4}")
    printf '%s %s | %s | %s | %s' "$_flag" "$_country" "$_server" "$_protocol" "$_ip_type" | tr -d '\r\n\t'
}

format_ipv6_for_uri() {
    echo "$1" | grep -q ':' && printf '[%s]' "$1" || printf '%s' "$1"
}

format_server_for_yaml() {
    echo "$1" | grep -q ':' && printf "'%s'" "$1" || printf '%s' "$1"
}

shell_json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

yaml_single_quote_escape() {
    printf '%s' "$1" | sed "s/'/''/g"
}

generate_terminal_qrcode() {
    local _data="$1"
    command -v qrencode >/dev/null 2>&1 || return 1
    qrencode -t ANSIUTF8 -m 2 "$_data"
}

generate_local_qrcode_png() {
    local _data="$1" _protocol="$2" _ip_type="$3" _dir="/root/singbox-tools/qrcode" _slug _file
    command -v qrencode >/dev/null 2>&1 || return 1
    _slug=$(printf '%s' "$_protocol" | tr '[:upper:]' '[:lower:]' | tr ' ' '-' | tr -cd 'a-z0-9-')
    mkdir -p "$_dir" 2>/dev/null || return 1
    _file="${_dir}/${_slug}-${_ip_type}.png"
    qrencode -o "$_file" "$_data" 2>/dev/null || return 1
    printf '%s' "$_file"
}

generate_online_qrcode_url() {
    local _data="$1" _encoded
    _encoded=$(uri_encode "$_data")
    printf 'https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=%s' "$_encoded"
}

render_uri() {
    local _server="$1" _port="$2" _uuid="$3" _name="$4" _sni="${5:-$SERVER_NAME}"
    local _public_key="${6:-$REALITY_PUBLIC_KEY}" _short_id="${7:-$SHORT_ID}"
    local _host
    _host=$(format_ipv6_for_uri "$_server")
    local _enc_name _enc_sni
    _enc_name=$(uri_encode "$_name")
    _enc_sni=$(uri_encode "$_sni")
    printf 'vless://%s@%s:%s?encryption=none&flow=xtls-rprx-vision&security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s&type=tcp#%s\n' \
        "$_uuid" "$_host" "$_port" "$_enc_sni" "$_public_key" "$_short_id" "$_enc_name"
}

# ============================================================
# 配置写入 / 读取
# ============================================================
write_config() {
    mkdir -p "$VLESS_DIR" "$VLESS_META"
    chmod 700 "$VLESS_META"
    local _tmp_config _tmp_meta
    _tmp_config=$(mktemp "${VLESS_DIR}/vless.json.new.XXXXXX" 2>/dev/null) || return 1
    _tmp_meta=$(mktemp "${VLESS_META}/config.env.new.XXXXXX" 2>/dev/null) || {
        rm -f "$_tmp_config"
        return 1
    }
    if ! cat > "$_tmp_config" <<CFG
{
  "log": { "level": "info", "timestamp": true },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "${LISTEN_HOST}",
      "listen_port": ${LISTEN_PORT},
      "users": [
        {
          "name": "default",
          "uuid": "${UUID}",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "${SERVER_NAME}",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "${SERVER_NAME}",
            "server_port": ${HANDSHAKE_PORT}
          },
          "private_key": "${REALITY_PRIVATE_KEY}",
          "short_id": ["${SHORT_ID}"]
        }
      }
    }
  ],
  "outbounds": [{ "type": "direct", "tag": "direct" }]
}
CFG
    then
        rm -f "$_tmp_config" "$_tmp_meta"
        return 1
    fi
    if ! cat > "$_tmp_meta" <<CFG
LISTEN_PORT=${LISTEN_PORT}
EXT_PORT=${EXT_PORT}
UUID=${UUID}
REALITY_PRIVATE_KEY=${REALITY_PRIVATE_KEY}
REALITY_PUBLIC_KEY=${REALITY_PUBLIC_KEY}
SHORT_ID=${SHORT_ID}
NAT_MODE=${NAT_MODE}
BIND_FAMILY=${BIND_FAMILY}
LISTEN_HOST=${LISTEN_HOST}
SERVER_NAME=${SERVER_NAME}
HANDSHAKE_PORT=${HANDSHAKE_PORT}
MANAGED_SING_BOX=${MANAGED_SING_BOX}
CFG
    then
        rm -f "$_tmp_config" "$_tmp_meta"
        return 1
    fi
    chmod 600 "$_tmp_config" "$_tmp_meta" || {
        rm -f "$_tmp_config" "$_tmp_meta"
        return 1
    }
    mv -f "$_tmp_meta" "$VLESS_META/config.env" || {
        rm -f "$_tmp_config" "$_tmp_meta"
        return 1
    }
    mv -f "$_tmp_config" "$VLESS_CONFIG" || {
        rm -f "$_tmp_config"
        return 1
    }
    atomic_write_meta "$VLESS_META/public_ip" "$PUBLIC_IP" || return 1
    atomic_write_meta "$VLESS_META/public_ipv6" "$PUBLIC_IPV6" || return 1
}

atomic_write_meta() {
    local _target="$1" _value="$2" _tmp
    _tmp=$(mktemp "${_target}.new.XXXXXX" 2>/dev/null) || return 1
    printf '%s' "$_value" > "$_tmp" && chmod 600 "$_tmp" && mv -f "$_tmp" "$_target" || {
        rm -f "$_tmp"
        return 1
    }
}

read_config() {
    [ -f "$VLESS_CONFIG" ] && [ -f "$VLESS_META/config.env" ] || return 1
    while IFS='=' read -r _key _value; do
        case "$_key" in
            LISTEN_PORT) LISTEN_PORT="$_value" ;;
            EXT_PORT) EXT_PORT="$_value" ;;
            UUID) UUID="$_value" ;;
            REALITY_PRIVATE_KEY) REALITY_PRIVATE_KEY="$_value" ;;
            REALITY_PUBLIC_KEY) REALITY_PUBLIC_KEY="$_value" ;;
            SHORT_ID) SHORT_ID="$_value" ;;
            NAT_MODE) NAT_MODE="$_value" ;;
            BIND_FAMILY) BIND_FAMILY="$_value" ;;
            LISTEN_HOST) LISTEN_HOST="$_value" ;;
            SERVER_NAME) SERVER_NAME="$_value" ;;
            HANDSHAKE_PORT) HANDSHAKE_PORT="$_value" ;;
            MANAGED_SING_BOX) MANAGED_SING_BOX="$_value" ;;
        esac
    done < "$VLESS_META/config.env"
    validate_port "$LISTEN_PORT" || return 1
    validate_port "$EXT_PORT" || return 1
    validate_uuid "$UUID" || return 1
    validate_reality_key "$REALITY_PRIVATE_KEY" || return 1
    validate_reality_key "$REALITY_PUBLIC_KEY" || return 1
    validate_short_id "$SHORT_ID" || return 1
    validate_server_name "$SERVER_NAME" || return 1
    validate_port "$HANDSHAKE_PORT" || return 1
    case "$NAT_MODE" in 0|1) ;; *) return 1 ;; esac
    case "$BIND_FAMILY" in v4|v6) ;; *) return 1 ;; esac
    case "$LISTEN_HOST" in 0.0.0.0|::) ;; *) LISTEN_HOST="::" ;; esac
    case "$MANAGED_SING_BOX" in 0|1) ;; *) MANAGED_SING_BOX=0 ;; esac
    [ -z "${PUBLIC_IP:-}"   ] && PUBLIC_IP=$(cat "$VLESS_META/public_ip"   2>/dev/null || true)
    [ -z "${PUBLIC_IPV6:-}" ] && PUBLIC_IPV6=$(cat "$VLESS_META/public_ipv6" 2>/dev/null || true)
    return 0
}

show_install_diagnostics() {
    echo -e "${YELLOW}诊断信息:${PLAIN}"
    echo "  sing-box: $SING_BOX_BIN"
    "$SING_BOX_BIN" version 2>&1 | head -1 | sed 's/^/  version : /'
    echo "  config  : $VLESS_CONFIG"
    echo "  meta    : $VLESS_META/config.env"
    [ -s "$VLESS_CONFIG" ] || echo -e "  ${RED}配置文件缺失或为空${PLAIN}"
    validate_reality_key "$REALITY_PRIVATE_KEY" || echo -e "  ${RED}REALITY 私钥缺失或无效${PLAIN}"
    validate_reality_key "$REALITY_PUBLIC_KEY" || echo -e "  ${RED}REALITY 公钥缺失或无效${PLAIN}"
}

write_wrapper() {
    cat > "$VLESS_BIN" <<WRAPPER || return 1
#!/bin/sh
exec "${SING_BOX_BIN}" run -c "${VLESS_CONFIG}" "\$@"
WRAPPER
    chmod 755 "$VLESS_BIN"
}

check_config() {
    "$SING_BOX_BIN" check -c "$VLESS_CONFIG"
}

backup_current_install() {
    INSTALL_BACKUP_DIR=$(mktemp -d "$(disk_tmp_dir)/vless-backup-XXXXXX") || return 1
    [ ! -f "$VLESS_CONFIG" ] || cp -a "$VLESS_CONFIG" "$INSTALL_BACKUP_DIR/config" || { discard_install_backup; return 1; }
    [ ! -d "$VLESS_META" ] || cp -a "$VLESS_META" "$INSTALL_BACKUP_DIR/meta" || { discard_install_backup; return 1; }
    [ ! -f "$SING_BOX_MANAGED_MARKER" ] || cp -a "$SING_BOX_MANAGED_MARKER" "$INSTALL_BACKUP_DIR/managed-marker" || { discard_install_backup; return 1; }
    [ ! -f "$VLESS_BIN" ] || cp -a "$VLESS_BIN" "$INSTALL_BACKUP_DIR/wrapper" || { discard_install_backup; return 1; }
    [ ! -f "$SING_BOX_BIN" ] || cp -a "$SING_BOX_BIN" "$INSTALL_BACKUP_DIR/sing-box" || { discard_install_backup; return 1; }
    [ ! -f "$SYSTEMD_SERVICE" ] || cp -a "$SYSTEMD_SERVICE" "$INSTALL_BACKUP_DIR/systemd-service" || { discard_install_backup; return 1; }
    [ ! -f "$OPENRC_SERVICE" ] || cp -a "$OPENRC_SERVICE" "$INSTALL_BACKUP_DIR/openrc-service" || { discard_install_backup; return 1; }
    service_is_active && : > "$INSTALL_BACKUP_DIR/was-active" || true
    service_is_enabled && : > "$INSTALL_BACKUP_DIR/was-enabled" || true
    arm_install_rollback
    return 0
}

arm_install_rollback() {
    [ "$INSTALL_ROLLBACK_ARMED" = "0" ] || return 0
    INSTALL_PREV_INT_TRAP=$(trap -p INT)
    INSTALL_PREV_TERM_TRAP=$(trap -p TERM)
    trap 'rollback_install_on_signal 130' INT
    trap 'rollback_install_on_signal 143' TERM
    INSTALL_ROLLBACK_ARMED=1
}

disarm_install_rollback() {
    [ "$INSTALL_ROLLBACK_ARMED" = "1" ] || return 0
    trap - INT TERM
    [ -z "$INSTALL_PREV_INT_TRAP" ] || eval "$INSTALL_PREV_INT_TRAP"
    [ -z "$INSTALL_PREV_TERM_TRAP" ] || eval "$INSTALL_PREV_TERM_TRAP"
    INSTALL_PREV_INT_TRAP=""
    INSTALL_PREV_TERM_TRAP=""
    INSTALL_ROLLBACK_ARMED=0
}

rollback_install_on_signal() {
    local _status="$1"
    trap - INT TERM
    echo -e "\n${YELLOW}安装被中断，正在恢复原配置和服务...${PLAIN}" >&2
    restore_current_install
    exit "$_status"
}

discard_install_backup() {
    [ -n "$INSTALL_BACKUP_DIR" ] && rm -rf "$INSTALL_BACKUP_DIR"
    INSTALL_BACKUP_DIR=""
    disarm_install_rollback
}

restore_current_install() {
    [ -n "$INSTALL_BACKUP_DIR" ] && [ -d "$INSTALL_BACKUP_DIR" ] || return 0
    service_stop
    service_disable
    close_ports "${LISTEN_PORT:-}"
    rm -f "$VLESS_CONFIG" "$VLESS_BIN" "$SYSTEMD_SERVICE" "$OPENRC_SERVICE"
    rm -f "$SING_BOX_MANAGED_MARKER"
    rm -rf "$VLESS_META"

    [ -f "$INSTALL_BACKUP_DIR/config" ] && cp -a "$INSTALL_BACKUP_DIR/config" "$VLESS_CONFIG"
    [ -d "$INSTALL_BACKUP_DIR/meta" ] && cp -a "$INSTALL_BACKUP_DIR/meta" "$VLESS_META"
    [ -f "$INSTALL_BACKUP_DIR/managed-marker" ] && cp -a "$INSTALL_BACKUP_DIR/managed-marker" "$SING_BOX_MANAGED_MARKER"
    [ -f "$INSTALL_BACKUP_DIR/wrapper" ] && cp -a "$INSTALL_BACKUP_DIR/wrapper" "$VLESS_BIN"
    if [ -f "$INSTALL_BACKUP_DIR/sing-box" ]; then
        cp -a "$INSTALL_BACKUP_DIR/sing-box" "$SING_BOX_BIN"
    elif [ "$MANAGED_SING_BOX" = "1" ]; then
        rm -f "$SING_BOX_BIN"
    fi
    [ -f "$INSTALL_BACKUP_DIR/systemd-service" ] && cp -a "$INSTALL_BACKUP_DIR/systemd-service" "$SYSTEMD_SERVICE"
    [ -f "$INSTALL_BACKUP_DIR/openrc-service" ] && cp -a "$INSTALL_BACKUP_DIR/openrc-service" "$OPENRC_SERVICE"
    [ "$INIT_SYS" = "systemd" ] && systemctl daemon-reload
    [ -f "$INSTALL_BACKUP_DIR/was-enabled" ] && service_enable >/dev/null 2>&1 || true
    [ -f "$INSTALL_BACKUP_DIR/was-active" ] && service_start >/dev/null 2>&1 || true
    discard_install_backup
}

read_config_live() {
    read_config || return 1
    local _warp_active=0
    if detect_warp; then
        _warp_active=1
        local _native_ipv4 _default_ipv4
        _native_ipv4=$(get_native_public_ipv4 2>/dev/null || true)
        _default_ipv4=$(get_default_public_ipv4 2>/dev/null || true)
        if is_valid_ipv4 "$_native_ipv4"; then
            PUBLIC_IP="$_native_ipv4"
            printf '%s' "$PUBLIC_IP" > "$VLESS_META/public_ip"
        elif is_valid_ipv4 "$_default_ipv4" && [ "$PUBLIC_IP" = "$_default_ipv4" ]; then
            PUBLIC_IP=""
            : > "$VLESS_META/public_ip"
        fi
    fi
    if [ -z "${PUBLIC_IP:-}" ] && [ -z "${PUBLIC_IPV6:-}" ]; then
        [ "$_warp_active" = "1" ] || PUBLIC_IP=$(get_default_public_ipv4 2>/dev/null || true)
        PUBLIC_IPV6=$(curl -s6 --max-time 6 https://api6.ipify.org 2>/dev/null | tr -d '[:space:]') || true
    fi
}

# ============================================================
# 服务管理
# ============================================================
write_systemd_service() {
    cat > "$SYSTEMD_SERVICE" <<SVC || return 1
[Unit]
Description=VLESS Server
After=network.target nss-lookup.target
Wants=network.target

[Service]
Type=simple
User=root
ExecStart=${VLESS_BIN}
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
SVC
    chmod 600 "$SYSTEMD_SERVICE"
}

write_openrc_service() {
    cat > "$OPENRC_SERVICE" <<'SVCHEAD' || return 1
#!/sbin/openrc-run

name="vless-server"
description="VLESS Server"
SVCHEAD
    cat >> "$OPENRC_SERVICE" <<SVC || return 1
command="${VLESS_BIN}"
command_args=""
command_background="yes"
pidfile="/var/run/vless-server.pid"
output_log="/var/log/vless-server.log"
error_log="/var/log/vless-server.log"

depend() {
    need net
    after firewall
}
SVC
    chmod +x "$OPENRC_SERVICE"
}

service_start() {
    [ -x "$VLESS_BIN" ] && [ -f "$VLESS_CONFIG" ] || {
        echo -e "${RED}VLESS 尚未安装或配置不完整${PLAIN}"
        return 1
    }
    service_is_active && return 0
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl start vless-server
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service vless-server start
    else
        nohup "$VLESS_BIN" >/var/log/vless-server.log 2>&1 &
        echo $! > /var/run/vless-server.pid
    fi
}

service_stop() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl stop vless-server 2>/dev/null
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service vless-server stop 2>/dev/null
    else
        if [ -f /var/run/vless-server.pid ]; then
            kill "$(cat /var/run/vless-server.pid)" 2>/dev/null || true
            rm -f /var/run/vless-server.pid
        fi
    fi
}

service_restart() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl restart vless-server
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service vless-server restart
    else
        service_stop; sleep 1; service_start
    fi
}

service_enable() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl daemon-reload
        systemctl enable vless-server >/dev/null 2>&1
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-update add vless-server default >/dev/null 2>&1
    fi
}

service_disable() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl disable vless-server 2>/dev/null
        systemctl daemon-reload
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-update del vless-server default 2>/dev/null
    fi
}

service_is_active() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl is-active --quiet vless-server
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service vless-server status 2>/dev/null | grep -q "started"
    else
        [ -f /var/run/vless-server.pid ] && kill -0 "$(cat /var/run/vless-server.pid)" 2>/dev/null
    fi
}

shared_anytls_service_is_active() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl is-active --quiet anytls-server 2>/dev/null
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service anytls-server status 2>/dev/null | grep -q "started"
    else
        [ -f /var/run/anytls-server.pid ] && kill -0 "$(cat /var/run/anytls-server.pid)" 2>/dev/null
    fi
}

shared_anytls_service_restart() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl restart anytls-server
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service anytls-server restart
    else
        [ -x /usr/local/bin/anytls-server ] || return 1
        if [ -f /var/run/anytls-server.pid ]; then
            kill "$(cat /var/run/anytls-server.pid)" 2>/dev/null || true
            rm -f /var/run/anytls-server.pid
        fi
        nohup /usr/local/bin/anytls-server >/var/log/anytls-server.log 2>&1 &
        echo $! > /var/run/anytls-server.pid
    fi
}

service_is_healthy() {
    service_is_active || return 1
    validate_port "${LISTEN_PORT:-}" || return 0
    command -v ss >/dev/null 2>&1 || return 0
    ss -lnt 2>/dev/null | awk -v port="$LISTEN_PORT" '
        NR > 1 { addr=$4; if (addr ~ (":" port "$")) found=1 }
        END { exit(found ? 0 : 1) }
    '
}

has_free_space_mb() {
    local _path="$1" _required="$2" _available
    command -v df >/dev/null 2>&1 || return 0
    _available=$(df -Pk "$_path" 2>/dev/null | awk 'NR == 2 { print $4; exit }')
    [ -z "$_available" ] && return 0
    [ "$_available" -ge $((_required * 1024)) ]
}

check_download_space() {
    has_free_space_mb "$(disk_tmp_dir)" 160 && has_free_space_mb "$(dirname "$SING_BOX_BIN")" 48 || {
        echo -e "${RED}磁盘空间不足：下载并解压 sing-box 至少需要临时分区 160MB、目标分区 48MB${PLAIN}"
        return 1
    }
}

service_is_enabled() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl is-enabled --quiet vless-server 2>/dev/null
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-update show default 2>/dev/null | grep -qE '(^|[[:space:]])vless-server([[:space:]]|$)'
    else
        return 1
    fi
}

service_logs() {
    if [ "$INIT_SYS" = "systemd" ]; then
        journalctl -u vless-server -n 80 --no-pager
    else
        tail -n 80 /var/log/vless-server.log 2>/dev/null || echo -e "${YELLOW}暂无日志${PLAIN}"
    fi
}

# ============================================================
# 安装 / 修改
# ============================================================
configure_vless() {
    local _default_port _default_sni _target_verified=0
    _default_port=$(generate_random_port) || { echo -e "${RED}无法生成可用随机端口${PLAIN}"; return 1; }
    echo -e "\n${SKYBLUE}--- 配置 VLESS + REALITY + Vision 协议 ---${PLAIN}"

    if [ "$NAT_MODE" = "1" ]; then
        read -r -p "请输入本机监听端口 [随机默认 ${_default_port}]: " LISTEN_PORT
        [ -z "$LISTEN_PORT" ] && LISTEN_PORT="$_default_port"
        validate_port "$LISTEN_PORT" || { echo -e "${RED}端口必须为 1-65535 的整数${PLAIN}"; return 1; }
        read -r -p "请输入对外转发端口 [留空=与监听端口相同]: " EXT_PORT
        [ -z "$EXT_PORT" ] && EXT_PORT="$LISTEN_PORT"
        validate_port "$EXT_PORT" || { echo -e "${RED}对外端口必须为 1-65535 的整数${PLAIN}"; return 1; }
        echo -e "${YELLOW}提示：请确保宿主机已将 TCP ${EXT_PORT} 转发到本机 TCP ${LISTEN_PORT}${PLAIN}"
    else
        read -r -p "请输入端口 [随机默认 ${_default_port}]: " LISTEN_PORT
        [ -z "$LISTEN_PORT" ] && LISTEN_PORT="$_default_port"
        validate_port "$LISTEN_PORT" || { echo -e "${RED}端口必须为 1-65535 的整数（输入值: '${LISTEN_PORT}'）${PLAIN}"; return 1; }
        EXT_PORT="$LISTEN_PORT"
        echo -e "${GREEN}端口: ${LISTEN_PORT}${PLAIN}"
    fi

    read -r -p "请输入 VLESS UUID [留空自动生成]: " UUID
    if [ -z "$UUID" ]; then
        UUID=$(generate_uuid) || { echo -e "${RED}生成 UUID 失败${PLAIN}"; return 1; }
        echo -e "${GREEN}自动生成 UUID: ${YELLOW}${UUID}${PLAIN}"
    fi
    validate_uuid "$UUID" || { echo -e "${RED}UUID 格式无效${PLAIN}"; return 1; }

    read -r -p "请输入 REALITY 目标端口 [默认 443]: " HANDSHAKE_PORT
    [ -z "$HANDSHAKE_PORT" ] && HANDSHAKE_PORT="443"
    validate_port "$HANDSHAKE_PORT" || { echo -e "${RED}REALITY 目标端口无效${PLAIN}"; return 1; }

    echo -e "${YELLOW}正在从当前 VPS 检测可用 REALITY 目标...${PLAIN}"
    if _default_sni=$(select_reality_target "$HANDSHAKE_PORT"); then
        _target_verified=1
        echo -e "${GREEN}✓ 已找到可用目标: ${_default_sni}:${HANDSHAKE_PORT}${PLAIN}"
    else
        _default_sni=$(random_sni)
        echo -e "${YELLOW}! 未能自动验证候选目标，请确认 VPS 可访问 ${_default_sni}:${HANDSHAKE_PORT}${PLAIN}"
    fi
    read -r -p "请输入 REALITY 目标域名/SNI [默认 ${_default_sni}]: " SERVER_NAME
    [ -z "$SERVER_NAME" ] && SERVER_NAME="$_default_sni"
    validate_server_name "$SERVER_NAME" || { echo -e "${RED}REALITY 目标域名格式无效${PLAIN}"; return 1; }
    if [ "$SERVER_NAME" != "$_default_sni" ] || [ "$_target_verified" != "1" ]; then
        if reality_target_usable "$SERVER_NAME" "$HANDSHAKE_PORT"; then
            echo -e "${GREEN}✓ REALITY 目标 HTTPS/TLS 可达${PLAIN}"
        else
            echo -e "${YELLOW}! 当前 VPS 无法验证该目标，节点可能握手不稳定或无法连接${PLAIN}"
        fi
    fi

    echo -e "${YELLOW}正在生成 REALITY 密钥对...${PLAIN}"
    generate_reality_keypair || { echo -e "${RED}生成 REALITY 密钥对失败${PLAIN}"; return 1; }
    SHORT_ID=$(generate_short_id) || { echo -e "${RED}生成 REALITY short ID 失败${PLAIN}"; return 1; }
    echo -e "${GREEN}✓ REALITY 密钥与 short ID 已生成${PLAIN}"
    echo -e "${DIM}私钥仅写入服务器配置，不会出现在节点输出中。${PLAIN}"

    NODE_NAME="VLESS-$(hostname 2>/dev/null | tr -d '\n\r')"
    [ "$NODE_NAME" = "VLESS-" ] && NODE_NAME="VLESS-Node"
    return 0
}

install_vless() {
    install_dependencies || { read -r -p "按回车键返回主菜单..." _; return; }
    detect_network
    backup_current_install || { echo -e "${RED}无法创建安装备份，已取消操作${PLAIN}"; read -r -p "按回车键返回主菜单..." _; return; }
    ensure_vless_bin || { restore_current_install; read -r -p "按回车键返回主菜单..." _; return; }
    configure_vless || { restore_current_install; read -r -p "按回车键返回主菜单..." _; return; }
    write_config || {
        echo -e "${RED}VLESS 配置写入失败${PLAIN}"
        restore_current_install
        read -r -p "按回车键返回主菜单..." _
        return
    }
    write_wrapper || {
        echo -e "${RED}VLESS 启动 wrapper 写入失败${PLAIN}"
        restore_current_install
        read -r -p "按回车键返回主菜单..." _
        return
    }
    echo -e "${YELLOW}正在校验 sing-box 配置...${PLAIN}"
    if ! check_config; then
        echo -e "${RED}sing-box 配置校验失败${PLAIN}"
        show_install_diagnostics
        restore_current_install
        read -r -p "按回车键返回主菜单..." _
        return
    fi
    echo -e "${GREEN}✓ sing-box 配置校验通过${PLAIN}"

    if [ "$INIT_SYS" = "systemd" ]; then
        write_systemd_service || { restore_current_install; return; }
    elif [ "$INIT_SYS" = "openrc" ]; then
        write_openrc_service || { restore_current_install; return; }
    fi

    service_enable
    open_ports "$LISTEN_PORT"
    echo -e "${YELLOW}正在启动 VLESS 服务...${PLAIN}"
    if service_is_active; then service_restart; else service_start; fi

    sleep 2
    if service_is_healthy; then
        echo -e "${GREEN}✓ VLESS 服务端启动成功${PLAIN}"
    else
        echo -e "${RED}✗ VLESS 启动失败，请查看日志：${PLAIN}"
        service_logs
        restore_current_install
        echo -e "${YELLOW}已恢复安装前的配置和服务${PLAIN}"
        read -r -p "按回车键返回主菜单..." _tmp
        return
    fi

    discard_install_backup
    show_config
}

change_config() {
    if [ ! -f "$VLESS_CONFIG" ]; then
        echo -e "${RED}未安装 VLESS${PLAIN}"; sleep 2; return
    fi
    read_config || { echo -e "${RED}VLESS 配置或元数据损坏，无法安全修改${PLAIN}"; sleep 2; return; }
    local _old_port="$LISTEN_PORT" _was_active=0 _port _ext _uuid _sni _handshake_port _regen
    service_is_active && _was_active=1 || true
    detect_network

    echo -e "\n${YELLOW}修改 VLESS 配置，留空则保留原值。${PLAIN}"
    read -r -p "监听端口 [当前 ${LISTEN_PORT}]: " _port
    if [ -n "$_port" ]; then
        validate_port "$_port" || { echo -e "${RED}端口无效${PLAIN}"; sleep 2; return; }
        LISTEN_PORT="$_port"
    fi

    read -r -p "对外端口 [当前 ${EXT_PORT:-$LISTEN_PORT}]: " _ext
    if [ -n "$_ext" ]; then
        validate_port "$_ext" || { echo -e "${RED}端口无效${PLAIN}"; sleep 2; return; }
        EXT_PORT="$_ext"
    fi
    [ -z "$EXT_PORT" ] && EXT_PORT="$LISTEN_PORT"

    read -r -p "VLESS UUID [留空保留原 UUID]: " _uuid
    if [ -n "$_uuid" ]; then
        validate_uuid "$_uuid" || { echo -e "${RED}UUID 格式无效${PLAIN}"; sleep 2; return; }
        UUID="$_uuid"
    fi

    read -r -p "REALITY 目标域名/SNI [当前 ${SERVER_NAME}]: " _sni
    if [ -n "$_sni" ]; then
        validate_server_name "$_sni" || { echo -e "${RED}目标域名格式无效${PLAIN}"; sleep 2; return; }
        SERVER_NAME="$_sni"
    fi

    read -r -p "REALITY 目标端口 [当前 ${HANDSHAKE_PORT}]: " _handshake_port
    if [ -n "$_handshake_port" ]; then
        validate_port "$_handshake_port" || { echo -e "${RED}目标端口无效${PLAIN}"; sleep 2; return; }
        HANDSHAKE_PORT="$_handshake_port"
    fi
    if [ -n "${_sni}${_handshake_port}" ]; then
        echo -e "${YELLOW}正在验证 REALITY 目标...${PLAIN}"
        reality_target_usable "$SERVER_NAME" "$HANDSHAKE_PORT" \
            && echo -e "${GREEN}✓ REALITY 目标 HTTPS/TLS 可达${PLAIN}" \
            || echo -e "${YELLOW}! 当前 VPS 无法验证该目标，保存后可能影响连接稳定性${PLAIN}"
    fi

    read -r -p "重新生成 REALITY 密钥和 short ID？[y/N]: " _regen
    case "$_regen" in
        [yY])
            generate_reality_keypair || { echo -e "${RED}生成 REALITY 密钥对失败${PLAIN}"; return; }
            SHORT_ID=$(generate_short_id) || { echo -e "${RED}生成 short ID 失败${PLAIN}"; return; }
            ;;
    esac

    cp -p "$VLESS_CONFIG" "${VLESS_CONFIG}.bak" 2>/dev/null && \
    cp -p "$VLESS_META/config.env" "$VLESS_META/config.env.bak" 2>/dev/null && \
    cp -p "$VLESS_META/public_ip" "$VLESS_META/public_ip.bak" 2>/dev/null && \
    cp -p "$VLESS_META/public_ipv6" "$VLESS_META/public_ipv6.bak" 2>/dev/null || {
        rm -f "${VLESS_CONFIG}.bak" "$VLESS_META/config.env.bak" \
            "$VLESS_META/public_ip.bak" "$VLESS_META/public_ipv6.bak"
        echo -e "${RED}无法创建完整配置备份，已取消修改${PLAIN}"
        return
    }

    if ! write_config || ! check_config; then
        mv -f "${VLESS_CONFIG}.bak" "$VLESS_CONFIG" 2>/dev/null || true
        mv -f "$VLESS_META/config.env.bak" "$VLESS_META/config.env" 2>/dev/null || true
        mv -f "$VLESS_META/public_ip.bak" "$VLESS_META/public_ip" 2>/dev/null || true
        mv -f "$VLESS_META/public_ipv6.bak" "$VLESS_META/public_ipv6" 2>/dev/null || true
        echo -e "${RED}配置无效，已回滚${PLAIN}"
        sleep 2
        return
    fi
    if [ "$INIT_SYS" = "systemd" ]; then
        write_systemd_service
    elif [ "$INIT_SYS" = "openrc" ]; then
        write_openrc_service
    fi

    open_ports "$LISTEN_PORT"
    [ "$_was_active" = "1" ] && service_restart
    sleep 1
    if [ "$_was_active" = "1" ] && ! service_is_healthy; then
        [ "$_old_port" = "$LISTEN_PORT" ] || close_ports "$LISTEN_PORT"
        mv -f "${VLESS_CONFIG}.bak" "$VLESS_CONFIG" 2>/dev/null || true
        mv -f "$VLESS_META/config.env.bak" "$VLESS_META/config.env" 2>/dev/null || true
        mv -f "$VLESS_META/public_ip.bak" "$VLESS_META/public_ip" 2>/dev/null || true
        mv -f "$VLESS_META/public_ipv6.bak" "$VLESS_META/public_ipv6" 2>/dev/null || true
        read_config || true
        service_restart || true
        echo -e "${RED}服务重启失败，配置已回滚，请查看日志${PLAIN}"
        service_logs
        return
    fi
    [ "$_old_port" != "$LISTEN_PORT" ] && close_ports "$_old_port"
    rm -f "${VLESS_CONFIG}.bak" "$VLESS_META/config.env.bak" \
        "$VLESS_META/public_ip.bak" "$VLESS_META/public_ipv6.bak"
    show_config
}

# ============================================================
# 展示单个节点（IPv4 或 IPv6）
# $1=IP  $2=Port  $3=标签(v4/v6)
# ============================================================
export_uri_vless() {
    render_uri "$1" "$2" "$UUID" "$3" "$SERVER_NAME" "$REALITY_PUBLIC_KEY" "$SHORT_ID"
}

export_mihomo_vless() {
    local _server="$1" _port="$2" _node="$3" _yaml_server _safe_node _sni
    _yaml_server=$(format_server_for_yaml "$_server")
    _safe_node=$(yaml_single_quote_escape "$_node")
    _sni=$(yaml_single_quote_escape "$SERVER_NAME")
    printf '%s' "- {name: '${_safe_node}', type: vless, server: ${_yaml_server}, port: ${_port}, uuid: ${UUID}, network: tcp, udp: true, tls: true, servername: '${_sni}', flow: xtls-rprx-vision, client-fingerprint: chrome, reality-opts: {public-key: ${REALITY_PUBLIC_KEY}, short-id: ${SHORT_ID}}}"
}

export_loon_vless() {
    local _server="$1" _port="$2" _node="$3"
    printf '%s = VLESS, %s, %s, "%s", transport=tcp, flow=xtls-rprx-vision, public-key="%s", short-id=%s, udp=true, over-tls=true, sni=%s, skip-cert-verify=true' \
        "$_node" "$_server" "$_port" "$UUID" "$REALITY_PUBLIC_KEY" "$SHORT_ID" "$SERVER_NAME"
}

export_surfboard_vless() {
    printf 'Surfboard 暂无经官方文档确认的 VLESS + REALITY 配置格式，请使用 URI 或 Mihomo 配置。'
}

export_shadowrocket_vless() {
    render_uri "$1" "$2" "$UUID" "$3" "$SERVER_NAME" "$REALITY_PUBLIC_KEY" "$SHORT_ID"
}

export_quantumultx_vless() {
    local _server="$1" _port="$2" _node="$3" _host
    _host=$(format_ipv6_for_uri "$_server")
    printf 'vless=%s:%s, method=none, password=%s, obfs=over-tls, obfs-host=%s, reality-base64-pubkey=%s, reality-hex-shortid=%s, vless-flow=xtls-rprx-vision, udp-relay=true, tag=%s' \
        "$_host" "$_port" "$UUID" "$SERVER_NAME" "$REALITY_PUBLIC_KEY" "$SHORT_ID" "$_node"
}

print_reality_status() {
    echo -e "${GREEN}REALITY 参数:${PLAIN}"
    echo "公钥 Public Key: ${REALITY_PUBLIC_KEY}"
    echo "Short ID: ${SHORT_ID}"
    echo "目标 SNI: ${SERVER_NAME}"
    echo "目标端口: ${HANDSHAKE_PORT}"
    echo "Flow: xtls-rprx-vision"
    echo -e "${DIM}服务器私钥已隐藏，仅保存在 root 可读配置中。${PLAIN}"
}

should_show_output() {
    local _mode="${1:-all}" _section="$2"
    [ "$_mode" = "all" ] || [ "$_mode" = "$_section" ]
}

show_node() {
    local _server="$1" _port="$2" _tag="$3" _mode="${4:-all}"
    [ -z "$_server" ] && return
    validate_server_address "$_server" || {
        echo -e "${RED}节点地址格式无效: ${_server}${PLAIN}"
        return 1
    }

    local _ip_type _country _server_name _node _uri _qr_url _png
    case "$_tag" in
        v6|IPv6|ipv6) _ip_type="IPv6" ;;
        *)            _ip_type="IPv4" ;;
    esac
    _country=$(get_country_code "$PUBLIC_IP" "$PUBLIC_IPV6")
    _server_name=$(generate_server_name)
    _node=$(generate_node_name "$_country" "$_server_name" "VLESS-Reality" "$_ip_type")

    _uri=$(export_uri_vless "$_server" "$_port" "$_node")
    _qr_url=$(generate_online_qrcode_url "$_uri")

    echo -e "${YELLOW}节点名称:${PLAIN}"
    print_copy_block "$_node"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    if should_show_output "$_mode" "uri"; then
        echo -e "${GREEN}URI 分享链接:${PLAIN}"
        print_copy_block "$_uri"
        echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    fi

    if should_show_output "$_mode" "mihomo"; then
        echo -e "${GREEN}Mihomo / Clash Meta / Clash Verge 单行配置:${PLAIN}"
        print_copy_block "$(export_mihomo_vless "$_server" "$_port" "$_node")"
        echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    fi

    if should_show_output "$_mode" "surfboard"; then
        echo -e "${GREEN}Surfboard 配置:${PLAIN}"
        print_copy_block "$(export_surfboard_vless)"
        echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    fi

    if should_show_output "$_mode" "shadowrocket"; then
        echo -e "${GREEN}Shadowrocket 配置:${PLAIN}"
        print_copy_block "$(export_shadowrocket_vless "$_server" "$_port" "$_node")"
        echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    fi

    if should_show_output "$_mode" "loon"; then
        echo -e "${GREEN}Loon 配置:${PLAIN}"
        print_copy_block "$(export_loon_vless "$_server" "$_port" "$_node")"
        echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    fi

    if should_show_output "$_mode" "quantumult"; then
        echo -e "${GREEN}Quantumult X 配置:${PLAIN}"
        print_copy_block "$(export_quantumultx_vless "$_server" "$_port" "$_node")"
        echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    fi

    if [ "$_mode" = "all" ]; then
        print_reality_status
        echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    fi

    if should_show_output "$_mode" "qrcode"; then
        echo -e "${GREEN}二维码:${PLAIN}"
        if generate_terminal_qrcode "$_uri"; then
            echo -e "${GREEN}[OK] 终端二维码已生成${PLAIN}"
            _png=$(generate_local_qrcode_png "$_uri" "vless-reality" "$_ip_type" 2>/dev/null || true)
            [ -n "$_png" ] && echo -e "本地二维码图片: ${YELLOW}${_png}${PLAIN}"
        else
            echo -e "${YELLOW}[WARN] 未安装 qrencode，跳过终端和本地 PNG 二维码。${PLAIN}"
        fi
        echo -e "${YELLOW}[WARN] 在线二维码会把节点链接提交给第三方服务，不建议公开节点使用。${PLAIN}"
        print_copy_block "$_qr_url"
        echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    fi
}

show_config() {
    local _mode="${1:-all}"
    read_config_live || { echo -e "${RED}未找到 VLESS 配置${PLAIN}"; sleep 2; return; }

    local _country _server_name
    _country=$(get_country_code "$PUBLIC_IP" "$PUBLIC_IPV6")
    _server_name=$(generate_server_name)

    echo -e "\n${GREEN}VLESS + REALITY + Vision 配置详情${PLAIN}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    echo -e "服务器名称: ${YELLOW}${_server_name}${PLAIN}"
    echo -e "国家/地区: ${YELLOW}${_country} / $(get_country_name "$_country")${PLAIN}"
    [ -n "$PUBLIC_IP"   ] && echo -e "IPv4 地址 : ${YELLOW}${PUBLIC_IP}${PLAIN}"
    [ -n "$PUBLIC_IPV6" ] && echo -e "IPv6 地址 : ${YELLOW}${PUBLIC_IPV6}${PLAIN}"
    if [ "$NAT_MODE" = "1" ] && [ "$EXT_PORT" != "$LISTEN_PORT" ]; then
        echo -e "监听端口 : ${YELLOW}${LISTEN_PORT}${PLAIN}  ${RED}← 本机监听${PLAIN}"
        echo -e "对外端口 : ${YELLOW}${EXT_PORT}${PLAIN}  ${RED}← 客户端连接此端口${PLAIN}"
    else
        echo -e "端口 Port : ${YELLOW}${EXT_PORT}${PLAIN}"
    fi
    echo -e "用户 UUID : ${YELLOW}${UUID}${PLAIN}"
    echo -e "伪装 SNI : ${YELLOW}${SERVER_NAME}:${HANDSHAKE_PORT}${PLAIN}"
    echo -e "REALITY 公钥: ${YELLOW}${REALITY_PUBLIC_KEY}${PLAIN}"
    echo -e "Short ID  : ${YELLOW}${SHORT_ID}${PLAIN}"
    echo -e "Flow      : ${YELLOW}xtls-rprx-vision${PLAIN}"
    echo -e "TLS 指纹 : ${YELLOW}chrome${PLAIN}"
    [ "$NAT_MODE" = "1" ] && echo -e "机器类型 : ${YELLOW}NAT 机器${PLAIN}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    if [ "$_mode" = "all" ]; then
        print_reality_status
        echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    fi

    if [ -n "$PUBLIC_IP" ]; then
        echo -e "${YELLOW}▼ IPv4 节点配置${PLAIN}"
        show_node "$PUBLIC_IP" "$EXT_PORT" "v4" "$_mode"
    fi
    if [ -n "$PUBLIC_IPV6" ]; then
        echo -e "${YELLOW}▼ IPv6 节点配置${PLAIN}"
        show_node "$PUBLIC_IPV6" "$EXT_PORT" "v6" "$_mode"
    fi

    if [ -z "$PUBLIC_IP" ] && [ -z "$PUBLIC_IPV6" ]; then
        read -r -p "未检测到公网 IP，请手动输入节点地址: " _manual_addr
        if [ -n "$_manual_addr" ]; then
            echo -e "${YELLOW}▼ 手动地址节点配置${PLAIN}"
            show_node "$_manual_addr" "$EXT_PORT" "manual" "$_mode"
        fi
    fi

    read -r -p "按回车键返回主菜单..." _tmp
}

# ============================================================
# 升级 / 卸载 / 工具
# ============================================================
acquire_upgrade_lock() {
    local _lock_dir="${UPGRADE_LOCK_FILE}.d" _owner=""
    mkdir -p "$(dirname "$UPGRADE_LOCK_FILE")" 2>/dev/null || return 1
    if command -v flock >/dev/null 2>&1; then
        exec 8>"$UPGRADE_LOCK_FILE" || return 1
        flock -n 8 || { exec 8>&-; return 1; }
        UPGRADE_LOCK_MODE="flock"
        return 0
    fi
    if ! mkdir "$_lock_dir" 2>/dev/null; then
        _owner=$(cat "$_lock_dir/pid" 2>/dev/null || true)
        if [ -n "$_owner" ] && ! kill -0 "$_owner" 2>/dev/null; then
            rm -rf "$_lock_dir"
            mkdir "$_lock_dir" 2>/dev/null || return 1
        else
            return 1
        fi
    fi
    printf '%s' "$$" > "$_lock_dir/pid"
    UPGRADE_LOCK_MODE="mkdir"
}

release_upgrade_lock() {
    if [ "$UPGRADE_LOCK_MODE" = "flock" ]; then
        flock -u 8 2>/dev/null || true
        exec 8>&-
    elif [ "$UPGRADE_LOCK_MODE" = "mkdir" ]; then
        rm -rf "${UPGRADE_LOCK_FILE}.d"
    fi
    UPGRADE_LOCK_MODE=""
}

upgrade_core() {
    acquire_upgrade_lock || { echo -e "${YELLOW}另一个 VLESS 升级任务正在运行，请稍后重试${PLAIN}"; return 1; }
    local _status=0
    _upgrade_core_locked || _status=$?
    release_upgrade_lock
    return "$_status"
}

_upgrade_core_locked() {
    [ -f "$VLESS_CONFIG" ] && [ -x "$SING_BOX_BIN" ] || {
        echo -e "${RED}VLESS 尚未安装，请先执行安装${PLAIN}"
        return 1
    }
    read_config || { echo -e "${RED}VLESS 元数据不完整，无法安全升级${PLAIN}"; return 1; }
    get_latest_version || return 1

    local _current_version _latest_version _was_active=0 _shared_was_active=0
    local _restart_failed=0 _was_managed="$MANAGED_SING_BOX"
    _current_version=$(get_installed_version)
    _latest_version="${LAST_VERSION_TAG#v}"
    if [ -n "$_current_version" ] && [ "$_current_version" = "$_latest_version" ]; then
        echo -e "${GREEN}sing-box 已是最新版本 ${_current_version}${PLAIN}"
        return 0
    fi

    cp -p "$SING_BOX_BIN" "${SING_BOX_BIN}.bak" || {
        echo -e "${RED}无法备份现有 sing-box，已取消升级${PLAIN}"
        return 1
    }
    service_is_active && _was_active=1 || true
    shared_anytls_service_is_active && _shared_was_active=1 || true
    if ! download_vless; then
        mv -f "${SING_BOX_BIN}.bak" "$SING_BOX_BIN" 2>/dev/null || true
        MANAGED_SING_BOX="$_was_managed"
        return 1
    fi
    MANAGED_SING_BOX="$_was_managed"
    if ! check_config; then
        mv -f "${SING_BOX_BIN}.bak" "$SING_BOX_BIN" 2>/dev/null || true
        echo -e "${RED}新版本不兼容当前配置，已回滚${PLAIN}"
        return 1
    fi
    if [ "$_was_active" = "1" ]; then
        service_restart || _restart_failed=1
    fi
    if [ "$_shared_was_active" = "1" ]; then
        shared_anytls_service_restart || _restart_failed=1
    fi
    if [ "$_was_active" = "1" ] || [ "$_shared_was_active" = "1" ]; then
        sleep 2
    fi
    [ "$_was_active" = "0" ] || service_is_healthy || _restart_failed=1
    [ "$_shared_was_active" = "0" ] || shared_anytls_service_is_active || _restart_failed=1
    if [ "$_restart_failed" = "1" ]; then
        mv -f "${SING_BOX_BIN}.bak" "$SING_BOX_BIN" 2>/dev/null || true
        [ "$_was_active" = "0" ] || service_restart || true
        [ "$_shared_was_active" = "0" ] || shared_anytls_service_restart || true
        echo -e "${RED}升级后共享服务启动失败，已回滚${PLAIN}"
        return 1
    fi
    rm -f "${SING_BOX_BIN}.bak"
    echo -e "${GREEN}✓ sing-box 已从 ${_current_version:-未知版本} 升级到 ${_latest_version}${PLAIN}"
    return 0
}

upgrade_vless() {
    if ! install_dependencies; then
        read -r -p "按回车键返回主菜单..." _
        return 1
    fi
    local _status=0
    upgrade_core || _status=$?
    sleep 2
    return "$_status"
}

uninstall_vless() {
    echo -e "${RED}警告：这将删除 VLESS 服务、配置和定时更新。${PLAIN}"
    read -r -p "确认卸载 VLESS？[y/N]: " _confirm
    case "$_confirm" in
        [yY]) ;;
        *) echo "已取消。"; sleep 1; return ;;
    esac

    read_config 2>/dev/null || true
    local _managed_core=0 _other_file=""
    if [ "$MANAGED_SING_BOX" = "1" ] || [ -f "$SING_BOX_MANAGED_MARKER" ]; then
        _managed_core=1
    fi
    if [ "$MANAGED_SING_BOX" = "1" ]; then
        mkdir -p "$VLESS_DIR" 2>/dev/null || true
        : > "$SING_BOX_MANAGED_MARKER" 2>/dev/null || true
    fi
    service_stop
    service_disable
    close_ports "${LISTEN_PORT:-}"
    if command -v crontab >/dev/null 2>&1; then
        crontab -l 2>/dev/null | grep -vF "$AUTO_UPDATE_SCRIPT" | crontab - 2>/dev/null || true
    fi
    rm -f "$SYSTEMD_SERVICE" "$OPENRC_SERVICE" "$AUTO_UPDATE_SCRIPT" "$VLESS_BIN"
    rm -f "$VLESS_CONFIG" "$AUTO_UPDATE_LOG"
    rm -rf "$VLESS_META"
    if [ -d "$VLESS_DIR" ]; then
        _other_file=$(find "$VLESS_DIR" -mindepth 1 -maxdepth 1 ! -name '.singbox-tools-managed' -print -quit 2>/dev/null)
    fi
    if [ -z "$_other_file" ]; then
        rm -f "$SING_BOX_MANAGED_MARKER"
        rmdir "$VLESS_DIR" 2>/dev/null || true
        [ "$_managed_core" = "1" ] && rm -f "$SING_BOX_BIN"
    elif [ "$_managed_core" = "1" ]; then
        echo -e "${YELLOW}检测到 /etc/sing-box 中还有其他文件，已保留共享 sing-box 二进制${PLAIN}"
    fi
    rm -f /var/run/vless-server.pid
    [ "$INIT_SYS" = "systemd" ] && systemctl daemon-reload
    echo -e "${GREEN}✓ VLESS 已卸载${PLAIN}"
    sleep 2
}

setup_auto_update() {
    cat > "$AUTO_UPDATE_SCRIPT" <<'AUTOUPDATE_EOF'
#!/bin/bash
LOG_FILE=/var/log/vless-autoupdate.log
TMP_SCRIPT=$(mktemp /tmp/vless-update-XXXXXX.sh) || exit 1
trap 'rm -f "$TMP_SCRIPT"' EXIT INT TERM
{
  echo "[$(date '+%F %T')] 开始检查 sing-box 更新"
  curl -fsSL --connect-timeout 15 --max-time 60 \
    https://raw.githubusercontent.com/everett7623/hy2/main/vless.sh -o "$TMP_SCRIPT" || exit 1
  bash -n "$TMP_SCRIPT" || exit 1
  bash "$TMP_SCRIPT" --upgrade-noninteractive
  echo "[$(date '+%F %T')] 更新检查完成"
} >> "$LOG_FILE" 2>&1
AUTOUPDATE_EOF
    chmod +x "$AUTO_UPDATE_SCRIPT"

    if command -v crontab >/dev/null 2>&1; then
        (crontab -l 2>/dev/null | grep -v "$AUTO_UPDATE_SCRIPT"; echo "27 4 * * 1 $AUTO_UPDATE_SCRIPT") | crontab -
        echo -e "${GREEN}✓ 已设置每周一 04:27 自动检查 sing-box 更新${PLAIN}"
    else
        echo -e "${YELLOW}系统未安装 crontab，请手动安装 cron 后再设置自动升级${PLAIN}"
    fi
    sleep 2
}

remove_auto_update() {
    if command -v crontab >/dev/null 2>&1; then
        crontab -l 2>/dev/null | grep -vF "$AUTO_UPDATE_SCRIPT" | crontab - 2>/dev/null || true
    fi
    rm -f "$AUTO_UPDATE_SCRIPT"
    echo -e "${GREEN}✓ 已移除 VLESS 自动更新任务${PLAIN}"
    sleep 2
}

diagnose_vless() {
    local _speed _cc
    echo -e "\n${GREEN}VLESS 运行诊断${PLAIN}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    if ! read_config; then
        echo -e "  ${RED}✗ 配置或元数据缺失${PLAIN}"
        echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
        return 1
    fi
    if check_config >/dev/null 2>&1; then
        echo -e "  ${GREEN}✓ sing-box 配置有效${PLAIN}"
    else
        echo -e "  ${RED}✗ sing-box 配置无效${PLAIN}"
        check_config 2>&1 | sed 's/^/    /'
    fi
    if validate_uuid "$UUID" && validate_reality_key "$REALITY_PRIVATE_KEY" && \
        validate_reality_key "$REALITY_PUBLIC_KEY" && validate_short_id "$SHORT_ID"; then
        echo -e "  ${GREEN}✓ UUID 与 REALITY 密钥元数据有效${PLAIN}"
    else
        echo -e "  ${RED}✗ UUID 或 REALITY 密钥元数据无效${PLAIN}"
    fi
    if service_is_active; then
        echo -e "  ${GREEN}✓ VLESS 服务运行中${PLAIN}"
    else
        echo -e "  ${RED}✗ VLESS 服务未运行${PLAIN}"
    fi
    if command -v ss >/dev/null 2>&1 && ss -lnt 2>/dev/null | awk '{print $4}' | grep -qE "(^|:|\])${LISTEN_PORT}$"; then
        echo -e "  ${GREEN}✓ TCP ${LISTEN_PORT} 正在监听${PLAIN}"
    else
        echo -e "  ${YELLOW}! 未检测到 TCP ${LISTEN_PORT} 监听${PLAIN}"
    fi
    if reality_target_usable "$SERVER_NAME" "$HANDSHAKE_PORT"; then
        echo -e "  ${GREEN}✓ REALITY 目标 ${SERVER_NAME}:${HANDSHAKE_PORT} HTTPS/TLS 可达${PLAIN}"
    else
        echo -e "  ${RED}✗ REALITY 目标 ${SERVER_NAME}:${HANDSHAKE_PORT} 不可达或 TLS 握手失败${PLAIN}"
    fi
    if _speed=$(probe_vps_download_mbps); then
        echo -e "  ${GREEN}✓ VPS 直连下载探测: ${_speed} Mbps${PLAIN}"
    else
        echo -e "  ${YELLOW}! VPS 直连下载探测失败，可能是出口网络或测速站限制${PLAIN}"
    fi
    _cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)
    [ -n "$_cc" ] && echo -e "  ${DIM}TCP 拥塞控制: ${_cc}${PLAIN}"
    echo -e "  ${DIM}说明: 直连探测正常但客户端慢时，应继续检查客户端分流、MTU、运营商路由和测速站限制。${PLAIN}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
}

show_system_info() {
    echo -e "\n${GREEN}系统信息${PLAIN}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    echo -e " 主机名: $(hostname 2>/dev/null)"
    echo -e " 内核  : $(uname -r)"
    echo -e " 架构  : $(uname -m)"
    [ -x "$SING_BOX_BIN" ] && echo -e " 核心  : $("$SING_BOX_BIN" version 2>/dev/null | head -1)"
    echo -e " 内存  : $(awk '/MemAvailable/ {printf "%.0f MB available", $2/1024}' /proc/meminfo 2>/dev/null)"
    echo -e " 磁盘  : $(df -h / 2>/dev/null | awk 'NR==2 {print $3" / "$2" ("$5" used)"}')"
    echo -e " 负载  : $(uptime 2>/dev/null | awk -F'load average:' '{print $2}' | xargs)"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    read -r -p "按回车返回..." _tmp
}

server_tools_menu() {
    while true; do
        clear_screen
        local _auto_status="${RED}未启用${PLAIN}"
        if command -v crontab >/dev/null 2>&1 && crontab -l 2>/dev/null | grep -qF "$AUTO_UPDATE_SCRIPT"; then
            _auto_status="${GREEN}已启用${PLAIN}"
        fi
        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e "${GREEN}  VLESS 工具箱${PLAIN}"
        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e " 自动更新: ${_auto_status}"
        echo -e "${SKYBLUE}───────────────────────────────────────────────${PLAIN}"
        echo -e " 1. 查看系统信息"
        echo -e " 2. 查看 VLESS 日志"
        echo -e " 3. 运行状态诊断"
        echo -e " 4. 设置每周自动更新"
        echo -e " 5. 移除自动更新"
        echo -e " 0. 返回"
        read -r -p "请输入选项 [0-5]: " choice
        case "$choice" in
            1) show_system_info ;;
            2) service_logs; read -r -p "按回车返回..." _tmp ;;
            3) diagnose_vless; read -r -p "按回车返回..." _tmp ;;
            4) setup_auto_update ;;
            5) remove_auto_update ;;
            0|q|quit|exit) return ;;
            *) echo -e "${RED}无效选项${PLAIN}"; sleep 1 ;;
        esac
    done
}

manage_vless() {
    if [ ! -f "$VLESS_CONFIG" ] || [ ! -x "$VLESS_BIN" ]; then
        echo -e "${RED}VLESS 尚未安装，请先执行安装${PLAIN}"
        sleep 2
        return
    fi
    while true; do
        clear_screen
        local STATUS
        service_is_active && STATUS="${GREEN}运行中${PLAIN}" || STATUS="${RED}已停止${PLAIN}"

        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e "${GREEN}  VLESS 服务管理${PLAIN}"
        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e " 当前状态: ${STATUS}"
        echo -e " 1. 启动"
        echo -e " 2. 停止"
        echo -e " 3. 重启"
        echo -e " 4. 查看日志"
        echo -e " 5. 修改配置"
        echo -e " 6. 运行状态与速度诊断"
        echo -e " 0. 返回"
        read -r -p "请输入选项 [0-6]: " choice
        case "$choice" in
            1)
                if service_start && sleep 1 && service_is_active; then
                    echo -e "${GREEN}✓ VLESS 已启动${PLAIN}"
                else
                    echo -e "${RED}✗ 启动失败，请查看日志${PLAIN}"
                fi
                sleep 1
                ;;
            2)
                service_stop
                sleep 1
                service_is_active && echo -e "${RED}✗ 服务仍在运行${PLAIN}" || echo -e "${GREEN}✓ VLESS 已停止${PLAIN}"
                sleep 1
                ;;
            3)
                if service_restart && sleep 1 && service_is_active; then
                    echo -e "${GREEN}✓ VLESS 已重启${PLAIN}"
                else
                    echo -e "${RED}✗ 重启失败，请查看日志${PLAIN}"
                fi
                sleep 1
                ;;
            4) service_logs; read -r -p "按回车返回..." _tmp ;;
            5) change_config ;;
            6) diagnose_vless; read -r -p "按回车返回..." _tmp ;;
            0|q|quit|exit) return ;;
            *) echo -e "${RED}无效选项${PLAIN}"; sleep 1 ;;
        esac
    done
}

# ============================================================
# 主菜单
# ============================================================
main_menu() {
    while true; do
        clear_screen
        local STATUS _ver_line
        if [ -f "$VLESS_CONFIG" ] && [ -x "$VLESS_BIN" ] && [ -x "$SING_BOX_BIN" ]; then
            service_is_active && STATUS="${GREEN}运行中${PLAIN}" || STATUS="${RED}已停止${PLAIN}"
        elif [ -e "$VLESS_CONFIG" ] || [ -e "$VLESS_BIN" ]; then
            STATUS="${YELLOW}安装不完整${PLAIN}"
        else
            STATUS="${RED}未安装${PLAIN}"
        fi
        _ver_line=""
        if [ -x "$SING_BOX_BIN" ]; then
            _ver_line=" ($(get_installed_version))"
        fi

        echo -e "${SKYBLUE}${BOLD}================================================${PLAIN}"
        echo -e "  ${GREEN}${BOLD}VLESS Management Script${PLAIN} ${DIM}v2.0.19${PLAIN}"
        echo -e "  ${DIM}sing-box native VLESS inbound${PLAIN}"
        echo -e "${SKYBLUE}${BOLD}================================================${PLAIN}"
        echo -e "  项目地址: ${YELLOW}https://github.com/everett7623/hy2${PLAIN}"
        echo -e "  作者    : ${YELLOW}everettlabs${PLAIN}"
        echo -e "  实现    : ${YELLOW}sing-box 原生 VLESS 入站${PLAIN}"
        echo -e "${SKYBLUE}------------------------------------------------${PLAIN}"
        echo -e "  Seedloc博客 : https://seedloc.com"
        echo -e "  VPSknow网站 : https://vpsknow.com"
        echo -e "  Nodeloc论坛 : https://nodeloc.com"
        echo -e "${SKYBLUE}------------------------------------------------${PLAIN}"
        echo -e "  当前状态: $STATUS${_ver_line}"
        echo -e "${SKYBLUE}------------------------------------------------${PLAIN}"
        echo -e " 1. 安装 / 重装 VLESS"
        echo -e " 2. 查看节点信息 / 链接"
        echo -e " 3. 管理 VLESS（启动 / 停止 / 重启 / 日志 / 修改）"
        echo -e " 4. 升级 sing-box"
        echo -e " 5. 卸载 VLESS"
        echo -e " 6. 服务器工具"
        echo -e " 0. 退出"
        echo -e "${SKYBLUE}================================================${PLAIN}"

        read -r -p "请输入选项 [0-6]: " choice
        case "$choice" in
            1) install_vless ;;
            2) show_config ;;
            3) manage_vless ;;
            4) upgrade_vless ;;
            5) uninstall_vless ;;
            6) server_tools_menu ;;
            0|q|quit|exit) exit 0 ;;
            *) echo -e "${RED}无效选项，请输入 0-6${PLAIN}"; sleep 1 ;;
        esac
    done
}

# 非交互升级，供 cron 使用
if [ "${1:-}" = "--upgrade-noninteractive" ]; then
    check_root
    check_sys
    detect_init
    install_dependencies || exit 1
    upgrade_core
    exit $?
fi

# ============================================================
# 入口（VLESS_LIB_ONLY=1 时跳过）
# ============================================================
[ "$_VLESS_LIB_ONLY" = "1" ] && return 0

check_root
check_sys
detect_init
case "${1:-menu}" in
    install) install_vless ;;
    info|node|export|all) show_config ;;
    uri|link) show_config uri ;;
    mihomo|clash) show_config mihomo ;;
    surfboard) show_config surfboard ;;
    shadowrocket) show_config shadowrocket ;;
    loon) show_config loon ;;
    quantumult|quantumultx) show_config quantumult ;;
    qrcode|qr) show_config qrcode ;;
    manage|service|config) manage_vless ;;
    diagnose|check|health) diagnose_vless ;;
    upgrade|update) upgrade_vless ;;
    uninstall|remove) uninstall_vless ;;
    menu|"") main_menu ;;
    *)
        echo -e "${RED}未知命令: ${1}${PLAIN}"
        echo "可用命令: install | info | manage | diagnose | upgrade | uninstall"
        exit 1
        ;;
esac
