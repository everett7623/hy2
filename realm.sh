#!/bin/bash
#====================================================================================
# 项目：Realm TCP Relay Management Script
# 作者：everettlabs
# 版本：v2.3.0
# GitHub: https://github.com/everett7623/hy2
# Seedloc博客: https://seedloc.com
# VPSknow网站：https://vpsknow.com
# Nodeloc论坛: https://nodeloc.com
# 更新日期: 2026-11-12
#
# 支持系统: Debian / Ubuntu / CentOS / Rocky / Alma / Fedora / Arch / Alpine
# 支持环境: 标准 VPS / NAT 机器 / IPv6 单栈 / 双栈机器
# 实现方式: 线路机运行 realm 纯 TCP 端口转发，落地机运行 sing-box AnyTLS / VLESS 节点
#
# 架构：
#   客户端 → 线路机（realm TCP 转发）→ 落地机（AnyTLS / VLESS 节点）→ 互联网
#   线路机只跑 realm，不跑 sing-box；节点凭据来自落地机，分享链接用线路机公网 IP + 转发端口。
#====================================================================================

# ============================================================
# 自举：确保以 bash 运行（Alpine 默认 sh）
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

# 远程动作与非交互升级必须保持 headless，不接管 /dev/tty
case "${1:-}" in
    --remote-exit-install|--remote-exit-uninstall|--remote-exit-status|--upgrade-noninteractive)
        _REALM_HEADLESS=1
        ;;
    *)
        _REALM_HEADLESS=0
        ;;
esac

[ "${REALM_LIB_ONLY:-0}" != "1" ] && [ "$_REALM_HEADLESS" = "0" ] && [ ! -t 0 ] && [ -c /dev/tty ] && exec < /dev/tty

# CRLF guard：任何引入 CRLF 的编辑会在 Linux 运行时自动修正并重新执行
if [ -f "$SCRIPT_PATH" ] && grep -q $'\r' "$SCRIPT_PATH" 2>/dev/null; then
    sed -i 's/\r$//' "$SCRIPT_PATH"
    exec bash "$SCRIPT_PATH" "$@"
fi

# ============================================================
# REALM_LIB_ONLY=1：仅加载函数库，不执行任何副作用（供测试 source）
# ============================================================
[ "${REALM_LIB_ONLY:-0}" = "1" ] && _REALM_LIB_ONLY=1 || _REALM_LIB_ONLY=0

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

# ============================================================
# 路径常量（测试可在 source 后覆盖）
# ============================================================
# 线路机 realm
REALM_BIN="${REALM_BIN:-/usr/local/bin/realm}"
REALM_DIR="${REALM_DIR:-/etc/realm}"
REALM_CONFIG="${REALM_CONFIG:-${REALM_DIR}/config.toml}"
REALM_META="${REALM_META:-${REALM_DIR}/meta}"
REALM_SYSTEMD="${REALM_SYSTEMD:-/etc/systemd/system/realm.service}"
REALM_OPENRC="${REALM_OPENRC:-/etc/init.d/realm}"

# 落地机节点（独立于 landing.sh / anytls.sh 的路径，避免冲突）
SING_BOX_BIN="${SING_BOX_BIN:-/usr/local/bin/sing-box}"
SING_BOX_DIR="${SING_BOX_DIR:-/etc/sing-box}"
SING_BOX_MANAGED_MARKER="${SING_BOX_MANAGED_MARKER:-${SING_BOX_DIR}/.singbox-tools-managed}"
NODE_CONFIG="${NODE_CONFIG:-${SING_BOX_DIR}/realm-node.json}"
NODE_BIN="${NODE_BIN:-/usr/local/bin/realm-node}"
NODE_META="${NODE_META:-${SING_BOX_DIR}/realm-node-meta}"
NODE_CERT_DIR="${NODE_CERT_DIR:-${SING_BOX_DIR}/realm-node-cert}"
NODE_CERT="${NODE_CERT:-${NODE_CERT_DIR}/cert.pem}"
NODE_KEY="${NODE_KEY:-${NODE_CERT_DIR}/private.key}"
NODE_SYSTEMD="${NODE_SYSTEMD:-/etc/systemd/system/realm-node.service}"
NODE_OPENRC="${NODE_OPENRC:-/etc/init.d/realm-node}"

# realm 下载：优先 musl（Alpine 兼容、glibc 可移植）
REALM_REPO="${REALM_REPO:-zhboner/realm}"
REALM_FALLBACK_TAG="${REALM_FALLBACK_TAG:-v2.9.6}"
REALM_VERSION_TAG=""

# sing-box 下载
SING_BOX_STABLE_FALLBACK_TAG="${SING_BOX_STABLE_FALLBACK_TAG:-v1.13.14}"
SINGBOX_MIN_VERSION="${SINGBOX_MIN_VERSION:-1.12.10}"
LAST_VERSION_TAG=""

# 公网 IP 探测站（混合 ASN + 免 DNS 字面量端点）
IPV4_PROBE_URLS="${IPV4_PROBE_URLS:-https://api.ipify.org https://1.1.1.1/cdn-cgi/trace https://checkip.amazonaws.com https://ipv4.icanhazip.com}"
IPV6_PROBE_URLS="${IPV6_PROBE_URLS:-https://api6.ipify.org https://[2606:4700:4700::1111]/cdn-cgi/trace https://ipv6.icanhazip.com}"

# ============================================================
# 运行时变量
# ============================================================
RELEASE="unknown"
INIT_SYS="none"
ROLE=""
NODE_PROTO="anytls"
RELAY_LISTEN_PORT=""
NODE_PORT=""
LANDING_HOST=""
SSH_PORT="22"
SSH_USER="root"
LISTEN_HOST="0.0.0.0"
SERVER_NAME="www.apple.com"
HANDSHAKE_PORT="443"
ANYTLS_PASSWORD=""
UUID=""
REALITY_PRIVATE_KEY=""
REALITY_PUBLIC_KEY=""
SHORT_ID=""
NODE_NAME=""
RELAY_PUBLIC_IP=""
RELAY_PUBLIC_IPV6=""
EXIT_IPV4=""
EXIT_HAS_IPV6=0
MANAGED_SING_BOX=0

SSH_CTL_DIR=""
SSH_OPTS=()
REMOTE_STAGE_DIR=""
REMOTE_RESULT=""
REALM_SCRIPT_URL="${REALM_SCRIPT_URL:-https://raw.githubusercontent.com/everett7623/hy2/main/realm.sh}"
REALM_SCRIPT_SOURCE=""
REALM_SCRIPT_TMP=""

# ============================================================
# 基础检测
# ============================================================
check_root() {
    [ "$(id -u 2>/dev/null)" != "0" ] && echo -e "${RED}错误: 请以 root 权限运行${PLAIN}" && exit 1
    return 0
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
    for _cmd in curl tar openssl; do
        command -v "$_cmd" >/dev/null 2>&1 || _ready=0
    done
    if [ "$_ready" = "1" ]; then
        return 0
    fi
    echo -e "${YELLOW}正在补齐必要依赖...${PLAIN}"
    case "$RELEASE" in
        alpine)
            retry_command apk update -q >/dev/null 2>&1
            retry_command apk add --no-cache bash curl wget ca-certificates tar openssl iproute2 >/dev/null 2>&1
            apk add --no-cache libqrencode >/dev/null 2>&1 || true
            ;;
        centos)
            retry_command yum install -y curl wget ca-certificates tar openssl iproute >/dev/null 2>&1
            yum install -y qrencode >/dev/null 2>&1 || true
            ;;
        fedora|rocky)
            retry_command dnf install -y curl wget ca-certificates tar openssl iproute >/dev/null 2>&1
            dnf install -y qrencode >/dev/null 2>&1 || true
            ;;
        arch)
            retry_command pacman -Sy --noconfirm curl wget ca-certificates tar openssl iproute2 >/dev/null 2>&1
            pacman -S --noconfirm qrencode >/dev/null 2>&1 || true
            ;;
        *)
            if command -v apt-get >/dev/null 2>&1; then
                retry_command apt-get update -qq >/dev/null 2>&1
                retry_command apt-get install -y -qq curl wget ca-certificates tar openssl iproute2 >/dev/null 2>&1
                apt-get install -y qrencode >/dev/null 2>&1 || true
            else
                echo -e "${RED}无法识别包管理器，请手动安装 curl wget tar openssl${PLAIN}"
                return 1
            fi
            ;;
    esac
    local _missing=0
    for _cmd in curl tar openssl; do
        if ! command -v "$_cmd" >/dev/null 2>&1; then
            echo -e "${RED}致命错误: 缺少组件 [ $_cmd ]，请手动安装后重试${PLAIN}"
            _missing=1
        fi
    done
    [ "$_missing" -eq 1 ] && return 1
    return 0
}

# 一键对接依赖 OpenSSH 的连接复用（ControlMaster）
ensure_ssh_client() {
    if command -v ssh >/dev/null 2>&1 && ssh -V 2>&1 | grep -qi openssh; then
        return 0
    fi
    echo -e "${YELLOW}正在安装 OpenSSH 客户端...${PLAIN}"
    case "$RELEASE" in
        alpine) retry_command apk add --no-cache openssh-client >/dev/null 2>&1 ;;
        centos) retry_command yum install -y openssh-clients >/dev/null 2>&1 ;;
        fedora|rocky) retry_command dnf install -y openssh-clients >/dev/null 2>&1 ;;
        arch) retry_command pacman -Sy --noconfirm openssh >/dev/null 2>&1 ;;
        *)
            if command -v apt-get >/dev/null 2>&1; then
                retry_command apt-get update -qq >/dev/null 2>&1
                retry_command apt-get install -y -qq openssh-client >/dev/null 2>&1
            fi
            ;;
    esac
    if command -v ssh >/dev/null 2>&1 && ssh -V 2>&1 | grep -qi openssh; then
        return 0
    fi
    echo -e "${RED}无法安装 OpenSSH 客户端，请手动安装 openssh-client 后重试${PLAIN}"
    return 1
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

# 只用字母和数字：直接写进 JSON、URI、TOML 与各客户端单行配置，无需任何转义
validate_anytls_password() {
    case "$1" in ""|*[!A-Za-z0-9]*) return 1 ;; esac
    [ "${#1}" -ge 16 ] && [ "${#1}" -le 64 ]
}

validate_ssh_user() {
    printf '%s\n' "$1" | grep -qE '^[a-z_][a-z0-9_.-]{0,31}$'
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
        *:*) ;;
        *) return 1 ;;
    esac
    printf '%s' "$1" | awk '
        {
            s = $0
            if (s !~ /^[0-9A-Fa-f:]+$/) exit 1
            if (s ~ /:::/) exit 1
            if (gsub(/::/, "::") > 1) exit 1
            if (s ~ /^:[^:]/ || s ~ /[^:]:$/) exit 1
            n = split(s, g, ":")
            groups = 0
            for (i = 1; i <= n; i++) {
                if (g[i] == "") continue
                if (length(g[i]) > 4) exit 1
                groups++
            }
            if (groups == 0) exit 1
            if (s ~ /::/) { if (groups > 7) exit 1 }
            else if (groups != 8) exit 1
            exit 0
        }
    '
}

# 落地机地址会同时写入 realm 配置与 ssh 命令行，只接受 IPv4、IPv6 或域名
validate_exit_host() {
    local _host="$1"
    [ -n "$_host" ] || return 1
    case "$_host" in
        -*) return 1 ;;
    esac
    is_valid_ipv4 "$_host" && return 0
    is_valid_ipv6 "$_host" && return 0
    validate_server_name "$_host"
}

# ============================================================
# 端口 / 随机值
# ============================================================
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

tcp_port_is_listening() {
    local _port="$1"
    command -v ss >/dev/null 2>&1 || return 1
    ss -lnt 2>/dev/null | awk -v port="$_port" '
        NR > 1 { for (i=4; i<=NF; i++) if ($i ~ (":" port "$")) found=1 }
        END { exit(found ? 0 : 1) }
    '
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

random_sni() {
    local _number
    _number=$(od -An -N2 -tu2 /dev/urandom 2>/dev/null | tr -d ' ')
    [ -z "$_number" ] && _number=$(date +%s)
    case $((_number % 6)) in
        0) echo "www.apple.com" ;;
        1) echo "www.amazon.com" ;;
        2) echo "www.amd.com" ;;
        3) echo "www.mozilla.org" ;;
        4) echo "www.nvidia.com" ;;
        *) echo "www.samsung.com" ;;
    esac
}

# ============================================================
# 密钥 / 随机值生成
# ============================================================
generate_uuid() {
    local _uuid="" _hex
    if [ -x "$SING_BOX_BIN" ]; then
        _uuid=$("$SING_BOX_BIN" generate uuid 2>/dev/null | grep -E '^[0-9A-Fa-f-]{36}$' | head -1)
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

# REALITY 为 X25519 密钥对，base64url 原始 32 字节（43 字符）。
# 线路机通常没有 sing-box，用 openssl 直接生成；私钥交给落地机，公钥留在线路机写进分享链接。
generate_reality_keypair() {
    local _output _priv _pub _priv_pem
    if [ -x "$SING_BOX_BIN" ]; then
        _output=$("$SING_BOX_BIN" generate reality-keypair 2>/dev/null) || _output=""
        _priv=$(printf '%s\n' "$_output" | awk -F':[[:space:]]*' 'tolower($1) ~ /private/ { print $2; exit }' | tr -d '[:space:]')
        _pub=$(printf '%s\n' "$_output" | awk -F':[[:space:]]*' 'tolower($1) ~ /public/ { print $2; exit }' | tr -d '[:space:]')
        if validate_reality_key "$_priv" && validate_reality_key "$_pub"; then
            REALITY_PRIVATE_KEY="$_priv"
            REALITY_PUBLIC_KEY="$_pub"
            return 0
        fi
    fi
    command -v openssl >/dev/null 2>&1 || return 1
    _priv_pem=$(mktemp "$(disk_tmp_dir)/realm-x25519.XXXXXX" 2>/dev/null) || return 1
    if ! openssl genpkey -algorithm X25519 -out "$_priv_pem" >/dev/null 2>&1; then
        rm -f "$_priv_pem"
        return 1
    fi
    _priv=$(openssl pkey -in "$_priv_pem" -outform DER 2>/dev/null | tail -c 32 | openssl base64 -A 2>/dev/null | tr '+/' '-_' | tr -d '=')
    _pub=$(openssl pkey -in "$_priv_pem" -pubout -outform DER 2>/dev/null | tail -c 32 | openssl base64 -A 2>/dev/null | tr '+/' '-_' | tr -d '=')
    rm -f "$_priv_pem"
    validate_reality_key "$_priv" || return 1
    validate_reality_key "$_pub" || return 1
    REALITY_PRIVATE_KEY="$_priv"
    REALITY_PUBLIC_KEY="$_pub"
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

generate_anytls_password() {
    local _password
    _password=$(openssl rand -base64 32 2>/dev/null | tr -dc 'A-Za-z0-9' | cut -c1-24)
    validate_anytls_password "$_password" || _password=$(od -An -N16 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n')
    validate_anytls_password "$_password" || return 1
    printf '%s' "$_password"
}

# ============================================================
# 自签证书（落地机 AnyTLS 节点）
# ============================================================
node_certificate_ok() {
    local _cert_pub _key_pub
    [ -s "$NODE_CERT" ] && [ -s "$NODE_KEY" ] || return 1
    openssl x509 -in "$NODE_CERT" -noout -checkend 86400 >/dev/null 2>&1 || return 1
    _cert_pub=$(openssl x509 -in "$NODE_CERT" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256 2>/dev/null) || return 1
    _key_pub=$(openssl pkey -in "$NODE_KEY" -pubout -outform DER 2>/dev/null | openssl dgst -sha256 2>/dev/null) || return 1
    [ -n "$_cert_pub" ] && [ "$_cert_pub" = "$_key_pub" ]
}

generate_node_certificate() {
    local _force="${1:-}" _tmp_dir _status=0
    if [ "$_force" != "force" ] && node_certificate_ok; then
        return 0
    fi
    mkdir -p "$NODE_CERT_DIR" && chmod 700 "$NODE_CERT_DIR" || return 1
    _tmp_dir=$(mktemp -d "${NODE_CERT_DIR}/new.XXXXXX" 2>/dev/null) || return 1
    if ! openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
        -subj "/CN=${SERVER_NAME}" -addext "subjectAltName=DNS:${SERVER_NAME}" \
        -keyout "$_tmp_dir/private.key" -out "$_tmp_dir/cert.pem" >/dev/null 2>&1; then
        rm -f "$_tmp_dir/private.key" "$_tmp_dir/cert.pem"
        openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
            -subj "/CN=${SERVER_NAME}" \
            -keyout "$_tmp_dir/private.key" -out "$_tmp_dir/cert.pem" >/dev/null 2>&1 || _status=1
    fi
    if [ "$_status" = "0" ] && [ -s "$_tmp_dir/cert.pem" ] && [ -s "$_tmp_dir/private.key" ]; then
        chmod 600 "$_tmp_dir/private.key" "$_tmp_dir/cert.pem" && \
            mv -f "$_tmp_dir/private.key" "$NODE_KEY" && \
            mv -f "$_tmp_dir/cert.pem" "$NODE_CERT" || _status=1
    else
        _status=1
    fi
    rm -rf "$_tmp_dir"
    return "$_status"
}

node_certificate_sha256() {
    local _fp
    [ -s "$NODE_CERT" ] || return 1
    _fp=$(openssl x509 -in "$NODE_CERT" -noout -fingerprint -sha256 2>/dev/null \
        | awk -F= 'NF == 2 { gsub(/:/, "", $2); print tolower($2) }')
    case "$_fp" in ""|*[!0-9a-f]*) return 1 ;; esac
    [ "${#_fp}" = 64 ] || return 1
    printf '%s' "$_fp"
}

# ============================================================
# 架构 / 版本
# ============================================================
detect_arch() {
    local _machine="${1:-$(uname -m)}"
    case "$_machine" in
        x86_64)        echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        *)
            echo -e "${RED}不支持的架构: ${_machine}${PLAIN}" >&2
            return 1
            ;;
    esac
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

# ============================================================
# 下载 / 校验
# ============================================================
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

validate_elf() {
    local _file="$1" _magic
    [ -z "$_file" ] && return 1
    [ -f "$_file" ] || return 1
    [ -s "$_file" ] || return 1
    _magic=$(od -A d -t x1 -N 4 "$_file" 2>/dev/null | awk 'NR==1 { print $2, $3, $4, $5 }')
    [ "$_magic" = "7f 45 4c 46" ] && return 0
    return 1
}

# ------------------------------------------------------------
# realm 二进制
# ------------------------------------------------------------
get_realm_latest_version() {
    local _candidate
    REALM_VERSION_TAG=""
    _candidate=$(curl -fsSL --connect-timeout 8 --max-time 15 \
        "https://api.github.com/repos/${REALM_REPO}/releases/latest" 2>/dev/null \
        | awk -F'"' '/"tag_name":/ { print $4; exit }' 2>/dev/null || true)
    REALM_VERSION_TAG=$(normalize_version_tag "$_candidate" 2>/dev/null || true)
    if [ -z "$REALM_VERSION_TAG" ]; then
        _candidate=$(curl -Ls --connect-timeout 8 --max-time 15 -o /dev/null -w "%{url_effective}" \
            "https://github.com/${REALM_REPO}/releases/latest" 2>/dev/null || true)
        REALM_VERSION_TAG=$(normalize_version_tag "$_candidate" 2>/dev/null || true)
    fi
    if [ -z "$REALM_VERSION_TAG" ]; then
        REALM_VERSION_TAG="$REALM_FALLBACK_TAG"
        echo -e "${YELLOW}[WARN] 无法获取 realm 最新版本，使用内置版本 ${REALM_VERSION_TAG}${PLAIN}"
    fi
    echo -e "${GREEN}realm 版本: ${REALM_VERSION_TAG}${PLAIN}"
}

# 优先 musl（Alpine 兼容、glibc 可移植）；非 Alpine 先 gnu 后 musl 兜底
realm_asset_names() {
    local _arch="$1" _gnu="" _musl=""
    case "$_arch" in
        amd64) _gnu="realm-x86_64-unknown-linux-gnu.tar.gz"; _musl="realm-x86_64-unknown-linux-musl.tar.gz" ;;
        arm64) _gnu="realm-aarch64-unknown-linux-gnu.tar.gz"; _musl="realm-aarch64-unknown-linux-musl.tar.gz" ;;
        *) return 1 ;;
    esac
    if [ "${RELEASE:-unknown}" = "alpine" ]; then
        printf '%s\n' "$_musl"
    else
        printf '%s\n%s\n' "$_gnu" "$_musl"
    fi
}

download_realm() {
    local _arch _ver _asset _ok=0 _tmp_dir _tmp_archive _url _bin
    _arch=$(detect_arch) || return 1
    case "$_arch" in
        amd64|arm64) ;;
        *) echo -e "${RED}realm 不支持该架构: ${_arch}${PLAIN}"; return 1 ;;
    esac
    get_realm_latest_version
    _ver="${REALM_VERSION_TAG#v}"
    _tmp_dir=$(mktemp -d "$(disk_tmp_dir)/realm-dl-XXXXXX" 2>/dev/null) || return 1
    _tmp_archive="${_tmp_dir}/realm.tar.gz"
    while IFS= read -r _asset; do
        [ -n "$_asset" ] || continue
        for _url in \
            "https://github.com/${REALM_REPO}/releases/download/v${_ver}/${_asset}" \
            "https://gh-proxy.com/https://github.com/${REALM_REPO}/releases/download/v${_ver}/${_asset}" \
            "https://kkgithub.com/${REALM_REPO}/releases/download/v${_ver}/${_asset}"
        do
            echo -e "${YELLOW}正在下载 ${_asset}...${PLAIN}"
            rm -f "$_tmp_archive"
            if download_file "$_url" "$_tmp_archive" && tar -tzf "$_tmp_archive" >/dev/null 2>&1; then
                _ok=1
                break 2
            fi
        done
    done <<EOF
$(realm_asset_names "$_arch")
EOF
    if [ "$_ok" = "0" ]; then
        rm -rf "$_tmp_dir"
        echo -e "${RED}realm 下载失败，请检查网络后重试${PLAIN}"
        return 1
    fi
    if ! tar -xzf "$_tmp_archive" -C "$_tmp_dir" 2>/dev/null; then
        rm -rf "$_tmp_dir"
        echo -e "${RED}realm 解压失败${PLAIN}"
        return 1
    fi
    _bin=$(find "$_tmp_dir" -type f -name "realm" | head -1)
    [ -n "$_bin" ] || _bin=$(find "$_tmp_dir" -type f -perm -u+x ! -name '*.tar.gz' | head -1)
    if [ -z "$_bin" ]; then
        rm -rf "$_tmp_dir"
        echo -e "${RED}压缩包中未找到 realm 二进制${PLAIN}"
        return 1
    fi
    chmod +x "$_bin"
    if ! validate_elf "$_bin"; then
        rm -rf "$_tmp_dir"
        echo -e "${RED}realm 二进制 ELF 校验失败（文件损坏或架构不匹配）${PLAIN}"
        return 1
    fi
    mkdir -p "$(dirname "$REALM_BIN")" || { rm -rf "$_tmp_dir"; return 1; }
    if ! mv -f "$_bin" "$REALM_BIN" || ! chmod +x "$REALM_BIN"; then
        rm -rf "$_tmp_dir"
        echo -e "${RED}安装 realm 二进制失败${PLAIN}"
        return 1
    fi
    rm -rf "$_tmp_dir"
    echo -e "${GREEN}✓ realm 已安装: ${REALM_BIN}${PLAIN}"
}

# ------------------------------------------------------------
# sing-box 共享核心（落地机节点）
# ------------------------------------------------------------
singbox_asset_name() {
    local _ver="${1#v}" _arch="$2" _suffix=""
    if [ "${RELEASE:-unknown}" = "alpine" ] && version_at_least "$_ver" "1.13.0"; then
        case "$_arch" in
            amd64|arm64) _suffix="-musl" ;;
        esac
    fi
    printf 'sing-box-%s-linux-%s%s.tar.gz\n' "$_ver" "$_arch" "$_suffix"
}

get_latest_version() {
    local _candidate _url
    LAST_VERSION_TAG=""
    echo -e "${YELLOW}正在获取 sing-box 最新稳定版...${PLAIN}"
    _candidate=$(curl -fsSL --connect-timeout 8 --max-time 15 \
        "https://api.github.com/repos/SagerNet/sing-box/releases/latest" 2>/dev/null \
        | awk -F'"' '/"tag_name":/ { print $4; exit }' 2>/dev/null || true)
    LAST_VERSION_TAG=$(normalize_version_tag "$_candidate" 2>/dev/null || true)
    if [ -z "$LAST_VERSION_TAG" ]; then
        for _url in \
            "https://github.com/SagerNet/sing-box/releases/latest" \
            "https://kkgithub.com/SagerNet/sing-box/releases/latest"
        do
            _candidate=$(curl -Ls --connect-timeout 8 --max-time 15 -o /dev/null -w "%{url_effective}" "$_url" 2>/dev/null || true)
            LAST_VERSION_TAG=$(normalize_version_tag "$_candidate" 2>/dev/null || true)
            [ -n "$LAST_VERSION_TAG" ] && break
        done
    fi
    if [ -z "$LAST_VERSION_TAG" ]; then
        LAST_VERSION_TAG=$(normalize_version_tag "$SING_BOX_STABLE_FALLBACK_TAG" 2>/dev/null || true)
        [ -n "$LAST_VERSION_TAG" ] && echo -e "${YELLOW}[WARN] 无法连接 GitHub，使用内置稳定版 ${LAST_VERSION_TAG}${PLAIN}"
    fi
    [ -n "$LAST_VERSION_TAG" ] || { echo -e "${RED}获取 sing-box 版本失败${PLAIN}"; return 1; }
    echo -e "${GREEN}sing-box 最新版本: ${LAST_VERSION_TAG}${PLAIN}"
}

get_installed_version() {
    [ -x "$SING_BOX_BIN" ] || return 1
    "$SING_BOX_BIN" version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1
}

validate_shared_configs_with_bin() {
    local _bin="$1" _config
    [ -x "$_bin" ] || return 1
    for _config in "$SING_BOX_DIR"/*.json; do
        [ -f "$_config" ] || continue
        if ! "$_bin" check -c "$_config" >/dev/null 2>&1; then
            echo -e "${RED}新核心无法加载共享配置: ${_config}${PLAIN}"
            return 1
        fi
    done
    return 0
}

download_singbox() {
    local _arch _ver _asset _ok=0 _tmp_dir _tmp_archive _url _bin
    _arch=$(detect_arch) || return 1
    _ver="${LAST_VERSION_TAG#v}"
    _asset=$(singbox_asset_name "$_ver" "$_arch") || return 1
    _tmp_dir=$(mktemp -d "$(disk_tmp_dir)/sing-box-XXXXXX" 2>/dev/null) || return 1
    _tmp_archive="${_tmp_dir}/${_asset}"
    for _url in \
        "https://github.com/SagerNet/sing-box/releases/download/v${_ver}/${_asset}" \
        "https://gh-proxy.com/https://github.com/SagerNet/sing-box/releases/download/v${_ver}/${_asset}" \
        "https://kkgithub.com/SagerNet/sing-box/releases/download/v${_ver}/${_asset}"
    do
        echo -e "${YELLOW}正在下载 ${_asset}...${PLAIN}"
        rm -f "$_tmp_archive"
        if download_file "$_url" "$_tmp_archive" && tar -tzf "$_tmp_archive" >/dev/null 2>&1; then
            _ok=1
            break
        fi
    done
    if [ "$_ok" = "0" ]; then
        rm -rf "$_tmp_dir"
        echo -e "${RED}sing-box 下载失败，请检查网络后重试${PLAIN}"
        return 1
    fi
    if ! tar -xzf "$_tmp_archive" -C "$_tmp_dir" 2>/dev/null; then
        rm -rf "$_tmp_dir"
        echo -e "${RED}sing-box 解压失败${PLAIN}"
        return 1
    fi
    _bin=$(find "$_tmp_dir" -type f -name "sing-box" | head -1)
    if [ -z "$_bin" ]; then
        rm -rf "$_tmp_dir"
        echo -e "${RED}未在压缩包中找到 sing-box 二进制${PLAIN}"
        return 1
    fi
    chmod +x "$_bin"
    if ! validate_elf "$_bin"; then
        rm -rf "$_tmp_dir"
        echo -e "${RED}sing-box ELF 校验失败${PLAIN}"
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
    rm -rf "$_tmp_dir"
    echo -e "${GREEN}sing-box 安装完成: $("$SING_BOX_BIN" version 2>/dev/null | head -1)${PLAIN}"
}

ensure_singbox_bin() {
    local _preexisting=0 _installed_version
    if [ -x "$SING_BOX_BIN" ]; then
        _preexisting=1
        _installed_version=$(get_installed_version)
        if version_at_least "${_installed_version:-0.0.0}" "$SINGBOX_MIN_VERSION"; then
            if [ -f "$NODE_META/config.env" ]; then
                MANAGED_SING_BOX=$(awk -F= '$1 == "MANAGED_SING_BOX" { print $2; exit }' "$NODE_META/config.env")
                [ "$MANAGED_SING_BOX" = "1" ] || MANAGED_SING_BOX=0
            fi
            return 0
        fi
        echo -e "${YELLOW}现有 sing-box ${_installed_version:-未知版本} 低于最低要求 ${SINGBOX_MIN_VERSION}，将升级到最新稳定版${PLAIN}"
    fi
    get_latest_version || return 1
    download_singbox || return 1
    if [ "$_preexisting" = "1" ]; then
        MANAGED_SING_BOX=0
    else
        MANAGED_SING_BOX=1
        mkdir -p "$SING_BOX_DIR" || { echo -e "${RED}无法创建 sing-box 配置目录${PLAIN}"; return 1; }
        { : > "$SING_BOX_MANAGED_MARKER"; } || { echo -e "${RED}无法写入 sing-box 所有权标记${PLAIN}"; return 1; }
        chmod 600 "$SING_BOX_MANAGED_MARKER" || { echo -e "${RED}无法保护 sing-box 所有权标记${PLAIN}"; return 1; }
    fi
    return 0
}

# ============================================================
# 公网 IP 探测
# ============================================================
extract_probe_ip() {
    awk '
        /^ip=/ { sub(/^ip=/, ""); print; found = 1; exit }
        NR == 1 && $0 !~ /=/ { first = $0 }
        END { if (!found && first != "") print first }
    ' | tr -d ' \t\r\n'
}

get_default_public_ipv4() {
    local _ip _url
    for _url in $IPV4_PROBE_URLS; do
        _ip=$(curl -s4 --connect-timeout 3 --max-time 5 "$_url" 2>/dev/null | extract_probe_ip)
        if is_valid_ipv4 "$_ip"; then
            printf '%s' "$_ip"
            return 0
        fi
    done
    return 1
}

get_default_public_ipv6() {
    local _ip _url
    for _url in $IPV6_PROBE_URLS; do
        _ip=$(curl -s6 --connect-timeout 3 --max-time 5 "$_url" 2>/dev/null | extract_probe_ip)
        if is_valid_ipv6 "$_ip"; then
            printf '%s' "$_ip"
            return 0
        fi
    done
    return 1
}

detect_exit_egress() {
    EXIT_IPV4=""
    EXIT_HAS_IPV6=0
    EXIT_IPV4=$(get_default_public_ipv4 2>/dev/null || true)
    get_default_public_ipv6 >/dev/null 2>&1 && EXIT_HAS_IPV6=1 || EXIT_HAS_IPV6=0
}

detect_relay_ip() {
    RELAY_PUBLIC_IP=$(get_default_public_ipv4 2>/dev/null || true)
    RELAY_PUBLIC_IPV6=$(get_default_public_ipv6 2>/dev/null || true)
}

# ============================================================
# URI / 分享链接
# ============================================================
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

format_ipv6_for_uri() {
    echo "$1" | grep -q ':' && printf '[%s]' "$1" || printf '%s' "$1"
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

get_country_flag() {
    case "$1" in
        US) printf '🇺🇸' ;; DE) printf '🇩🇪' ;; JP) printf '🇯🇵' ;; SG) printf '🇸🇬' ;;
        HK) printf '🇭🇰' ;; TW) printf '🇹🇼' ;; KR) printf '🇰🇷' ;; GB) printf '🇬🇧' ;;
        FR) printf '🇫🇷' ;; NL) printf '🇳🇱' ;; CA) printf '🇨🇦' ;; AU) printf '🇦🇺' ;;
        RU) printf '🇷🇺' ;; IN) printf '🇮🇳' ;; VN) printf '🇻🇳' ;; TH) printf '🇹🇭' ;;
        *) printf '🌐' ;;
    esac
}

generate_node_name() {
    local _country _flag _proto
    _country=$(printf '%s' "${1:-UN}" | tr '[:lower:]' '[:upper:]')
    case "$_country" in [A-Z][A-Z]) ;; *) _country="UN" ;; esac
    _flag=$(get_country_flag "$_country")
    case "${NODE_PROTO:-anytls}" in
        anytls) _proto="AnyTLS" ;;
        *) _proto="VLESS" ;;
    esac
    printf '%s %s | Realm | %s' "$_flag" "$_country" "$_proto" | tr -d '\r\n\t'
}

# AnyTLS 自签证书节点带 insecure=1，不写 fp：带 fp 时客户端改用 uTLS Chrome 指纹，新建会话偶发
# "failed to create session: tls: first record does not look like a TLS handshake"
render_anytls_uri() {
    local _server="$1" _port="$2" _password="$3" _name="$4" _sni="${5:-$SERVER_NAME}"
    local _host _enc_name _enc_password _enc_sni
    _host=$(format_ipv6_for_uri "$_server")
    _enc_name=$(uri_encode "$_name")
    _enc_password=$(uri_encode "$_password")
    _enc_sni=$(uri_encode "$_sni")
    printf 'anytls://%s@%s:%s/?security=tls&sni=%s&insecure=1#%s\n' \
        "$_enc_password" "$_host" "$_port" "$_enc_sni" "$_enc_name"
}

# VLESS REALITY 必须带 fp=chrome（REALITY 要 uTLS）
render_vless_uri() {
    local _server="$1" _port="$2" _uuid="$3" _name="$4" _sni="${5:-$SERVER_NAME}"
    local _public_key="${6:-$REALITY_PUBLIC_KEY}" _short_id="${7:-$SHORT_ID}"
    local _host _enc_name _enc_sni
    _host=$(format_ipv6_for_uri "$_server")
    _enc_name=$(uri_encode "$_name")
    _enc_sni=$(uri_encode "$_sni")
    printf 'vless://%s@%s:%s?encryption=none&flow=xtls-rprx-vision&security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s&type=tcp#%s\n' \
        "$_uuid" "$_host" "$_port" "$_enc_sni" "$_public_key" "$_short_id" "$_enc_name"
}

build_node_uri() {
    local _server="$1" _port="$2"
    case "${NODE_PROTO:-anytls}" in
        anytls) render_anytls_uri "$_server" "$_port" "$ANYTLS_PASSWORD" "$NODE_NAME" "$SERVER_NAME" ;;
        *) render_vless_uri "$_server" "$_port" "$UUID" "$NODE_NAME" "$SERVER_NAME" "$REALITY_PUBLIC_KEY" "$SHORT_ID" ;;
    esac
}

generate_terminal_qrcode() {
    local _data="$1"
    command -v qrencode >/dev/null 2>&1 || return 1
    qrencode -t ANSIUTF8 -m 2 "$_data"
}

# ============================================================
# realm 配置（线路机）
# ============================================================
realm_remote_endpoint() {
    local _host="$1" _port="$2"
    if is_valid_ipv6 "$_host"; then
        printf '[%s]:%s' "$_host" "$_port"
    else
        printf '%s:%s' "$_host" "$_port"
    fi
}

# TOML：纯 TCP 转发，RELAY_LISTEN_PORT → LANDING_HOST:NODE_PORT
write_realm_config() {
    local _tmp _remote
    validate_port "$RELAY_LISTEN_PORT" || { echo -e "${RED}转发监听端口无效${PLAIN}"; return 1; }
    validate_port "$NODE_PORT" || { echo -e "${RED}落地节点端口无效${PLAIN}"; return 1; }
    validate_exit_host "$LANDING_HOST" || { echo -e "${RED}落地机地址无效${PLAIN}"; return 1; }
    mkdir -p "$REALM_DIR" || return 1
    _remote=$(realm_remote_endpoint "$LANDING_HOST" "$NODE_PORT")
    _tmp=$(mktemp "${REALM_DIR}/config.toml.new.XXXXXX" 2>/dev/null) || return 1
    if ! cat > "$_tmp" <<CFG
[network]
no_tcp = false
use_udp = false

[[endpoints]]
listen = "${LISTEN_HOST}:${RELAY_LISTEN_PORT}"
remote = "${_remote}"
CFG
    then
        rm -f "$_tmp"
        return 1
    fi
    chmod 644 "$_tmp" && mv -f "$_tmp" "$REALM_CONFIG" || { rm -f "$_tmp"; return 1; }
}

atomic_write_meta() {
    local _target="$1" _value="$2" _tmp
    _tmp=$(mktemp "${_target}.new.XXXXXX" 2>/dev/null) || return 1
    printf '%s' "$_value" > "$_tmp" && chmod 600 "$_tmp" && mv -f "$_tmp" "$_target" || {
        rm -f "$_tmp"
        return 1
    }
}

write_realm_meta() {
    local _tmp
    mkdir -p "$REALM_META" && chmod 700 "$REALM_META" || return 1
    _tmp=$(mktemp "${REALM_META}/config.env.new.XXXXXX" 2>/dev/null) || return 1
    if ! cat > "$_tmp" <<CFG
ROLE=relay
NODE_PROTO=${NODE_PROTO}
RELAY_LISTEN_PORT=${RELAY_LISTEN_PORT}
NODE_PORT=${NODE_PORT}
LANDING_HOST=${LANDING_HOST}
SSH_PORT=${SSH_PORT}
SSH_USER=${SSH_USER}
LISTEN_HOST=${LISTEN_HOST}
SERVER_NAME=${SERVER_NAME}
HANDSHAKE_PORT=${HANDSHAKE_PORT}
ANYTLS_PASSWORD=${ANYTLS_PASSWORD}
UUID=${UUID}
REALITY_PUBLIC_KEY=${REALITY_PUBLIC_KEY}
SHORT_ID=${SHORT_ID}
NODE_NAME=${NODE_NAME}
RELAY_PUBLIC_IP=${RELAY_PUBLIC_IP}
RELAY_PUBLIC_IPV6=${RELAY_PUBLIC_IPV6}
EXIT_IPV4=${EXIT_IPV4}
EXIT_HAS_IPV6=${EXIT_HAS_IPV6}
CFG
    then
        rm -f "$_tmp"
        return 1
    fi
    chmod 600 "$_tmp" && mv -f "$_tmp" "$REALM_META/config.env" || { rm -f "$_tmp"; return 1; }
}

read_realm_meta() {
    [ -f "$REALM_META/config.env" ] || return 1
    local _key _value
    while IFS='=' read -r _key _value; do
        case "$_key" in
            ROLE) ROLE="$_value" ;;
            NODE_PROTO) NODE_PROTO="$_value" ;;
            RELAY_LISTEN_PORT) RELAY_LISTEN_PORT="$_value" ;;
            NODE_PORT) NODE_PORT="$_value" ;;
            LANDING_HOST) LANDING_HOST="$_value" ;;
            SSH_PORT) SSH_PORT="$_value" ;;
            SSH_USER) SSH_USER="$_value" ;;
            LISTEN_HOST) LISTEN_HOST="$_value" ;;
            SERVER_NAME) SERVER_NAME="$_value" ;;
            HANDSHAKE_PORT) HANDSHAKE_PORT="$_value" ;;
            ANYTLS_PASSWORD) ANYTLS_PASSWORD="$_value" ;;
            UUID) UUID="$_value" ;;
            REALITY_PUBLIC_KEY) REALITY_PUBLIC_KEY="$_value" ;;
            SHORT_ID) SHORT_ID="$_value" ;;
            NODE_NAME) NODE_NAME="$_value" ;;
            RELAY_PUBLIC_IP) RELAY_PUBLIC_IP="$_value" ;;
            RELAY_PUBLIC_IPV6) RELAY_PUBLIC_IPV6="$_value" ;;
            EXIT_IPV4) EXIT_IPV4="$_value" ;;
            EXIT_HAS_IPV6) EXIT_HAS_IPV6="$_value" ;;
        esac
    done < "$REALM_META/config.env"
    return 0
}

# ============================================================
# 落地机节点配置（sing-box JSON）
# ============================================================
# 独立节点：AnyTLS 或 VLESS REALITY 入站，direct 出站直接出网（无隧道）
write_exit_node_config() {
    local _tmp _inbound
    validate_port "$NODE_PORT" || return 1
    case "${NODE_PROTO:-anytls}" in
        anytls)
            _inbound=$(cat <<CFG
    {
      "type": "anytls",
      "tag": "realm-node-in",
      "listen": "::",
      "listen_port": ${NODE_PORT},
      "users": [
        { "name": "default", "password": "${ANYTLS_PASSWORD}" }
      ],
      "padding_scheme": [],
      "tls": {
        "enabled": true,
        "server_name": "${SERVER_NAME}",
        "certificate_path": "${NODE_CERT}",
        "key_path": "${NODE_KEY}"
      }
    }
CFG
)
            ;;
        *)
            _inbound=$(cat <<CFG
    {
      "type": "vless",
      "tag": "realm-node-in",
      "listen": "::",
      "listen_port": ${NODE_PORT},
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
            "server_port": ${HANDSHAKE_PORT},
            "domain_resolver": {
              "server": "local",
              "strategy": "prefer_ipv4"
            }
          },
          "private_key": "${REALITY_PRIVATE_KEY}",
          "short_id": ["${SHORT_ID}"]
        }
      }
    }
CFG
)
            ;;
    esac
    mkdir -p "$SING_BOX_DIR" || return 1
    _tmp=$(mktemp "${SING_BOX_DIR}/realm-node.json.new.XXXXXX" 2>/dev/null) || return 1
    if ! cat > "$_tmp" <<CFG
{
  "log": { "level": "warn", "timestamp": true },
  "dns": {
    "servers": [
      { "type": "local", "tag": "local" }
    ]
  },
  "inbounds": [
${_inbound}
  ],
  "outbounds": [
    { "type": "direct", "tag": "direct" }
  ],
  "route": {
    "rules": [
      { "ip_is_private": true, "action": "reject" }
    ],
    "final": "direct",
    "default_domain_resolver": { "server": "local", "strategy": "prefer_ipv4" }
  }
}
CFG
    then
        rm -f "$_tmp"
        return 1
    fi
    chmod 600 "$_tmp" && mv -f "$_tmp" "$NODE_CONFIG" || { rm -f "$_tmp"; return 1; }
}

write_exit_node_meta() {
    local _tmp
    mkdir -p "$NODE_META" && chmod 700 "$NODE_META" || return 1
    _tmp=$(mktemp "${NODE_META}/config.env.new.XXXXXX" 2>/dev/null) || return 1
    if ! cat > "$_tmp" <<CFG
ROLE=exit
NODE_PROTO=${NODE_PROTO}
NODE_PORT=${NODE_PORT}
SERVER_NAME=${SERVER_NAME}
HANDSHAKE_PORT=${HANDSHAKE_PORT}
ANYTLS_PASSWORD=${ANYTLS_PASSWORD}
UUID=${UUID}
REALITY_PRIVATE_KEY=${REALITY_PRIVATE_KEY}
SHORT_ID=${SHORT_ID}
EXIT_IPV4=${EXIT_IPV4}
EXIT_HAS_IPV6=${EXIT_HAS_IPV6}
MANAGED_SING_BOX=${MANAGED_SING_BOX}
CFG
    then
        rm -f "$_tmp"
        return 1
    fi
    chmod 600 "$_tmp" && mv -f "$_tmp" "$NODE_META/config.env" || { rm -f "$_tmp"; return 1; }
}

read_exit_node_meta() {
    [ -f "$NODE_META/config.env" ] || return 1
    local _key _value
    while IFS='=' read -r _key _value; do
        case "$_key" in
            ROLE) ROLE="$_value" ;;
            NODE_PROTO) NODE_PROTO="$_value" ;;
            NODE_PORT) NODE_PORT="$_value" ;;
            SERVER_NAME) SERVER_NAME="$_value" ;;
            HANDSHAKE_PORT) HANDSHAKE_PORT="$_value" ;;
            ANYTLS_PASSWORD) ANYTLS_PASSWORD="$_value" ;;
            UUID) UUID="$_value" ;;
            REALITY_PRIVATE_KEY) REALITY_PRIVATE_KEY="$_value" ;;
            SHORT_ID) SHORT_ID="$_value" ;;
            EXIT_IPV4) EXIT_IPV4="$_value" ;;
            EXIT_HAS_IPV6) EXIT_HAS_IPV6="$_value" ;;
            MANAGED_SING_BOX) MANAGED_SING_BOX="$_value" ;;
        esac
    done < "$NODE_META/config.env"
    return 0
}

write_node_wrapper() {
    cat > "$NODE_BIN" <<WRAPPER
#!/bin/sh
exec "${SING_BOX_BIN}" run -c "${NODE_CONFIG}" "\$@"
WRAPPER
    chmod 755 "$NODE_BIN"
}

check_node_config() {
    "$SING_BOX_BIN" check -c "$NODE_CONFIG"
}

# ============================================================
# 服务管理（systemd / openrc / raw）
# ============================================================
svc_exec_for() {
    case "$1" in
        realm) printf '%s -c %s' "$REALM_BIN" "$REALM_CONFIG" ;;
        realm-node) printf '%s' "$NODE_BIN" ;;
    esac
}

write_realm_service() {
    if [ "$INIT_SYS" = "openrc" ]; then
        cat > "$REALM_OPENRC" <<'SVCHEAD'
#!/sbin/openrc-run

name="realm"
description="Realm TCP Relay"
SVCHEAD
        cat >> "$REALM_OPENRC" <<SVC
command="${REALM_BIN}"
command_args="-c ${REALM_CONFIG}"
command_background="yes"
pidfile="/var/run/realm.pid"
output_log="/var/log/realm.log"
error_log="/var/log/realm.log"

depend() {
    need net
    after firewall
}
SVC
        chmod +x "$REALM_OPENRC"
    else
        cat > "$REALM_SYSTEMD" <<SVC
[Unit]
Description=Realm TCP Relay
After=network.target

[Service]
Type=simple
User=root
ExecStart=${REALM_BIN} -c ${REALM_CONFIG}
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
SVC
        chmod 600 "$REALM_SYSTEMD"
    fi
}

write_node_service() {
    if [ "$INIT_SYS" = "openrc" ]; then
        cat > "$NODE_OPENRC" <<'SVCHEAD'
#!/sbin/openrc-run

name="realm-node"
description="Realm Landing Node (sing-box)"
SVCHEAD
        cat >> "$NODE_OPENRC" <<SVC
command="${NODE_BIN}"
command_args=""
command_background="yes"
pidfile="/var/run/realm-node.pid"
output_log="/var/log/realm-node.log"
error_log="/var/log/realm-node.log"

depend() {
    need net
    after firewall
}
SVC
        chmod +x "$NODE_OPENRC"
    else
        cat > "$NODE_SYSTEMD" <<SVC
[Unit]
Description=Realm Landing Node (sing-box)
After=network.target nss-lookup.target
Wants=network.target

[Service]
Type=simple
User=root
ExecStart=${NODE_BIN}
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
SVC
        chmod 600 "$NODE_SYSTEMD"
    fi
}

svc_is_active() {
    local _name="$1"
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl is-active --quiet "$_name"
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service "$_name" status 2>/dev/null | grep -q "started"
    else
        [ -f "/var/run/${_name}.pid" ] && kill -0 "$(cat "/var/run/${_name}.pid")" 2>/dev/null
    fi
}

svc_start() {
    local _name="$1" _exec
    if svc_is_active "$_name"; then
        return 0
    fi
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl start "$_name"
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service "$_name" start
    else
        _exec=$(svc_exec_for "$_name")
        nohup $_exec >"/var/log/${_name}.log" 2>&1 &
        echo $! > "/var/run/${_name}.pid"
    fi
}

svc_stop() {
    local _name="$1"
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl stop "$_name" 2>/dev/null
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service "$_name" stop 2>/dev/null
    else
        if [ -f "/var/run/${_name}.pid" ]; then
            kill "$(cat "/var/run/${_name}.pid")" 2>/dev/null || true
            rm -f "/var/run/${_name}.pid"
        fi
    fi
}

svc_restart() {
    local _name="$1"
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl restart "$_name"
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service "$_name" restart
    else
        svc_stop "$_name"; sleep 1; svc_start "$_name"
    fi
}

svc_enable() {
    local _name="$1"
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl daemon-reload
        systemctl enable "$_name" >/dev/null 2>&1
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-update add "$_name" default >/dev/null 2>&1
    fi
}

svc_disable() {
    local _name="$1"
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl disable "$_name" 2>/dev/null
        systemctl daemon-reload
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-update del "$_name" default 2>/dev/null
    fi
}

svc_logs() {
    local _name="$1"
    if [ "$INIT_SYS" = "systemd" ]; then
        journalctl -u "$_name" -n 60 --no-pager 2>/dev/null || true
    else
        [ -f "/var/log/${_name}.log" ] && tail -n 60 "/var/log/${_name}.log" || echo "暂无日志"
    fi
}

wait_for_service() {
    local _name="$1" _tries="${2:-6}" _i=0
    while [ "$_i" -lt "$_tries" ]; do
        if svc_is_active "$_name"; then
            return 0
        fi
        sleep 1
        _i=$((_i + 1))
    done
    svc_is_active "$_name"
}

# ============================================================
# 防火墙（仅 TCP）
# ============================================================
fw_meta_dir() {
    case "$ROLE" in
        exit) printf '%s' "${NODE_META}/firewall" ;;
        *) printf '%s' "${REALM_META}/firewall" ;;
    esac
}

open_ports() {
    local _port="$1" _proto="${2:-tcp}" _fw_meta _added4=0
    _fw_meta=$(fw_meta_dir)
    validate_port "$_port" || { echo -e "${RED}无效的防火墙端口: ${_port}${PLAIN}"; return 1; }
    case "$_proto" in tcp|udp) ;; *) return 1 ;; esac
    mkdir -p "$_fw_meta" 2>/dev/null || {
        echo -e "${RED}无法创建防火墙规则记录目录，已取消放行${PLAIN}"
        return 1
    }
    echo -e "${YELLOW}正在自动放行 ${_proto} 端口 ${_port}...${PLAIN}"

    if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        if ! firewall-cmd --permanent --query-port="${_port}/${_proto}" >/dev/null 2>&1; then
            if ! firewall-cmd --permanent --add-port="${_port}/${_proto}" >/dev/null 2>&1 || \
                ! firewall-cmd --reload >/dev/null 2>&1; then
                echo -e "${RED}firewalld 放行 ${_proto}/${_port} 失败${PLAIN}"
                return 1
            fi
            : > "$_fw_meta/firewalld-${_port}-${_proto}"
        fi
        echo -e "  ${GREEN}✓ firewalld 已放行 ${_proto}/${_port}${PLAIN}"
        return 0
    fi

    if command -v ufw >/dev/null 2>&1 && LC_ALL=C ufw status 2>/dev/null | grep -qE '^Status:[[:space:]]+active[[:space:]]*$'; then
        if ! LC_ALL=C ufw status 2>/dev/null | grep -qE "^${_port}/${_proto}[[:space:]]+ALLOW"; then
            if ! LC_ALL=C ufw allow "${_port}/${_proto}" >/dev/null; then
                echo -e "${RED}ufw 放行 ${_proto}/${_port} 失败${PLAIN}"
                return 1
            fi
            : > "$_fw_meta/ufw-${_port}-${_proto}"
        fi
        echo -e "  ${GREEN}✓ ufw 已放行 ${_proto}/${_port}${PLAIN}"
        return 0
    fi

    if command -v iptables >/dev/null 2>&1; then
        if ! iptables -C INPUT -p "$_proto" --dport "${_port}" -j ACCEPT >/dev/null 2>&1; then
            if ! iptables -I INPUT -p "$_proto" --dport "${_port}" -j ACCEPT >/dev/null 2>&1; then
                echo -e "${RED}iptables 放行 ${_proto}/${_port} 失败${PLAIN}"
                return 1
            fi
            _added4=1
            : > "$_fw_meta/iptables4-${_port}-${_proto}"
        fi
        if command -v ip6tables >/dev/null 2>&1; then
            if ! ip6tables -C INPUT -p "$_proto" --dport "${_port}" -j ACCEPT >/dev/null 2>&1; then
                ip6tables -I INPUT -p "$_proto" --dport "${_port}" -j ACCEPT >/dev/null 2>&1 && \
                    : > "$_fw_meta/iptables6-${_port}-${_proto}" || true
            fi
        fi
        if command -v netfilter-persistent >/dev/null 2>&1; then
            netfilter-persistent save >/dev/null 2>&1 || true
        elif [ -f /etc/sysconfig/iptables ] && command -v service >/dev/null 2>&1; then
            service iptables save >/dev/null 2>&1 || true
        fi
        echo -e "  ${GREEN}✓ iptables 已放行 ${_proto}/${_port}${PLAIN}"
        return 0
    fi

    echo -e "  ${YELLOW}! 未检测到启用的本机防火墙；请确认云安全组 / 面板防火墙已放行 ${_proto}/${_port}${PLAIN}"
    return 0
}

close_ports() {
    local _port="$1" _proto="${2:-tcp}" _fw_meta
    _fw_meta=$(fw_meta_dir)
    validate_port "$_port" || return 0
    case "$_proto" in tcp|udp) ;; *) return 0 ;; esac

    if [ -f "$_fw_meta/firewalld-${_port}-${_proto}" ] && command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        firewall-cmd --permanent --remove-port="${_port}/${_proto}" >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
        rm -f "$_fw_meta/firewalld-${_port}-${_proto}"
    fi
    if [ -f "$_fw_meta/ufw-${_port}-${_proto}" ] && command -v ufw >/dev/null 2>&1; then
        ufw delete allow "${_port}/${_proto}" >/dev/null 2>&1 || true
        rm -f "$_fw_meta/ufw-${_port}-${_proto}"
    fi
    if [ -f "$_fw_meta/iptables4-${_port}-${_proto}" ] && command -v iptables >/dev/null 2>&1; then
        iptables -D INPUT -p "$_proto" --dport "${_port}" -j ACCEPT >/dev/null 2>&1 || true
        rm -f "$_fw_meta/iptables4-${_port}-${_proto}"
    fi
    if [ -f "$_fw_meta/iptables6-${_port}-${_proto}" ] && command -v ip6tables >/dev/null 2>&1; then
        ip6tables -D INPUT -p "$_proto" --dport "${_port}" -j ACCEPT >/dev/null 2>&1 || true
        rm -f "$_fw_meta/iptables6-${_port}-${_proto}"
    fi
    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save >/dev/null 2>&1 || true
    fi
}

# ============================================================
# SSH 一键对接（线路机 → 落地机）
# ============================================================
ssh_supports_accept_new() {
    ssh -G -o StrictHostKeyChecking=accept-new localhost >/dev/null 2>&1
}

ssh_target() {
    printf '%s@%s' "$SSH_USER" "$LANDING_HOST"
}

ssh_build_opts() {
    SSH_OPTS=(-p "$SSH_PORT" -o "ControlPath=${SSH_CTL_DIR}/cm" -o ConnectTimeout=15
        -o ServerAliveInterval=15 -o ServerAliveCountMax=4 -o LogLevel=ERROR)
    # 首次连接自动记录主机指纹（与手动 ssh 首登一致）；已记录的指纹变化时 ssh 会拒绝连接。
    if ssh_supports_accept_new; then
        SSH_OPTS+=(-o StrictHostKeyChecking=accept-new)
    fi
}

# known_hosts 里的落地机名称：非 22 端口时 OpenSSH 记录为 [主机]:端口。
ssh_known_hosts_name() {
    if [ "${SSH_PORT:-22}" = "22" ]; then
        printf '%s' "$LANDING_HOST"
    else
        printf '[%s]:%s' "$LANDING_HOST" "$SSH_PORT"
    fi
}

# 不登录、不提示密码，只连到主机密钥校验为止（认证方式 none 必然被拒），ssh 的报错写入 $1。
ssh_probe_host_key() {
    ssh "${SSH_OPTS[@]}" -o ControlMaster=no -o BatchMode=yes -o PreferredAuthentications=none \
        -T "$(ssh_target)" true </dev/null >/dev/null 2>"$1"
    return 0
}

ssh_host_key_changed() {
    grep -q 'REMOTE HOST IDENTIFICATION HAS CHANGED' "$1" 2>/dev/null
}

# 落地机现在出示的主机密钥指纹与类型，取自 ssh 报错。
ssh_presented_fingerprint() {
    awk '
        f || /sent by the remote host is/ {
            if (match($0, /SHA256:[A-Za-z0-9+\/=]+/)) { print substr($0, RSTART, RLENGTH); exit }
            f = 1
        }
    ' "$1" 2>/dev/null
}

ssh_presented_key_type() {
    awk '/key sent by the remote host is/ {
        for (i = 2; i <= NF; i++) if ($i == "key" && $(i + 1) == "sent") { print $(i - 1); exit }
    }' "$1" 2>/dev/null
}

ssh_offending_known_hosts() {
    awk '/^Offending .* key in / { sub(/^Offending .* key in /, ""); sub(/:[0-9]+$/, ""); print; exit }' "$1" 2>/dev/null
}

# 删除本机记录的落地机旧密钥；ssh-keygen 会把原文件备份为 .old，之后 accept-new 记录新密钥。
ssh_forget_host_key() {
    local _file="$1"
    if [ -n "$_file" ] && [ -f "$_file" ]; then
        ssh-keygen -f "$_file" -R "$(ssh_known_hosts_name)" >/dev/null 2>&1
    else
        ssh-keygen -R "$(ssh_known_hosts_name)" >/dev/null 2>&1
    fi
}

# 落地机重装后主机密钥会变；正式登录前先探测，用户确认后才删除旧记录。
# 不能自动信任新密钥：关闭主机密钥校验等于把 SSH 密码交给冒充落地机的中间人。
ssh_check_host_key() {
    local _err="${SSH_CTL_DIR}/hostkey.err" _file _fp _type _answer
    ssh_probe_host_key "$_err"
    if grep -qE '^ssh: (connect to host|Could not resolve hostname)' "$_err" 2>/dev/null; then
        sed 's/^/  /' "$_err"
        echo -e "${RED}✗ 无法连接落地机，请检查地址与 SSH 端口（落地机是否开机、防火墙是否放行）${PLAIN}"
        return 1
    fi
    ssh_host_key_changed "$_err" || return 0
    _file=$(ssh_offending_known_hosts "$_err")
    _fp=$(ssh_presented_fingerprint "$_err")
    _type=$(ssh_presented_key_type "$_err")
    echo -e "${YELLOW}! 落地机 ${LANDING_HOST} 的 SSH 主机密钥和本机上次记录的不一致，ssh 已拒绝连接。${PLAIN}"
    echo -e "${DIM}  最常见的原因是落地机重装了系统（会生成新的主机密钥）；如果你没有动过落地机，可能有人在冒充它，请不要继续。${PLAIN}"
    if [ -n "$_fp" ]; then
        echo -e "  落地机现在的 ${_type:-主机} 密钥指纹：${YELLOW}${_fp}${PLAIN}"
        [ -z "$_type" ] || echo -e "${DIM}  可在落地机上运行 ssh-keygen -lf /etc/ssh/ssh_host_$(printf '%s' "$_type" | tr '[:upper:]' '[:lower:]')_key.pub 核对${PLAIN}"
    fi
    read -r -p "确认落地机重装过、信任新的主机密钥？[y/N]: " _answer
    case "$_answer" in
        [yY]*) ;;
        *)
            echo -e "${YELLOW}已取消，未连接落地机。确认落地机重装过后重新操作并输入 y，或在本机执行：${PLAIN}"
            echo "  ssh-keygen ${_file:+-f '${_file}' }-R '$(ssh_known_hosts_name)'"
            return 1
            ;;
    esac
    if ! command -v ssh-keygen >/dev/null 2>&1 || ! ssh_forget_host_key "$_file"; then
        echo -e "${RED}✗ 无法自动删除旧记录（本机缺少 ssh-keygen 或 known_hosts 不可写），请手动执行：${PLAIN}"
        echo "  ssh-keygen ${_file:+-f '${_file}' }-R '$(ssh_known_hosts_name)'"
        return 1
    fi
    ssh_probe_host_key "$_err"
    if ssh_host_key_changed "$_err"; then
        echo -e "${RED}✗ 删除旧记录后主机密钥仍不一致，请检查本机 known_hosts：${PLAIN}"
        grep '^Offending ' "$_err" | sed 's/^/  /'
        return 1
    fi
    echo -e "${GREEN}✓ 已删除本机记录的旧主机密钥并记录新的（原文件备份为 ${_file:-~/.ssh/known_hosts}.old）${PLAIN}"
    return 0
}

# 建立一条复用的主连接：整个对接过程只需输入一次 SSH 密码，
# 密码由 ssh 自己在终端读取，脚本不接触、不保存。
ssh_open_master() {
    ssh_close_master
    SSH_CTL_DIR=$(mktemp -d /tmp/realm-ssh.XXXXXX 2>/dev/null) || {
        echo -e "${RED}无法创建 SSH 控制目录${PLAIN}"
        return 1
    }
    chmod 700 "$SSH_CTL_DIR"
    ssh_build_opts
    echo -e "${YELLOW}正在连接落地机 $(ssh_target)（端口 ${SSH_PORT}）...${PLAIN}"
    if ! ssh_check_host_key; then
        ssh_close_master
        return 1
    fi
    echo -e "${DIM}如提示输入密码，请输入落地机 ${SSH_USER} 的 SSH 密码（输入时不显示）；脚本不会读取或保存密码。${PLAIN}"
    if ! ssh "${SSH_OPTS[@]}" -o ControlMaster=yes -o ControlPersist=900 -fN "$(ssh_target)" </dev/null; then
        echo -e "${RED}✗ 无法 SSH 登录落地机，请检查地址、SSH 端口、用户名与密码${PLAIN}"
        ssh_close_master
        return 1
    fi
    if ! ssh "${SSH_OPTS[@]}" -O check "$(ssh_target)" </dev/null >/dev/null 2>&1; then
        echo -e "${RED}✗ SSH 连接建立后立即断开，请重试${PLAIN}"
        ssh_close_master
        return 1
    fi
    echo -e "${GREEN}✓ 已连接落地机${PLAIN}"
    return 0
}

ssh_close_master() {
    if [ -n "$SSH_CTL_DIR" ] && [ -d "$SSH_CTL_DIR" ]; then
        [ "${#SSH_OPTS[@]}" -gt 0 ] && ssh "${SSH_OPTS[@]}" -O exit "$(ssh_target)" </dev/null >/dev/null 2>&1 || true
        rm -rf "$SSH_CTL_DIR"
    fi
    SSH_CTL_DIR=""
}

ssh_run() {
    ssh "${SSH_OPTS[@]}" -o ControlMaster=no -o BatchMode=yes -T "$(ssh_target)" "$@"
}

remote_sudo_prefix() {
    [ "$SSH_USER" = "root" ] && return 0
    printf 'sudo -n '
}

# 落地机上执行的脚本必须与线路机一致；经管道运行时下载一份完整副本
resolve_script_source() {
    REALM_SCRIPT_SOURCE=""
    if [ -f "$SCRIPT_PATH" ] && grep -q 'REALM_LIB_ONLY' "$SCRIPT_PATH" 2>/dev/null && bash -n "$SCRIPT_PATH" 2>/dev/null; then
        REALM_SCRIPT_SOURCE="$SCRIPT_PATH"
        return 0
    fi
    REALM_SCRIPT_TMP=$(mktemp "$(disk_tmp_dir)/realm-src.XXXXXX" 2>/dev/null) || return 1
    if download_file "$REALM_SCRIPT_URL" "$REALM_SCRIPT_TMP" && \
        bash -n "$REALM_SCRIPT_TMP" 2>/dev/null && \
        grep -q 'REALM_LIB_ONLY' "$REALM_SCRIPT_TMP" 2>/dev/null; then
        REALM_SCRIPT_SOURCE="$REALM_SCRIPT_TMP"
        return 0
    fi
    cleanup_script_source
    echo -e "${RED}无法获取完整的 realm.sh 用于部署落地机${PLAIN}"
    return 1
}

cleanup_script_source() {
    [ -n "$REALM_SCRIPT_TMP" ] && rm -f "$REALM_SCRIPT_TMP"
    REALM_SCRIPT_TMP=""
}

is_valid_remote_stage_dir() {
    printf '%s\n' "$1" | grep -qE '^/tmp/realm-remote\.[A-Za-z0-9]+$'
}

# 先把脚本落盘到落地机临时目录，再以 </dev/null 执行，避免 apt 等子进程吞掉 stdin 脚本
remote_stage_script() {
    local _out
    REMOTE_STAGE_DIR=""
    [ -n "$REALM_SCRIPT_SOURCE" ] && [ -f "$REALM_SCRIPT_SOURCE" ] || return 1
    _out=$(ssh_run 'umask 077; d=$(mktemp -d /tmp/realm-remote.XXXXXX) && cat > "$d/realm.sh" && printf "%s\n" "$d"' < "$REALM_SCRIPT_SOURCE") || return 1
    _out=$(printf '%s\n' "$_out" | tail -n 1 | tr -d '\r')
    is_valid_remote_stage_dir "$_out" || return 1
    REMOTE_STAGE_DIR="$_out"
}

parse_remote_result() {
    awk '
        /^REALM_EXIT_RESULT=/ { value=$0; sub(/^REALM_EXIT_RESULT=/, "", value); last=value }
        END { if (last != "") print last }
    ' | tr -d '\r'
}

write_remote_params() {
    local _file
    _file=$(mktemp "$(disk_tmp_dir)/realm-params.XXXXXX" 2>/dev/null) || return 1
    chmod 600 "$_file" || { rm -f "$_file"; return 1; }
    if ! cat > "$_file" <<CFG
NODE_PROTO=${NODE_PROTO}
NODE_PORT=${NODE_PORT}
SERVER_NAME=${SERVER_NAME}
HANDSHAKE_PORT=${HANDSHAKE_PORT}
ANYTLS_PASSWORD=${ANYTLS_PASSWORD}
UUID=${UUID}
REALITY_PRIVATE_KEY=${REALITY_PRIVATE_KEY}
SHORT_ID=${SHORT_ID}
CFG
    then
        rm -f "$_file"
        return 1
    fi
    printf '%s' "$_file"
}

read_remote_params() {
    local _file="$1/params" _key _value
    [ -f "$_file" ] || return 1
    NODE_PROTO=""; NODE_PORT=""; SERVER_NAME=""; HANDSHAKE_PORT="443"
    ANYTLS_PASSWORD=""; UUID=""; REALITY_PRIVATE_KEY=""; SHORT_ID=""
    while IFS='=' read -r _key _value; do
        case "$_key" in
            NODE_PROTO) NODE_PROTO="$_value" ;;
            NODE_PORT) NODE_PORT="$_value" ;;
            SERVER_NAME) SERVER_NAME="$_value" ;;
            HANDSHAKE_PORT) HANDSHAKE_PORT="$_value" ;;
            ANYTLS_PASSWORD) ANYTLS_PASSWORD="$_value" ;;
            UUID) UUID="$_value" ;;
            REALITY_PRIVATE_KEY) REALITY_PRIVATE_KEY="$_value" ;;
            SHORT_ID) SHORT_ID="$_value" ;;
        esac
    done < "$_file"
    rm -f "$_file"
    case "$NODE_PROTO" in anytls|vless) ;; *) return 1 ;; esac
    validate_port "$NODE_PORT" || return 1
    validate_server_name "$SERVER_NAME" || return 1
    validate_port "$HANDSHAKE_PORT" || return 1
    if [ "$NODE_PROTO" = "anytls" ]; then
        validate_anytls_password "$ANYTLS_PASSWORD" || return 1
    else
        validate_uuid "$UUID" || return 1
        validate_reality_key "$REALITY_PRIVATE_KEY" || return 1
        validate_short_id "$SHORT_ID" || return 1
    fi
    return 0
}

# 在落地机上执行 realm.sh 的远程动作；$2 可选为本地参数文件
remote_realm_action() {
    local _action="$1" _params="${2:-}" _log _rc=0 _sudo
    REMOTE_RESULT=""
    case "$_action" in
        --remote-exit-install|--remote-exit-uninstall|--remote-exit-status) ;;
        *) return 1 ;;
    esac
    [ -n "$SSH_CTL_DIR" ] || return 1
    remote_stage_script || { echo -e "${RED}无法把脚本上传到落地机${PLAIN}"; return 1; }
    if [ -n "$_params" ]; then
        ssh_run "cat > '${REMOTE_STAGE_DIR}/params'" < "$_params" || {
            ssh_run "rm -rf '${REMOTE_STAGE_DIR}'" </dev/null >/dev/null 2>&1 || true
            echo -e "${RED}无法把对接参数上传到落地机${PLAIN}"
            return 1
        }
    fi
    _sudo=$(remote_sudo_prefix)
    _log=$(mktemp "$(disk_tmp_dir)/realm-remote-log.XXXXXX" 2>/dev/null) || return 1
    ssh_run "${_sudo}bash '${REMOTE_STAGE_DIR}/realm.sh' ${_action} '${REMOTE_STAGE_DIR}' </dev/null; _rc=\$?; rm -rf '${REMOTE_STAGE_DIR}'; exit \$_rc" \
        </dev/null 2>&1 | tee "$_log"
    _rc=${PIPESTATUS[0]}
    REMOTE_RESULT=$(parse_remote_result < "$_log")
    rm -f "$_log"
    return "$_rc"
}

# 解析落地机返回：ok|<节点端口>|<出口IPv4>|<是否有IPv6>
apply_remote_result() {
    local _result="$1" _tag _port _ipv4 _v6
    [ -n "$_result" ] || return 1
    IFS='|' read -r _tag _port _ipv4 _v6 <<EOF
$_result
EOF
    [ "$_tag" = "ok" ] || return 1
    validate_port "$_port" || return 1
    [ -z "$_ipv4" ] || is_valid_ipv4 "$_ipv4" || return 1
    case "$_v6" in 0|1) ;; *) _v6=0 ;; esac
    NODE_PORT="$_port"
    EXIT_IPV4="$_ipv4"
    EXIT_HAS_IPV6="$_v6"
    return 0
}

# ============================================================
# 落地机远程动作（由线路机经 SSH 调用）
# ============================================================
installed_exit_role() {
    [ -f "$NODE_META/config.env" ] || return 1
    awk -F= '$1 == "ROLE" { print $2; exit }' "$NODE_META/config.env"
}

remote_exit_install() {
    local _stage="$1"
    check_root
    check_sys
    detect_init
    ROLE="exit"
    is_valid_remote_stage_dir "$_stage" || { echo -e "${RED}无效的远程参数目录${PLAIN}"; return 1; }
    read_remote_params "$_stage" || { echo -e "${RED}对接参数无效，已取消${PLAIN}"; return 1; }
    echo -e "${SKYBLUE}── 落地机：开始部署 ${NODE_PROTO} 节点 ──${PLAIN}"
    install_dependencies || return 1
    echo -e "${YELLOW}正在检测落地机出口...${PLAIN}"
    detect_exit_egress
    if [ -z "$EXIT_IPV4" ]; then
        echo -e "${RED}落地机无法访问 IPv4 外网，不能作为出口${PLAIN}"
        return 1
    fi
    echo -e "${GREEN}✓ 落地机出口 IPv4: ${EXIT_IPV4}${PLAIN}"
    if tcp_port_is_listening "$NODE_PORT" && [ ! -f "$NODE_CONFIG" ]; then
        echo -e "${RED}落地机端口 ${NODE_PORT} 已被占用，请在线路机换一个节点端口${PLAIN}"
        return 1
    fi
    if ! ensure_singbox_bin; then
        return 1
    fi
    if [ "$NODE_PROTO" = "anytls" ]; then
        echo -e "${YELLOW}正在生成自签 TLS 证书...${PLAIN}"
        generate_node_certificate force || { echo -e "${RED}生成 TLS 证书失败${PLAIN}"; return 1; }
    else
        rm -rf "$NODE_CERT_DIR"
    fi
    if ! write_exit_node_config || ! write_exit_node_meta || ! write_node_wrapper || ! check_node_config; then
        echo -e "${RED}落地节点配置写入或校验失败${PLAIN}"
        return 1
    fi
    write_node_service
    svc_enable realm-node
    open_ports "$NODE_PORT" tcp || return 1
    if svc_is_active realm-node; then
        svc_restart realm-node || return 1
    else
        svc_start realm-node || return 1
    fi
    if ! wait_for_service realm-node 8; then
        echo -e "${RED}✗ 落地节点启动失败，日志如下：${PLAIN}"
        svc_logs realm-node
        return 1
    fi
    echo -e "${GREEN}✓ 落地节点已启动，监听 TCP ${NODE_PORT}${PLAIN}"
    echo "REALM_EXIT_RESULT=ok|${NODE_PORT}|${EXIT_IPV4}|${EXIT_HAS_IPV6}"
    return 0
}

uninstall_exit_node_files() {
    read_exit_node_meta >/dev/null 2>&1 || true
    ROLE="exit"
    local _managed_core=0 _other_file=""
    if [ "$MANAGED_SING_BOX" = "1" ] || [ -f "$SING_BOX_MANAGED_MARKER" ]; then
        _managed_core=1
    fi
    svc_stop realm-node
    svc_disable realm-node
    [ -n "$NODE_PORT" ] && close_ports "$NODE_PORT" tcp
    rm -f "$NODE_SYSTEMD" "$NODE_OPENRC" "$NODE_BIN"
    rm -f "$NODE_CONFIG"
    rm -rf "$NODE_META" "$NODE_CERT_DIR"
    rm -f /var/run/realm-node.pid /var/log/realm-node.log
    if [ -d "$SING_BOX_DIR" ]; then
        _other_file=$(find "$SING_BOX_DIR" -mindepth 1 -maxdepth 1 ! -name '.singbox-tools-managed' -print -quit 2>/dev/null)
    fi
    if [ -z "$_other_file" ]; then
        rm -f "$SING_BOX_MANAGED_MARKER"
        rmdir "$SING_BOX_DIR" 2>/dev/null || true
        [ "$_managed_core" = "1" ] && rm -f "$SING_BOX_BIN"
    elif [ "$_managed_core" = "1" ]; then
        echo -e "${YELLOW}检测到 /etc/sing-box 中还有其他协议文件，已保留共享 sing-box 二进制${PLAIN}"
    fi
    [ "$INIT_SYS" = "systemd" ] && systemctl daemon-reload
    return 0
}

remote_exit_uninstall() {
    check_root
    check_sys
    detect_init
    uninstall_exit_node_files
    echo -e "${GREEN}✓ 落地机节点已卸载${PLAIN}"
}

remote_exit_status() {
    check_root
    check_sys
    detect_init
    if [ "$(installed_exit_role 2>/dev/null)" != "exit" ] || ! read_exit_node_meta >/dev/null 2>&1; then
        echo -e "${RED}✗ 落地机未部署节点，或配置已损坏${PLAIN}"
        return 1
    fi
    svc_is_active realm-node && echo -e "  ${GREEN}✓ 落地节点服务运行中${PLAIN}" || echo -e "  ${RED}✗ 落地节点服务未运行${PLAIN}"
    tcp_port_is_listening "$NODE_PORT" && echo -e "  ${GREEN}✓ TCP ${NODE_PORT} 正在监听${PLAIN}" || echo -e "  ${RED}✗ 未检测到 TCP ${NODE_PORT} 监听${PLAIN}"
    detect_exit_egress
    [ -n "$EXIT_IPV4" ] && echo -e "  ${GREEN}✓ 落地机出口 IPv4: ${EXIT_IPV4}${PLAIN}" || echo -e "  ${RED}✗ 落地机无法访问 IPv4 外网${PLAIN}"
}

# ============================================================
# 线路机：一键部署 / 重新对接
# ============================================================
choose_node_protocol() {
    local _input
    echo -e "\n${SKYBLUE}--- 节点协议（客户端 → 落地机）---${PLAIN}"
    echo -e "  [1] AnyTLS（推荐）：自签证书，无需域名，自带流量填充"
    echo -e "  [2] VLESS + REALITY：借用大厂网站握手"
    while true; do
        read -r -p "节点协议 [默认 1]: " _input
        case "${_input:-1}" in
            1) NODE_PROTO="anytls"; return 0 ;;
            2) NODE_PROTO="vless"; return 0 ;;
            *) echo -e "${RED}请输入 1 或 2${PLAIN}" ;;
        esac
    done
}

prompt_landing_ssh() {
    local _input
    echo -e "\n${SKYBLUE}--- 落地机 SSH 信息 ---${PLAIN}"
    while true; do
        read -r -p "落地机地址（IPv4 / IPv6 / 域名）: " _input
        _input=$(trim_string "$_input")
        if validate_exit_host "$_input"; then
            LANDING_HOST="$_input"
            break
        fi
        echo -e "${RED}地址格式无效，请重新输入${PLAIN}"
    done
    while true; do
        read -r -p "落地机 SSH 端口 [默认 22]: " _input
        _input=$(trim_string "${_input:-22}")
        if validate_port "$_input"; then
            SSH_PORT="$_input"
            break
        fi
        echo -e "${RED}端口无效${PLAIN}"
    done
    while true; do
        read -r -p "落地机 SSH 用户名 [默认 root]: " _input
        _input=$(trim_string "${_input:-root}")
        if validate_ssh_user "$_input"; then
            SSH_USER="$_input"
            break
        fi
        echo -e "${RED}用户名格式无效${PLAIN}"
    done
}

prompt_ports() {
    local _input _default
    echo -e "\n${SKYBLUE}--- 端口设置 ---${PLAIN}"
    _default=$(generate_random_port) || _default=20000
    while true; do
        read -r -p "线路机转发监听端口 RELAY_LISTEN_PORT [默认 ${_default}]: " _input
        _input=$(trim_string "${_input:-$_default}")
        if validate_port "$_input"; then
            RELAY_LISTEN_PORT="$_input"
            break
        fi
        echo -e "${RED}端口无效${PLAIN}"
    done
    _default=$(generate_random_port) || _default=20001
    while true; do
        read -r -p "落地机节点端口 NODE_PORT [默认 ${_default}]: " _input
        _input=$(trim_string "${_input:-$_default}")
        if validate_port "$_input"; then
            NODE_PORT="$_input"
            break
        fi
        echo -e "${RED}端口无效${PLAIN}"
    done
}

confirm_firewall() {
    local _input
    echo -e "\n${YELLOW}请确认以下端口已在对应机器的云安全组 / 面板防火墙放行（脚本会尽量放行本机防火墙）：${PLAIN}"
    echo -e "  • 落地机 ${GREEN}TCP ${NODE_PORT}${PLAIN}（接收线路机转发的流量）"
    echo -e "  • 线路机 ${GREEN}TCP ${RELAY_LISTEN_PORT}${PLAIN}（接收客户端连接）"
    read -r -p "已确认 / 稍后放行？[Y/n]: " _input
    case "${_input:-y}" in
        [nN]*) echo -e "${YELLOW}已取消部署${PLAIN}"; return 1 ;;
        *) return 0 ;;
    esac
}

generate_node_params() {
    echo -e "\n${SKYBLUE}--- 生成节点参数 ---${PLAIN}"
    HANDSHAKE_PORT="443"
    if [ "$NODE_PROTO" = "anytls" ]; then
        local _default_sni
        _default_sni=$(random_sni)
        local _input
        read -r -p "TLS 伪装域名（SNI）[随机默认 ${_default_sni}]: " _input
        _input=$(trim_string "$_input")
        [ -z "$_input" ] && _input="$_default_sni"
        validate_server_name "$_input" || { echo -e "${RED}SNI 域名格式无效${PLAIN}"; return 1; }
        SERVER_NAME="$_input"
        ANYTLS_PASSWORD=$(generate_anytls_password) || { echo -e "${RED}生成连接密码失败${PLAIN}"; return 1; }
        UUID=""; REALITY_PRIVATE_KEY=""; REALITY_PUBLIC_KEY=""; SHORT_ID=""
        echo -e "${GREEN}✓ AnyTLS 连接密码已生成${PLAIN}"
    else
        SERVER_NAME=$(random_sni)
        local _input
        read -r -p "REALITY 伪装域名（SNI）[随机默认 ${SERVER_NAME}]: " _input
        _input=$(trim_string "$_input")
        [ -n "$_input" ] && SERVER_NAME="$_input"
        validate_server_name "$SERVER_NAME" || { echo -e "${RED}SNI 域名格式无效${PLAIN}"; return 1; }
        ANYTLS_PASSWORD=""
        UUID=$(generate_uuid) || { echo -e "${RED}生成 UUID 失败${PLAIN}"; return 1; }
        echo -e "${YELLOW}正在生成 REALITY 密钥对...${PLAIN}"
        generate_reality_keypair || { echo -e "${RED}生成 REALITY 密钥对失败（请确认已安装 openssl）${PLAIN}"; return 1; }
        SHORT_ID=$(generate_short_id) || { echo -e "${RED}生成 REALITY short ID 失败${PLAIN}"; return 1; }
        echo -e "${GREEN}✓ UUID、REALITY 密钥与 short ID 已生成${PLAIN}"
    fi
    return 0
}

deploy_realm() {
    clear_screen
    echo -e "${SKYBLUE}${BOLD}================================================${PLAIN}"
    echo -e "  ${GREEN}${BOLD}Realm TCP 中转一键部署${PLAIN}"
    echo -e "${SKYBLUE}================================================${PLAIN}"
    echo -e "  架构: 客户端 → ${GREEN}线路机(realm 转发)${PLAIN} → ${GREEN}落地机(节点)${PLAIN} → 互联网"
    echo -e "  ${DIM}本脚本在线路机上运行：会 SSH 到落地机安装 sing-box 节点，${PLAIN}"
    echo -e "  ${DIM}并在本机安装 realm，将本机端口纯 TCP 转发到落地机节点端口。${PLAIN}"
    echo -e "${SKYBLUE}------------------------------------------------${PLAIN}"

    ROLE="relay"
    install_dependencies || { echo -e "${RED}依赖安装失败${PLAIN}"; return 1; }
    ensure_ssh_client || return 1

    choose_node_protocol
    prompt_landing_ssh
    prompt_ports
    confirm_firewall || return 1
    generate_node_params || return 1

    echo -e "\n${YELLOW}正在检测线路机公网 IP...${PLAIN}"
    detect_relay_ip
    if [ -z "$RELAY_PUBLIC_IP" ] && [ -z "$RELAY_PUBLIC_IPV6" ]; then
        local _input
        read -r -p "未能自动检测到公网 IP，请手动输入线路机公网地址: " _input
        _input=$(trim_string "$_input")
        if is_valid_ipv4 "$_input"; then
            RELAY_PUBLIC_IP="$_input"
        elif is_valid_ipv6 "$_input"; then
            RELAY_PUBLIC_IPV6="$_input"
        fi
    fi
    [ -n "$RELAY_PUBLIC_IP" ] && echo -e "  线路机公网 IPv4: ${GREEN}${RELAY_PUBLIC_IP}${PLAIN}"
    [ -n "$RELAY_PUBLIC_IPV6" ] && echo -e "  线路机公网 IPv6: ${GREEN}${RELAY_PUBLIC_IPV6}${PLAIN}"

    echo -e "\n${YELLOW}正在准备部署脚本...${PLAIN}"
    resolve_script_source || return 1
    if ! ssh_open_master; then
        cleanup_script_source
        return 1
    fi

    local _params _rc=0
    _params=$(write_remote_params) || { ssh_close_master; cleanup_script_source; echo -e "${RED}生成对接参数失败${PLAIN}"; return 1; }
    echo -e "\n${YELLOW}正在落地机上安装 sing-box 节点...${PLAIN}"
    if ! remote_realm_action --remote-exit-install "$_params"; then
        rm -f "$_params"
        ssh_close_master
        cleanup_script_source
        echo -e "${RED}✗ 落地机节点部署失败，请检查上方日志${PLAIN}"
        return 1
    fi
    rm -f "$_params"
    if ! apply_remote_result "$REMOTE_RESULT"; then
        ssh_close_master
        cleanup_script_source
        echo -e "${RED}✗ 落地机返回结果异常，部署中止${PLAIN}"
        return 1
    fi
    ssh_close_master
    cleanup_script_source
    echo -e "${GREEN}✓ 落地机节点已就绪（端口 TCP ${NODE_PORT}，出口 ${EXIT_IPV4}）${PLAIN}"

    echo -e "\n${YELLOW}正在线路机安装 realm 转发...${PLAIN}"
    download_realm || return 1
    NODE_NAME=$(generate_node_name "$(get_ip_country "$EXIT_IPV4" 2>/dev/null || echo UN)")
    if ! write_realm_config; then
        echo -e "${RED}写入 realm 配置失败${PLAIN}"
        return 1
    fi
    write_realm_service
    svc_enable realm
    open_ports "$RELAY_LISTEN_PORT" tcp || return 1
    if svc_is_active realm; then
        svc_restart realm
    else
        svc_start realm
    fi
    if ! wait_for_service realm 6; then
        echo -e "${RED}✗ realm 启动失败，日志如下：${PLAIN}"
        svc_logs realm
        return 1
    fi
    write_realm_meta || echo -e "${YELLOW}! realm 元数据写入失败（不影响运行）${PLAIN}"

    echo -e "${GREEN}✓ realm 已启动，监听 TCP ${RELAY_LISTEN_PORT}${PLAIN}"
    echo -e "\n${YELLOW}正在检查线路机 → 落地机连通性...${PLAIN}"
    if check_relay_to_landing; then
        echo -e "${GREEN}✓ 线路机可连通落地机节点端口${PLAIN}"
    else
        echo -e "${YELLOW}! 线路机未能连通落地机 ${LANDING_HOST}:${NODE_PORT}，请确认落地机防火墙 / 安全组已放行 TCP ${NODE_PORT}${PLAIN}"
    fi

    echo -e "\n${GREEN}${BOLD}部署完成！${PLAIN}"
    show_config
    return 0
}

# 线路机对落地机节点端口做一次 TCP 连通性检查
check_relay_to_landing() {
    local _host="$LANDING_HOST" _port="$NODE_PORT"
    validate_port "$_port" || return 1
    if command -v nc >/dev/null 2>&1; then
        nc -z -w 5 "$_host" "$_port" >/dev/null 2>&1 && return 0
    fi
    if command -v curl >/dev/null 2>&1; then
        local _target
        if is_valid_ipv6 "$_host"; then
            _target="[$_host]:$_port"
        else
            _target="$_host:$_port"
        fi
        curl -s --connect-timeout 5 --max-time 6 "telnet://${_target}" >/dev/null 2>&1 && return 0
    fi
    # /dev/tcp 兜底（bash 内置）
    (exec 3<>"/dev/tcp/${_host}/${_port}") >/dev/null 2>&1 && { exec 3>&- 2>/dev/null; return 0; }
    return 1
}

# ============================================================
# 节点信息 / 分享链接
# ============================================================
show_config() {
    local _mode="${1:-all}" _server _uri
    if ! read_realm_meta || [ "$ROLE" != "relay" ]; then
        echo -e "${RED}未检测到线路机部署，请先执行一键部署${PLAIN}"
        return 1
    fi
    [ -z "$RELAY_PUBLIC_IP" ] && RELAY_PUBLIC_IP=$(get_default_public_ipv4 2>/dev/null || true)
    _server="$RELAY_PUBLIC_IP"
    [ -z "$_server" ] && _server="$RELAY_PUBLIC_IPV6"
    [ -z "$_server" ] && _server="$LANDING_HOST"
    [ -z "$NODE_NAME" ] && NODE_NAME=$(generate_node_name "UN")
    _uri=$(build_node_uri "$_server" "$RELAY_LISTEN_PORT")

    if [ "$_mode" = "uri" ] || [ "$_mode" = "link" ]; then
        printf '%s\n' "$_uri"
        return 0
    fi

    echo -e "${SKYBLUE}================================================${PLAIN}"
    echo -e "  ${GREEN}${BOLD}节点信息${PLAIN}"
    echo -e "${SKYBLUE}================================================${PLAIN}"
    echo -e "  协议      : ${GREEN}$(printf '%s' "$NODE_PROTO" | tr '[:lower:]' '[:upper:]')${PLAIN}"
    echo -e "  连接地址  : ${GREEN}${_server}${PLAIN}（线路机公网 IP）"
    echo -e "  连接端口  : ${GREEN}${RELAY_LISTEN_PORT}${PLAIN}（realm 转发 → 落地机 ${NODE_PORT}）"
    echo -e "  落地机    : ${DIM}${LANDING_HOST}:${NODE_PORT}${PLAIN}"
    echo -e "  出口 IP   : ${DIM}${EXIT_IPV4:-未知}${PLAIN}"
    echo -e "  SNI       : ${GREEN}${SERVER_NAME}${PLAIN}"
    if [ "$NODE_PROTO" = "anytls" ]; then
        echo -e "  连接密码  : ${GREEN}${ANYTLS_PASSWORD}${PLAIN}"
        echo -e "  ${DIM}自签证书 insecure=1；分享链接不带 fp（避免 uTLS 握手偶发失败）${PLAIN}"
    else
        echo -e "  UUID      : ${GREEN}${UUID}${PLAIN}"
        echo -e "  公钥 pbk  : ${GREEN}${REALITY_PUBLIC_KEY}${PLAIN}"
        echo -e "  short_id  : ${GREEN}${SHORT_ID}${PLAIN}"
    fi
    echo -e "${SKYBLUE}------------------------------------------------${PLAIN}"
    echo -e "  分享链接:"
    printf '%s\n' "$_uri"
    echo -e "${SKYBLUE}------------------------------------------------${PLAIN}"
    if command -v qrencode >/dev/null 2>&1; then
        echo -e "  二维码:"
        generate_terminal_qrcode "$_uri"
    else
        echo -e "  ${DIM}安装 qrencode 可显示二维码${PLAIN}"
    fi
    echo -e "${SKYBLUE}================================================${PLAIN}"
    return 0
}

# ============================================================
# 服务管理（线路机 realm）
# ============================================================
manage_realm() {
    if [ ! -f "$REALM_CONFIG" ] || [ ! -x "$REALM_BIN" ]; then
        echo -e "${RED}realm 尚未部署，请先执行一键部署${PLAIN}"
        sleep 2
        return
    fi
    read_realm_meta >/dev/null 2>&1 || true
    ROLE="relay"
    while true; do
        clear_screen
        local _status
        svc_is_active realm && _status="${GREEN}运行中${PLAIN}" || _status="${RED}已停止${PLAIN}"
        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e "${GREEN}  realm 服务管理${PLAIN}"
        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e " 当前状态: ${_status}"
        echo -e " 1. 启动"
        echo -e " 2. 停止"
        echo -e " 3. 重启"
        echo -e " 4. 查看日志"
        echo -e " 0. 返回"
        read -r -p "请输入选项 [0-4]: " choice
        case "$choice" in
            1) svc_start realm; sleep 1; svc_is_active realm && echo -e "${GREEN}✓ 已启动${PLAIN}" || echo -e "${RED}✗ 启动失败${PLAIN}"; sleep 1 ;;
            2) svc_stop realm; sleep 1; svc_is_active realm && echo -e "${RED}✗ 仍在运行${PLAIN}" || echo -e "${GREEN}✓ 已停止${PLAIN}"; sleep 1 ;;
            3) svc_restart realm; sleep 1; svc_is_active realm && echo -e "${GREEN}✓ 已重启${PLAIN}" || echo -e "${RED}✗ 重启失败${PLAIN}"; sleep 1 ;;
            4) svc_logs realm; read -r -p "按回车返回..." _ ;;
            0|q|quit|exit) return ;;
            *) echo -e "${RED}无效选项${PLAIN}"; sleep 1 ;;
        esac
    done
}

# ============================================================
# 升级 realm 二进制
# ============================================================
upgrade_realm() {
    check_root
    if [ ! -x "$REALM_BIN" ]; then
        echo -e "${RED}realm 尚未安装${PLAIN}"
        return 1
    fi
    read_realm_meta >/dev/null 2>&1 || true
    ROLE="relay"
    install_dependencies || return 1
    local _was_active=0
    svc_is_active realm && _was_active=1
    echo -e "${YELLOW}正在升级 realm 二进制...${PLAIN}"
    if ! download_realm; then
        echo -e "${RED}升级失败${PLAIN}"
        return 1
    fi
    if [ "$_was_active" = "1" ]; then
        svc_restart realm
        wait_for_service realm 6 && echo -e "${GREEN}✓ realm 已升级并重启${PLAIN}" || echo -e "${RED}✗ 升级后 realm 未能启动，请查看日志${PLAIN}"
    else
        echo -e "${GREEN}✓ realm 二进制已升级${PLAIN}"
    fi
}

# ============================================================
# 卸载
# ============================================================
uninstall_realm() {
    check_root
    if [ ! -f "$REALM_CONFIG" ] && [ ! -x "$REALM_BIN" ]; then
        echo -e "${RED}未检测到 realm 部署${PLAIN}"
        return 1
    fi
    read_realm_meta >/dev/null 2>&1 || true
    ROLE="relay"
    local _input
    echo -e "${YELLOW}即将卸载线路机上的 realm 转发。${PLAIN}"
    read -r -p "是否同时通过 SSH 卸载落地机上的节点？[y/N]: " _input
    case "$_input" in
        [yY]*)
            if [ -z "$LANDING_HOST" ]; then
                echo -e "${YELLOW}! 元数据缺少落地机地址，跳过远程卸载${PLAIN}"
            else
                ensure_ssh_client && resolve_script_source && ssh_open_master && {
                    remote_realm_action --remote-exit-uninstall || echo -e "${YELLOW}! 落地机远程卸载失败，请手动处理${PLAIN}"
                    ssh_close_master
                }
                cleanup_script_source
            fi
            ;;
        *)
            echo -e "${DIM}仅卸载线路机，落地机节点保留。${PLAIN}"
            ;;
    esac
    svc_stop realm
    svc_disable realm
    [ -n "$RELAY_LISTEN_PORT" ] && close_ports "$RELAY_LISTEN_PORT" tcp
    rm -f "$REALM_SYSTEMD" "$REALM_OPENRC" "$REALM_BIN"
    rm -f /var/run/realm.pid /var/log/realm.log
    rm -rf "$REALM_DIR"
    [ "$INIT_SYS" = "systemd" ] && systemctl daemon-reload
    echo -e "${GREEN}✓ 线路机 realm 已卸载${PLAIN}"
    return 0
}

# ============================================================
# 主菜单
# ============================================================
main_menu() {
    while true; do
        clear_screen
        local _status _role_text
        if [ -f "$REALM_CONFIG" ] && [ -x "$REALM_BIN" ]; then
            _role_text="${GREEN}线路机（中转端）${PLAIN}"
            svc_is_active realm && _status="${GREEN}运行中${PLAIN}" || _status="${RED}已停止${PLAIN}"
        elif [ -f "$NODE_CONFIG" ]; then
            _role_text="${GREEN}落地机（出口端）${PLAIN}"
            svc_is_active realm-node && _status="${GREEN}运行中${PLAIN}" || _status="${RED}已停止${PLAIN}"
        else
            _role_text="${DIM}未部署${PLAIN}"
            _status="${RED}未安装${PLAIN}"
        fi
        echo -e "${SKYBLUE}${BOLD}================================================${PLAIN}"
        echo -e "  ${GREEN}${BOLD}Realm TCP Relay Management Script${PLAIN} ${DIM}v2.3.0${PLAIN}"
        echo -e "  ${DIM}线路机 realm TCP 转发 + 落地机 AnyTLS / VLESS 节点${PLAIN}"
        echo -e "${SKYBLUE}${BOLD}================================================${PLAIN}"
        echo -e "  项目地址: ${YELLOW}https://github.com/everett7623/hy2${PLAIN}"
        echo -e "  作者    : ${YELLOW}everettlabs${PLAIN}"
        echo -e "${SKYBLUE}------------------------------------------------${PLAIN}"
        echo -e "  本机角色: ${_role_text}"
        echo -e "  当前状态: ${_status}"
        echo -e "${SKYBLUE}------------------------------------------------${PLAIN}"
        echo -e " 1. 一键部署 / 重新对接"
        echo -e " 2. 查看节点信息"
        echo -e " 3. 服务管理（启停重启日志）"
        echo -e " 4. 升级 realm 二进制"
        echo -e " 5. 卸载"
        echo -e " 0. 退出"
        echo -e "${SKYBLUE}================================================${PLAIN}"
        read -r -p "请输入选项 [0-5]: " choice
        case "$choice" in
            1) deploy_realm; read -r -p "按回车返回..." _ ;;
            2) show_config; read -r -p "按回车返回..." _ ;;
            3) manage_realm ;;
            4) upgrade_realm; read -r -p "按回车返回..." _ ;;
            5) uninstall_realm; read -r -p "按回车返回..." _ ;;
            0|q|quit|exit) exit 0 ;;
            *) echo -e "${RED}无效选项，请输入 0-5${PLAIN}"; sleep 1 ;;
        esac
    done
}

usage() {
    echo "用法: realm.sh [命令]"
    echo "可用命令: install | info | uri | manage | upgrade | uninstall | menu"
}

# ============================================================
# 入口（REALM_LIB_ONLY=1 时跳过）
# ============================================================
[ "$_REALM_LIB_ONLY" = "1" ] && return 0

# 非交互升级，供 cron 使用
if [ "${1:-}" = "--upgrade-noninteractive" ]; then
    check_root
    check_sys
    detect_init
    install_dependencies || exit 1
    if [ -x "$REALM_BIN" ]; then
        ROLE="relay"
        read_realm_meta >/dev/null 2>&1 || true
        download_realm && svc_restart realm
        exit $?
    fi
    exit 0
fi

# 落地机远程动作，仅由线路机经 SSH 调用
case "${1:-}" in
    --remote-exit-install) remote_exit_install "${2:-}"; exit $? ;;
    --remote-exit-uninstall) remote_exit_uninstall; exit $? ;;
    --remote-exit-status) remote_exit_status; exit $? ;;
esac

check_root
check_sys
detect_init
case "${1:-menu}" in
    install|deploy) deploy_realm ;;
    info|node|export|all) show_config ;;
    uri|link) show_config uri ;;
    manage|service|config) manage_realm ;;
    upgrade|update) upgrade_realm ;;
    uninstall|remove) uninstall_realm ;;
    menu|"") main_menu ;;
    *)
        echo -e "${RED}未知命令: ${1}${PLAIN}"
        usage
        exit 1
        ;;
esac
