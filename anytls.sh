#!/bin/bash
#====================================================================================
# 项目：AnyTLS Management Script
# 作者：Jensfrank
# 版本：v1.0.3
# GitHub: https://github.com/everett7623/hy2
# Seedloc博客: https://seedloc.com
# VPSknow网站：https://vpsknow.com
# Nodeloc论坛: https://nodeloc.com
# 更新日期: 2026-07-02
#
# 支持系统: Debian / Ubuntu / CentOS / Rocky / Alma / Fedora / Arch / Alpine
# 支持环境: 标准 VPS / NAT 机器 / IPv6 单栈 / 双栈机器
# 实现方式: 使用 sing-box >= 1.12.0 原生 AnyTLS 入站
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

[ "${ANYTLS_LIB_ONLY:-0}" != "1" ] && [ ! -t 0 ] && [ -c /dev/tty ] && exec < /dev/tty

if [ -f "$SCRIPT_PATH" ] && grep -q $'\r' "$SCRIPT_PATH" 2>/dev/null; then
    sed -i 's/\r$//' "$SCRIPT_PATH"
    exec bash "$SCRIPT_PATH" "$@"
fi

# ============================================================
# ANYTLS_LIB_ONLY=1：仅加载函数库，不执行任何副作用（供测试 source）
# ============================================================
[ "${ANYTLS_LIB_ONLY:-0}" = "1" ] && _ANYTLS_LIB_ONLY=1 || _ANYTLS_LIB_ONLY=0

# --- 颜色 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
SKYBLUE='\033[0;36m'
PLAIN='\033[0m'
BOLD='\033[1m'

# --- 路径 ---
ANYTLS_BIN="${ANYTLS_BIN:-/usr/local/bin/anytls-server}"
SING_BOX_BIN="${SING_BOX_BIN:-/usr/local/bin/sing-box}"
ANYTLS_DIR="${ANYTLS_DIR:-/etc/sing-box}"
ANYTLS_CONFIG="${ANYTLS_CONFIG:-${ANYTLS_DIR}/anytls.json}"
ANYTLS_META="${ANYTLS_META:-${ANYTLS_DIR}/anytls-meta}"
ANYTLS_CERT_DIR="${ANYTLS_CERT_DIR:-${ANYTLS_DIR}/anytls-cert}"
ANYTLS_CERT="${ANYTLS_CERT:-${ANYTLS_CERT_DIR}/cert.pem}"
ANYTLS_KEY="${ANYTLS_KEY:-${ANYTLS_CERT_DIR}/private.key}"
SYSTEMD_SERVICE="${SYSTEMD_SERVICE:-/etc/systemd/system/anytls-server.service}"
OPENRC_SERVICE="/etc/init.d/anytls-server"
AUTO_UPDATE_SCRIPT="/usr/local/bin/anytls-autoupdate.sh"
AUTO_UPDATE_LOG="/var/log/anytls-autoupdate.log"

# --- 运行时变量 ---
RELEASE="unknown"
INIT_SYS="none"
NAT_MODE=0
HAS_IPV4=0
HAS_IPV6=0
PUBLIC_IP=""
PUBLIC_IPV6=""
BIND_FAMILY="v4"
LISTEN_HOST="::"
LISTEN_PORT=""
EXT_PORT=""
PASSWORD=""
NODE_NAME=""
SERVER_NAME="www.example.com"
MANAGED_SING_BOX=0
LAST_VERSION_TAG=""
INSTALL_BACKUP_DIR=""


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

install_dependencies() {
    echo -e "${YELLOW}正在安装必要依赖...${PLAIN}"
    case "$RELEASE" in
        alpine)
            apk update -q
            apk add --no-cache bash curl wget ca-certificates tar openssl iproute2 procps
            apk add --no-cache libqrencode >/dev/null 2>&1 || true
            ;;
        centos)
            yum install -y curl wget ca-certificates tar openssl iproute procps-ng
            yum install -y qrencode >/dev/null 2>&1 || true
            ;;
        fedora|rocky)
            dnf install -y curl wget ca-certificates tar openssl iproute procps-ng
            dnf install -y qrencode >/dev/null 2>&1 || true
            ;;
        arch)
            pacman -Sy --noconfirm curl wget ca-certificates tar openssl iproute2 procps-ng
            pacman -S --noconfirm qrencode >/dev/null 2>&1 || true
            ;;
        *)
            if command -v apt-get >/dev/null 2>&1; then
                apt-get update -qq
                apt-get install -y curl wget ca-certificates tar openssl iproute2 procps
                apt-get install -y qrencode >/dev/null 2>&1 || true
            else
                echo -e "${RED}无法识别包管理器，请手动安装 curl wget tar openssl iproute2${PLAIN}"
                return 1
            fi
            ;;
    esac

    local _missing=0 _cmd
    for _cmd in curl wget tar openssl; do
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

validate_password() {
    local pw="$1"
    local len="${#pw}"
    [ "$len" -lt 8 ]   && return 1
    [ "$len" -gt 128 ] && return 1
    case "$pw" in
        *'"'*)  return 1 ;;
        *'\'*)  return 1 ;;
        *'$'*)  return 1 ;;
        *'`'*)  return 1 ;;
        *' '*)  return 1 ;;
    esac
    local _has_ctrl
    _has_ctrl=$(printf '%s' "$pw" | od -An -tx1 | tr ' \n' '\n' | { grep -cE '^[01][0-9a-f]$|^7f$' 2>/dev/null || true; })
    [ "${_has_ctrl:-0}" -gt 0 ] 2>/dev/null && return 1
    return 0
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

random_sni() {
    local _number
    _number=$(od -An -N2 -tu2 /dev/urandom 2>/dev/null | tr -d ' ')
    [ -z "$_number" ] && _number=$(date +%s)
    case $((_number % 8)) in
        0) echo "www.cloudflare.com" ;;
        1) echo "www.microsoft.com" ;;
        2) echo "www.apple.com" ;;
        3) echo "www.amazon.com" ;;
        4) echo "www.amd.com" ;;
        5) echo "www.bing.com" ;;
        6) echo "www.mozilla.org" ;;
        *) echo "www.github.com" ;;
    esac
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

# ============================================================
# 网络检测
# ============================================================
detect_network() {
    echo -e "${YELLOW}正在检测网络环境...${PLAIN}"
    NAT_MODE=0; HAS_IPV4=0; HAS_IPV6=0; PUBLIC_IP=""; PUBLIC_IPV6=""; BIND_FAMILY="v4"; LISTEN_HOST="::"
    local _ip _url

    for _url in "https://api6.ipify.org" "https://ipv6.icanhazip.com"; do
        _ip=$(curl -s6 --max-time 6 "$_url" 2>/dev/null | tr -d '[:space:]')
        if echo "$_ip" | grep -q ':'; then PUBLIC_IPV6="$_ip"; HAS_IPV6=1; break; fi
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
            [ -z "$PUBLIC_IPV6" ] && PUBLIC_IPV6="$_real_ipv6"
        else
            HAS_IPV6=0
            PUBLIC_IPV6=""
        fi
    fi

    for _url in "https://api.ipify.org" "https://ip.gs" "https://ipv4.icanhazip.com"; do
        _ip=$(curl -s4 --connect-timeout 3 --max-time 6 "$_url" 2>/dev/null | tr -d '[:space:]')
        if echo "$_ip" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then PUBLIC_IP="$_ip"; HAS_IPV4=1; break; fi
    done

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
}

open_ports() {
    local _port=$1
    echo -e "${YELLOW}正在自动放行 TCP 端口 ${_port}...${PLAIN}"

    if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port="${_port}/tcp" >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
        echo -e "  ${GREEN}✓ firewalld 已放行 tcp/${_port}${PLAIN}"
        return
    fi

    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "active"; then
        ufw allow "${_port}/tcp" >/dev/null 2>&1
        echo -e "  ${GREEN}✓ ufw 已放行 tcp/${_port}${PLAIN}"
        return
    fi

    if command -v iptables >/dev/null 2>&1; then
        iptables -C INPUT -p tcp --dport "${_port}" -j ACCEPT >/dev/null 2>&1 || \
            iptables -I INPUT -p tcp --dport "${_port}" -j ACCEPT >/dev/null 2>&1
        if [ "$HAS_IPV6" = "1" ] && command -v ip6tables >/dev/null 2>&1; then
            ip6tables -C INPUT -p tcp --dport "${_port}" -j ACCEPT >/dev/null 2>&1 || \
                ip6tables -I INPUT -p tcp --dport "${_port}" -j ACCEPT >/dev/null 2>&1
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
    validate_port "$_port" || return 0

    if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        firewall-cmd --permanent --remove-port="${_port}/tcp" >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
    fi
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "active"; then
        ufw delete allow "${_port}/tcp" >/dev/null 2>&1 || true
    fi
    if command -v iptables >/dev/null 2>&1; then
        while iptables -C INPUT -p tcp --dport "${_port}" -j ACCEPT >/dev/null 2>&1; do
            iptables -D INPUT -p tcp --dport "${_port}" -j ACCEPT >/dev/null 2>&1 || break
        done
    fi
    if command -v ip6tables >/dev/null 2>&1; then
        while ip6tables -C INPUT -p tcp --dport "${_port}" -j ACCEPT >/dev/null 2>&1; do
            ip6tables -D INPUT -p tcp --dport "${_port}" -j ACCEPT >/dev/null 2>&1 || break
        done
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

get_latest_version() {
    echo -e "${YELLOW}正在获取 sing-box 最新稳定版...${PLAIN}"
    LAST_VERSION_TAG=$(curl -Ls --max-time 12 "https://api.github.com/repos/SagerNet/sing-box/releases/latest" \
        | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' | head -1)

    if [ -z "$LAST_VERSION_TAG" ]; then
        LAST_VERSION_TAG=$(curl -Ls --max-time 12 -o /dev/null -w "%{url_effective}" \
            "https://github.com/SagerNet/sing-box/releases/latest" | sed 's|.*/tag/||')
    fi

    if ! printf '%s\n' "$LAST_VERSION_TAG" | grep -qE '^v?[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$'; then
        echo -e "${RED}获取版本失败或版本标签格式异常${PLAIN}"
        LAST_VERSION_TAG=""
        return 1
    fi
    echo -e "${GREEN}最新版本: ${LAST_VERSION_TAG}${PLAIN}"
}

get_installed_version() {
    [ -x "$SING_BOX_BIN" ] || return 1
    "$SING_BOX_BIN" version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1
}

download_anytls() {
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
    _tmp_dir=$(mktemp -d /tmp/sing-box-XXXXXX) || return 1
    _tmp_archive="${_tmp_dir}/${_asset}"

    for _url in "${_urls[@]}"; do
        _host=$(echo "$_url" | awk -F/ '{print $3}')
        echo -e "${YELLOW}正在下载 ${_asset}（来源: ${_host}）${PLAIN}"
        rm -f "$_tmp_archive"
        if wget -q --show-progress --timeout=60 -O "$_tmp_archive" "$_url" 2>/dev/null || \
           curl -fL --connect-timeout 15 --max-time 120 -o "$_tmp_archive" "$_url" 2>/dev/null; then
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

    mv -f "$_bin" "$SING_BOX_BIN"
    chmod +x "$SING_BOX_BIN"
    MANAGED_SING_BOX=1
    rm -rf "$_tmp_dir"
    echo -e "${GREEN}sing-box 安装完成: $("$SING_BOX_BIN" version 2>/dev/null | head -1)${PLAIN}"
}

ensure_anytls_bin() {
    local _preexisting=0
    if [ -x "$SING_BOX_BIN" ]; then
        _preexisting=1
        local _installed_version
        _installed_version=$(get_installed_version)
        if version_at_least "${_installed_version:-0.0.0}" "1.12.0"; then
            if [ -f "$ANYTLS_META/config.env" ]; then
                MANAGED_SING_BOX=$(awk -F= '$1 == "MANAGED_SING_BOX" { print $2; exit }' "$ANYTLS_META/config.env")
                [ "$MANAGED_SING_BOX" = "1" ] || MANAGED_SING_BOX=0
            fi
            return 0
        fi
        echo -e "${YELLOW}现有 sing-box ${_installed_version:-未知版本} 不支持原生 AnyTLS，将安装最新版${PLAIN}"
    fi
    get_latest_version || return 1
    download_anytls || return 1
    [ "$_preexisting" = "1" ] && MANAGED_SING_BOX=0
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

render_uri() {
    local _server="$1" _port="$2" _password="$3" _name="$4" _sni="${5:-$SERVER_NAME}"
    local _host="$_server"
    echo "$_server" | grep -q ':' && _host="[${_server}]"
    local _enc_name _enc_password _enc_sni
    _enc_name=$(uri_encode "$_name")
    _enc_password=$(uri_encode "$_password")
    _enc_sni=$(uri_encode "$_sni")
    printf 'anytls://%s@%s:%s?security=tls&sni=%s&fp=chrome&insecure=1#%s\n' \
        "$_enc_password" "$_host" "$_port" "$_enc_sni" "$_enc_name"
}

# ============================================================
# 配置写入 / 读取
# ============================================================
write_config() {
    mkdir -p "$ANYTLS_DIR" "$ANYTLS_META" "$ANYTLS_CERT_DIR"
    chmod 700 "$ANYTLS_META" "$ANYTLS_CERT_DIR"
    cat > "$ANYTLS_CONFIG" <<CFG
{
  "log": { "level": "info", "timestamp": true },
  "inbounds": [
    {
      "type": "anytls",
      "tag": "anytls-in",
      "listen": "${LISTEN_HOST}",
      "listen_port": ${LISTEN_PORT},
      "users": [{ "password": "${PASSWORD}" }],
      "padding_scheme": [],
      "tls": {
        "enabled": true,
        "server_name": "${SERVER_NAME}",
        "certificate_path": "${ANYTLS_CERT}",
        "key_path": "${ANYTLS_KEY}"
      }
    }
  ],
  "outbounds": [{ "type": "direct", "tag": "direct" }]
}
CFG
    chmod 600 "$ANYTLS_CONFIG"
    cat > "$ANYTLS_META/config.env" <<CFG
LISTEN_PORT=${LISTEN_PORT}
EXT_PORT=${EXT_PORT}
PASSWORD=${PASSWORD}
NAT_MODE=${NAT_MODE}
BIND_FAMILY=${BIND_FAMILY}
LISTEN_HOST=${LISTEN_HOST}
SERVER_NAME=${SERVER_NAME}
MANAGED_SING_BOX=${MANAGED_SING_BOX}
CFG
    chmod 600 "$ANYTLS_META/config.env"
    printf '%s' "$PUBLIC_IP"   > "$ANYTLS_META/public_ip"
    printf '%s' "$PUBLIC_IPV6" > "$ANYTLS_META/public_ipv6"
}

read_config() {
    [ -f "$ANYTLS_CONFIG" ] && [ -f "$ANYTLS_META/config.env" ] || return 1
    while IFS='=' read -r _key _value; do
        case "$_key" in
            LISTEN_PORT) LISTEN_PORT="$_value" ;;
            EXT_PORT) EXT_PORT="$_value" ;;
            PASSWORD) PASSWORD="$_value" ;;
            NAT_MODE) NAT_MODE="$_value" ;;
            BIND_FAMILY) BIND_FAMILY="$_value" ;;
            LISTEN_HOST) LISTEN_HOST="$_value" ;;
            SERVER_NAME) SERVER_NAME="$_value" ;;
            MANAGED_SING_BOX) MANAGED_SING_BOX="$_value" ;;
        esac
    done < "$ANYTLS_META/config.env"
    validate_port "$LISTEN_PORT" || return 1
    validate_port "$EXT_PORT" || return 1
    validate_password "$PASSWORD" || return 1
    validate_server_name "$SERVER_NAME" || return 1
    case "$NAT_MODE" in 0|1) ;; *) return 1 ;; esac
    case "$BIND_FAMILY" in v4|v6) ;; *) return 1 ;; esac
    case "$LISTEN_HOST" in 0.0.0.0|::) ;; *) LISTEN_HOST="::" ;; esac
    case "$MANAGED_SING_BOX" in 0|1) ;; *) MANAGED_SING_BOX=0 ;; esac
    [ -z "${PUBLIC_IP:-}"   ] && PUBLIC_IP=$(cat "$ANYTLS_META/public_ip"   2>/dev/null || true)
    [ -z "${PUBLIC_IPV6:-}" ] && PUBLIC_IPV6=$(cat "$ANYTLS_META/public_ipv6" 2>/dev/null || true)
    return 0
}

generate_certificate() {
    local _force="${1:-}" _tmp_dir _tmp_cert _tmp_key
    mkdir -p "$ANYTLS_CERT_DIR"
    chmod 700 "$ANYTLS_CERT_DIR"
    if [ "$_force" != "force" ] && [ -s "$ANYTLS_CERT" ] && [ -s "$ANYTLS_KEY" ]; then
        return 0
    fi
    _tmp_dir=$(mktemp -d /tmp/anytls-cert-XXXXXX) || return 1
    _tmp_cert="$_tmp_dir/cert.pem"
    _tmp_key="$_tmp_dir/private.key"
    if openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
        -subj "/CN=${SERVER_NAME}" \
        -addext "subjectAltName=DNS:${SERVER_NAME}" \
        -keyout "$_tmp_key" -out "$_tmp_cert" >/dev/null 2>&1; then
        :
    else
        rm -f "$_tmp_cert" "$_tmp_key"
        openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
            -subj "/CN=${SERVER_NAME}" \
            -keyout "$_tmp_key" -out "$_tmp_cert" >/dev/null 2>&1 || {
                rm -rf "$_tmp_dir"
                return 1
            }
    fi
    if [ ! -s "$_tmp_cert" ] || [ ! -s "$_tmp_key" ]; then
        rm -rf "$_tmp_dir"
        return 1
    fi
    mv -f "$_tmp_cert" "$ANYTLS_CERT"
    mv -f "$_tmp_key" "$ANYTLS_KEY"
    rm -rf "$_tmp_dir"
    chmod 600 "$ANYTLS_KEY" "$ANYTLS_CERT"
}

show_install_diagnostics() {
    echo -e "${YELLOW}诊断信息:${PLAIN}"
    echo "  sing-box: $SING_BOX_BIN"
    "$SING_BOX_BIN" version 2>&1 | head -1 | sed 's/^/  version : /'
    echo "  config  : $ANYTLS_CONFIG"
    echo "  cert    : $ANYTLS_CERT"
    echo "  key     : $ANYTLS_KEY"
    [ -s "$ANYTLS_CONFIG" ] || echo -e "  ${RED}配置文件缺失或为空${PLAIN}"
    [ -s "$ANYTLS_CERT" ] || echo -e "  ${RED}证书文件缺失或为空${PLAIN}"
    [ -s "$ANYTLS_KEY" ] || echo -e "  ${RED}私钥文件缺失或为空${PLAIN}"
}

write_wrapper() {
    cat > "$ANYTLS_BIN" <<WRAPPER
#!/bin/sh
exec "${SING_BOX_BIN}" run -c "${ANYTLS_CONFIG}" "\$@"
WRAPPER
    chmod 755 "$ANYTLS_BIN"
}

check_config() {
    "$SING_BOX_BIN" check -c "$ANYTLS_CONFIG"
}

backup_current_install() {
    INSTALL_BACKUP_DIR=$(mktemp -d /tmp/anytls-backup-XXXXXX) || return 1
    [ ! -f "$ANYTLS_CONFIG" ] || cp -a "$ANYTLS_CONFIG" "$INSTALL_BACKUP_DIR/config" || { discard_install_backup; return 1; }
    [ ! -d "$ANYTLS_META" ] || cp -a "$ANYTLS_META" "$INSTALL_BACKUP_DIR/meta" || { discard_install_backup; return 1; }
    [ ! -d "$ANYTLS_CERT_DIR" ] || cp -a "$ANYTLS_CERT_DIR" "$INSTALL_BACKUP_DIR/cert" || { discard_install_backup; return 1; }
    [ ! -f "$ANYTLS_BIN" ] || cp -a "$ANYTLS_BIN" "$INSTALL_BACKUP_DIR/wrapper" || { discard_install_backup; return 1; }
    [ ! -f "$SING_BOX_BIN" ] || cp -a "$SING_BOX_BIN" "$INSTALL_BACKUP_DIR/sing-box" || { discard_install_backup; return 1; }
    [ ! -f "$SYSTEMD_SERVICE" ] || cp -a "$SYSTEMD_SERVICE" "$INSTALL_BACKUP_DIR/systemd-service" || { discard_install_backup; return 1; }
    [ ! -f "$OPENRC_SERVICE" ] || cp -a "$OPENRC_SERVICE" "$INSTALL_BACKUP_DIR/openrc-service" || { discard_install_backup; return 1; }
    service_is_active && : > "$INSTALL_BACKUP_DIR/was-active" || true
    return 0
}

discard_install_backup() {
    [ -n "$INSTALL_BACKUP_DIR" ] && rm -rf "$INSTALL_BACKUP_DIR"
    INSTALL_BACKUP_DIR=""
}

restore_current_install() {
    [ -n "$INSTALL_BACKUP_DIR" ] && [ -d "$INSTALL_BACKUP_DIR" ] || return 0
    service_stop
    rm -f "$ANYTLS_CONFIG" "$ANYTLS_BIN" "$SYSTEMD_SERVICE" "$OPENRC_SERVICE"
    rm -rf "$ANYTLS_META" "$ANYTLS_CERT_DIR"

    [ -f "$INSTALL_BACKUP_DIR/config" ] && cp -a "$INSTALL_BACKUP_DIR/config" "$ANYTLS_CONFIG"
    [ -d "$INSTALL_BACKUP_DIR/meta" ] && cp -a "$INSTALL_BACKUP_DIR/meta" "$ANYTLS_META"
    [ -d "$INSTALL_BACKUP_DIR/cert" ] && cp -a "$INSTALL_BACKUP_DIR/cert" "$ANYTLS_CERT_DIR"
    [ -f "$INSTALL_BACKUP_DIR/wrapper" ] && cp -a "$INSTALL_BACKUP_DIR/wrapper" "$ANYTLS_BIN"
    if [ -f "$INSTALL_BACKUP_DIR/sing-box" ]; then
        cp -a "$INSTALL_BACKUP_DIR/sing-box" "$SING_BOX_BIN"
    elif [ "$MANAGED_SING_BOX" = "1" ]; then
        rm -f "$SING_BOX_BIN"
    fi
    [ -f "$INSTALL_BACKUP_DIR/systemd-service" ] && cp -a "$INSTALL_BACKUP_DIR/systemd-service" "$SYSTEMD_SERVICE"
    [ -f "$INSTALL_BACKUP_DIR/openrc-service" ] && cp -a "$INSTALL_BACKUP_DIR/openrc-service" "$OPENRC_SERVICE"
    [ "$INIT_SYS" = "systemd" ] && systemctl daemon-reload
    [ -f "$INSTALL_BACKUP_DIR/was-active" ] && service_start >/dev/null 2>&1 || true
    discard_install_backup
}

read_config_live() {
    read_config || return 1
    if [ -z "${PUBLIC_IP:-}" ] && [ -z "${PUBLIC_IPV6:-}" ]; then
        PUBLIC_IP=$(curl -s4 --max-time 6 https://api.ipify.org 2>/dev/null | tr -d '[:space:]') || true
        PUBLIC_IPV6=$(curl -s6 --max-time 6 https://api6.ipify.org 2>/dev/null | tr -d '[:space:]') || true
    fi
}

# ============================================================
# 服务管理
# ============================================================
write_systemd_service() {
    cat > "$SYSTEMD_SERVICE" <<SVC
[Unit]
Description=AnyTLS Server
After=network.target nss-lookup.target
Wants=network.target

[Service]
Type=simple
User=root
ExecStart=${ANYTLS_BIN}
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
SVC
    chmod 600 "$SYSTEMD_SERVICE"
}

write_openrc_service() {
    cat > "$OPENRC_SERVICE" <<'SVCHEAD'
#!/sbin/openrc-run

name="anytls-server"
description="AnyTLS Server"
SVCHEAD
    cat >> "$OPENRC_SERVICE" <<SVC
command="${ANYTLS_BIN}"
command_args=""
command_background="yes"
pidfile="/var/run/anytls-server.pid"
output_log="/var/log/anytls-server.log"
error_log="/var/log/anytls-server.log"

depend() {
    need net
    after firewall
}
SVC
    chmod +x "$OPENRC_SERVICE"
}

service_start() {
    [ -x "$ANYTLS_BIN" ] && [ -f "$ANYTLS_CONFIG" ] || {
        echo -e "${RED}AnyTLS 尚未安装或配置不完整${PLAIN}"
        return 1
    }
    service_is_active && return 0
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl start anytls-server
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service anytls-server start
    else
        nohup "$ANYTLS_BIN" >/var/log/anytls-server.log 2>&1 &
        echo $! > /var/run/anytls-server.pid
    fi
}

service_stop() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl stop anytls-server 2>/dev/null
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service anytls-server stop 2>/dev/null
    else
        if [ -f /var/run/anytls-server.pid ]; then
            kill "$(cat /var/run/anytls-server.pid)" 2>/dev/null || true
            rm -f /var/run/anytls-server.pid
        fi
    fi
}

service_restart() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl restart anytls-server
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service anytls-server restart
    else
        service_stop; sleep 1; service_start
    fi
}

service_enable() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl daemon-reload
        systemctl enable anytls-server >/dev/null 2>&1
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-update add anytls-server default >/dev/null 2>&1
    fi
}

service_disable() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl disable anytls-server 2>/dev/null
        systemctl daemon-reload
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-update del anytls-server default 2>/dev/null
    fi
}

service_is_active() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl is-active --quiet anytls-server
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service anytls-server status 2>/dev/null | grep -q "started"
    else
        [ -f /var/run/anytls-server.pid ] && kill -0 "$(cat /var/run/anytls-server.pid)" 2>/dev/null
    fi
}

service_logs() {
    if [ "$INIT_SYS" = "systemd" ]; then
        journalctl -u anytls-server -n 80 --no-pager
    else
        tail -n 80 /var/log/anytls-server.log 2>/dev/null || echo -e "${YELLOW}暂无日志${PLAIN}"
    fi
}

# ============================================================
# 安装 / 修改
# ============================================================
configure_anytls() {
    echo -e "\n${SKYBLUE}--- 配置 AnyTLS 协议 ---${PLAIN}"

    if [ "$NAT_MODE" = "1" ]; then
        read -r -p "请输入本机监听端口 [默认 38888]: " LISTEN_PORT
        [ -z "$LISTEN_PORT" ] && LISTEN_PORT="38888"
        validate_port "$LISTEN_PORT" || { echo -e "${RED}端口必须为 1-65535 的整数${PLAIN}"; return 1; }
        read -r -p "请输入对外转发端口 [留空=与监听端口相同]: " EXT_PORT
        [ -z "$EXT_PORT" ] && EXT_PORT="$LISTEN_PORT"
        validate_port "$EXT_PORT" || { echo -e "${RED}对外端口必须为 1-65535 的整数${PLAIN}"; return 1; }
        echo -e "${YELLOW}提示：请确保宿主机已将 TCP ${EXT_PORT} 转发到本机 TCP ${LISTEN_PORT}${PLAIN}"
    else
        read -r -p "请输入端口 [默认 38888]: " LISTEN_PORT
        [ -z "$LISTEN_PORT" ] && LISTEN_PORT="38888"
        validate_port "$LISTEN_PORT" || { echo -e "${RED}端口必须为 1-65535 的整数（输入值: '${LISTEN_PORT}'）${PLAIN}"; return 1; }
        EXT_PORT="$LISTEN_PORT"
        echo -e "${GREEN}端口: ${LISTEN_PORT}${PLAIN}"
    fi

    read -r -p "请设置连接密码 [留空自动生成]: " PASSWORD
    if [ -z "$PASSWORD" ]; then
        PASSWORD=$(openssl rand -base64 24 2>/dev/null | tr -d ' \n\r/+=' | cut -c1-32)
        [ -z "$PASSWORD" ] && PASSWORD=$(dd if=/dev/urandom bs=1 count=32 2>/dev/null | tr -dc 'A-Za-z0-9' | cut -c1-24)
        [ -z "$PASSWORD" ] && PASSWORD="AnyTLS$(date +%s | tail -c 8)"
        echo -e "${GREEN}自动生成密码: ${YELLOW}${PASSWORD}${PLAIN}"
    fi
    validate_password "$PASSWORD" || { echo -e "${RED}密码包含非法字符（实际值: ${PASSWORD}）${PLAIN}"; return 1; }

    local _default_sni
    _default_sni=$(random_sni)
    read -r -p "请输入 TLS 域名/SNI [随机默认 ${_default_sni}]: " SERVER_NAME
    [ -z "$SERVER_NAME" ] && SERVER_NAME="$_default_sni"
    validate_server_name "$SERVER_NAME" || { echo -e "${RED}SNI 域名格式无效${PLAIN}"; return 1; }

    NODE_NAME="AnyTLS-$(hostname 2>/dev/null | tr -d '\n\r')"
    [ "$NODE_NAME" = "AnyTLS-" ] && NODE_NAME="AnyTLS-Node"
    return 0
}

install_anytls() {
    install_dependencies || { read -r -p "按回车键返回主菜单..." _; return; }
    detect_network
    backup_current_install || { echo -e "${RED}无法创建安装备份，已取消操作${PLAIN}"; read -r -p "按回车键返回主菜单..." _; return; }
    ensure_anytls_bin || { restore_current_install; read -r -p "按回车键返回主菜单..." _; return; }
    configure_anytls || { restore_current_install; read -r -p "按回车键返回主菜单..." _; return; }
    echo -e "${YELLOW}正在生成 TLS 证书...${PLAIN}"
    generate_certificate force || {
        echo -e "${RED}生成 TLS 证书失败${PLAIN}"
        show_install_diagnostics
        restore_current_install
        read -r -p "按回车键返回主菜单..." _
        return
    }
    echo -e "${GREEN}✓ TLS 证书生成完成${PLAIN}"
    write_config
    write_wrapper
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
        write_systemd_service
    elif [ "$INIT_SYS" = "openrc" ]; then
        write_openrc_service
    fi

    service_enable
    open_ports "$LISTEN_PORT"
    echo -e "${YELLOW}正在启动 AnyTLS 服务...${PLAIN}"
    if service_is_active; then service_restart; else service_start; fi

    sleep 2
    if service_is_active; then
        echo -e "${GREEN}✓ AnyTLS 服务端启动成功${PLAIN}"
    else
        echo -e "${RED}✗ AnyTLS 启动失败，请查看日志：${PLAIN}"
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
    if [ ! -f "$ANYTLS_CONFIG" ]; then
        echo -e "${RED}未安装 AnyTLS${PLAIN}"; sleep 2; return
    fi
    read_config || { echo -e "${RED}AnyTLS 配置或元数据损坏，无法安全修改${PLAIN}"; sleep 2; return; }
    local _old_sni="$SERVER_NAME" _old_port="$LISTEN_PORT" _was_active=0
    service_is_active && _was_active=1 || true
    detect_network

    echo -e "\n${YELLOW}修改 AnyTLS 配置，留空则保留原值。${PLAIN}"
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

    read -r -p "连接密码 [留空保留原密码]: " _pass
    if [ -n "$_pass" ]; then
        validate_password "$_pass" || { echo -e "${RED}密码包含非法字符${PLAIN}"; sleep 2; return; }
        PASSWORD="$_pass"
    fi

    read -r -p "TLS 域名/SNI [当前 ${SERVER_NAME}]: " _sni
    if [ -n "$_sni" ]; then
        validate_server_name "$_sni" || { echo -e "${RED}SNI 域名格式无效${PLAIN}"; sleep 2; return; }
        SERVER_NAME="$_sni"
    fi

    cp "$ANYTLS_CONFIG" "${ANYTLS_CONFIG}.bak" 2>/dev/null || true
    cp "$ANYTLS_META/config.env" "$ANYTLS_META/config.env.bak" 2>/dev/null || true
    cp "$ANYTLS_CERT" "${ANYTLS_CERT}.bak" 2>/dev/null || true
    cp "$ANYTLS_KEY" "${ANYTLS_KEY}.bak" 2>/dev/null || true

    if [ "$SERVER_NAME" != "$_old_sni" ]; then
        if ! generate_certificate force; then
            mv -f "${ANYTLS_CERT}.bak" "$ANYTLS_CERT" 2>/dev/null || true
            mv -f "${ANYTLS_KEY}.bak" "$ANYTLS_KEY" 2>/dev/null || true
            rm -f "${ANYTLS_CONFIG}.bak" "$ANYTLS_META/config.env.bak"
            echo -e "${RED}生成 TLS 证书失败${PLAIN}"
            return
        fi
    fi

    write_config
    if ! check_config; then
        mv -f "${ANYTLS_CONFIG}.bak" "$ANYTLS_CONFIG" 2>/dev/null || true
        mv -f "$ANYTLS_META/config.env.bak" "$ANYTLS_META/config.env" 2>/dev/null || true
        mv -f "${ANYTLS_CERT}.bak" "$ANYTLS_CERT" 2>/dev/null || true
        mv -f "${ANYTLS_KEY}.bak" "$ANYTLS_KEY" 2>/dev/null || true
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
    if [ "$_was_active" = "1" ] && ! service_is_active; then
        mv -f "${ANYTLS_CONFIG}.bak" "$ANYTLS_CONFIG" 2>/dev/null || true
        mv -f "$ANYTLS_META/config.env.bak" "$ANYTLS_META/config.env" 2>/dev/null || true
        mv -f "${ANYTLS_CERT}.bak" "$ANYTLS_CERT" 2>/dev/null || true
        mv -f "${ANYTLS_KEY}.bak" "$ANYTLS_KEY" 2>/dev/null || true
        read_config || true
        service_restart || true
        echo -e "${RED}服务重启失败，配置已回滚，请查看日志${PLAIN}"
        service_logs
        return
    fi
    [ "$_old_port" != "$LISTEN_PORT" ] && close_ports "$_old_port"
    rm -f "${ANYTLS_CONFIG}.bak" "$ANYTLS_META/config.env.bak" "${ANYTLS_CERT}.bak" "${ANYTLS_KEY}.bak"
    show_config
}

# ============================================================
# 展示单个节点（IPv4 或 IPv6）
# $1=IP  $2=Port  $3=标签(v4/v6)
# ============================================================
render_singbox_client_config() {
    local _server="$1" _port="$2" _password="$3" _tag="$4" _sni="$5"
    cat <<CFG
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "127.0.0.1",
      "listen_port": 2080
    }
  ],
  "outbounds": [
    {
      "type": "anytls",
      "tag": "${_tag}",
      "server": "${_server}",
      "server_port": ${_port},
      "password": "${_password}",
      "tls": {
        "enabled": true,
        "server_name": "${_sni}",
        "insecure": true,
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        }
      }
    }
  ]
}
CFG
}

show_node() {
    local _server="$1" _port="$2" _tag="$3"
    [ -z "$_server" ] && return
    validate_server_address "$_server" || {
        echo -e "${RED}节点地址格式无效: ${_server}${PLAIN}"
        return 1
    }

    local _date _node _uri _enc_uri _qr_url _yaml_password
    _date=$(date +%m%d)
    _node="AnyTLS-${_tag}-${_date}"

    _uri=$(render_uri "$_server" "$_port" "$PASSWORD" "$_node" "$SERVER_NAME")
    _enc_uri=$(uri_encode "$_uri")
    _qr_url="https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=${_enc_uri}"
    _yaml_password=$(printf '%s' "$PASSWORD" | sed "s/'/''/g")

    # ---- 分享链接 ----
    echo -e "${GREEN} 分享链接 (NekoBox / v2rayN / Shadowrocket):${PLAIN}"
    echo -e "  ${_uri}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    # ---- 终端二维码（优先）----
    if command -v qrencode >/dev/null 2>&1; then
        echo -e "${GREEN} 扫码导入（终端二维码）:${PLAIN}"
        qrencode -t ANSIUTF8 -m 2 "${_uri}"
        echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    fi

    # ---- 二维码图片链接（备用）----
    echo -e "${GREEN} 二维码图片链接（无法扫描时用浏览器打开）:${PLAIN}"
    echo -e "  ${_qr_url}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    # ---- Mihomo / Clash Meta / Clash Verge ----
    echo -e "${GREEN} Mihomo / Clash Meta / Clash Verge 配置:${PLAIN}"
    echo -e "  - {name: '${_node}', type: anytls, server: '${_server}', port: ${_port}, password: '${_yaml_password}', client-fingerprint: chrome, udp: true, sni: '${SERVER_NAME}', skip-cert-verify: true}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    # ---- sing-box ----
    echo -e "${GREEN} sing-box 完整客户端配置（本地 SOCKS/HTTP: 127.0.0.1:2080）:${PLAIN}"
    render_singbox_client_config "$_server" "$_port" "$PASSWORD" "$_node" "$SERVER_NAME" | sed 's/^/  /'
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
}

show_config() {
    read_config_live || { echo -e "${RED}未找到 AnyTLS 配置${PLAIN}"; sleep 2; return; }

    echo -e "\n${GREEN}AnyTLS 配置详情${PLAIN}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    [ -n "$PUBLIC_IP"   ] && echo -e "  ${BOLD}IPv4地址${PLAIN}: ${YELLOW}${PUBLIC_IP}${PLAIN}"
    [ -n "$PUBLIC_IPV6" ] && echo -e "  ${BOLD}IPv6地址${PLAIN}: ${YELLOW}${PUBLIC_IPV6}${PLAIN}"
    if [ "$NAT_MODE" = "1" ] && [ "$EXT_PORT" != "$LISTEN_PORT" ]; then
        echo -e "  ${BOLD}监听端口${PLAIN}: ${YELLOW}${LISTEN_PORT}${PLAIN}  ${RED}← 本机监听${PLAIN}"
        echo -e "  ${BOLD}对外端口${PLAIN}: ${YELLOW}${EXT_PORT}${PLAIN}  ${RED}← 客户端连接此端口${PLAIN}"
    else
        echo -e "  ${BOLD}端口Port${PLAIN}: ${YELLOW}${EXT_PORT}${PLAIN}"
    fi
    echo -e "  ${BOLD}密码Pass${PLAIN}: ${YELLOW}${PASSWORD}${PLAIN}"
    echo -e "  ${BOLD}伪装 SNI${PLAIN}: ${YELLOW}${SERVER_NAME}${PLAIN}"
    echo -e "  ${BOLD}自签证书${PLAIN}: ${RED}Insecure / Skip Cert Verify = True${PLAIN}"
    [ "$NAT_MODE" = "1" ] && echo -e "  ${BOLD}机器类型${PLAIN}: ${YELLOW}NAT 机器${PLAIN}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    if [ -n "$PUBLIC_IP" ]; then
        echo -e "${YELLOW}▼ IPv4 节点配置${PLAIN}"
        show_node "$PUBLIC_IP" "$EXT_PORT" "v4"
    fi
    if [ -n "$PUBLIC_IPV6" ]; then
        echo -e "${YELLOW}▼ IPv6 节点配置${PLAIN}"
        show_node "$PUBLIC_IPV6" "$EXT_PORT" "v6"
    fi

    if [ -z "$PUBLIC_IP" ] && [ -z "$PUBLIC_IPV6" ]; then
        read -r -p "未检测到公网 IP，请手动输入节点地址: " _manual_addr
        if [ -n "$_manual_addr" ]; then
            echo -e "${YELLOW}▼ 手动地址节点配置${PLAIN}"
            show_node "$_manual_addr" "$EXT_PORT" "manual"
        fi
    fi

    read -r -p "按回车键返回主菜单..." _tmp
}

# ============================================================
# 升级 / 卸载 / 工具
# ============================================================
upgrade_core() {
    [ -f "$ANYTLS_CONFIG" ] && [ -x "$SING_BOX_BIN" ] || {
        echo -e "${RED}AnyTLS 尚未安装，请先执行安装${PLAIN}"
        return 1
    }
    read_config || { echo -e "${RED}AnyTLS 元数据不完整，无法安全升级${PLAIN}"; return 1; }
    get_latest_version || return 1

    local _current_version _latest_version _was_active=0 _was_managed="$MANAGED_SING_BOX"
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
    if ! download_anytls; then
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
        service_restart
        sleep 2
        if ! service_is_active; then
            mv -f "${SING_BOX_BIN}.bak" "$SING_BOX_BIN" 2>/dev/null || true
            service_restart || true
            echo -e "${RED}升级后服务启动失败，已回滚${PLAIN}"
            return 1
        fi
    fi
    rm -f "${SING_BOX_BIN}.bak"
    echo -e "${GREEN}✓ sing-box 已从 ${_current_version:-未知版本} 升级到 ${_latest_version}${PLAIN}"
    return 0
}

upgrade_anytls() {
    install_dependencies || { read -r -p "按回车键返回主菜单..." _; return; }
    upgrade_core || true
    sleep 2
}

uninstall_anytls() {
    echo -e "${RED}警告：这将删除 AnyTLS 服务、配置和定时更新。${PLAIN}"
    read -r -p "确认卸载 AnyTLS？[y/N]: " _confirm
    case "$_confirm" in
        [yY]) ;;
        *) echo "已取消。"; sleep 1; return ;;
    esac

    read_config 2>/dev/null || true
    service_stop
    service_disable
    close_ports "${LISTEN_PORT:-}"
    if command -v crontab >/dev/null 2>&1; then
        crontab -l 2>/dev/null | grep -vF "$AUTO_UPDATE_SCRIPT" | crontab - 2>/dev/null || true
    fi
    rm -f "$SYSTEMD_SERVICE" "$OPENRC_SERVICE" "$AUTO_UPDATE_SCRIPT" "$ANYTLS_BIN"
    rm -f "$ANYTLS_CONFIG" "$AUTO_UPDATE_LOG"
    rm -rf "$ANYTLS_META" "$ANYTLS_CERT_DIR"
    if [ ! -d "$ANYTLS_DIR" ] || rmdir "$ANYTLS_DIR" 2>/dev/null; then
        [ "$MANAGED_SING_BOX" = "1" ] && rm -f "$SING_BOX_BIN"
    elif [ "$MANAGED_SING_BOX" = "1" ]; then
        echo -e "${YELLOW}检测到 /etc/sing-box 中还有其他文件，已保留共享 sing-box 二进制${PLAIN}"
    fi
    rm -f /var/run/anytls-server.pid
    [ "$INIT_SYS" = "systemd" ] && systemctl daemon-reload
    echo -e "${GREEN}✓ AnyTLS 已卸载${PLAIN}"
    sleep 2
}

setup_auto_update() {
    cat > "$AUTO_UPDATE_SCRIPT" <<'AUTOUPDATE_EOF'
#!/bin/bash
LOG_FILE=/var/log/anytls-autoupdate.log
TMP_SCRIPT=$(mktemp /tmp/anytls-update-XXXXXX.sh) || exit 1
trap 'rm -f "$TMP_SCRIPT"' EXIT INT TERM
{
  echo "[$(date '+%F %T')] 开始检查 sing-box 更新"
  curl -fsSL --connect-timeout 15 --max-time 60 \
    https://raw.githubusercontent.com/everett7623/hy2/main/anytls.sh -o "$TMP_SCRIPT" || exit 1
  bash -n "$TMP_SCRIPT" || exit 1
  bash "$TMP_SCRIPT" --upgrade-noninteractive
  echo "[$(date '+%F %T')] 更新检查完成"
} >> "$LOG_FILE" 2>&1
AUTOUPDATE_EOF
    chmod +x "$AUTO_UPDATE_SCRIPT"

    if command -v crontab >/dev/null 2>&1; then
        (crontab -l 2>/dev/null | grep -v "$AUTO_UPDATE_SCRIPT"; echo "17 4 * * 1 $AUTO_UPDATE_SCRIPT") | crontab -
        echo -e "${GREEN}✓ 已设置每周一 04:17 自动检查 sing-box 更新${PLAIN}"
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
    echo -e "${GREEN}✓ 已移除 AnyTLS 自动更新任务${PLAIN}"
    sleep 2
}

diagnose_anytls() {
    echo -e "\n${GREEN}AnyTLS 运行诊断${PLAIN}"
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
    if [ -s "$ANYTLS_CERT" ] && openssl x509 -in "$ANYTLS_CERT" -noout -checkend 86400 >/dev/null 2>&1; then
        echo -e "  ${GREEN}✓ TLS 证书有效${PLAIN}"
    else
        echo -e "  ${RED}✗ TLS 证书缺失、损坏或即将过期${PLAIN}"
    fi
    if service_is_active; then
        echo -e "  ${GREEN}✓ AnyTLS 服务运行中${PLAIN}"
    else
        echo -e "  ${RED}✗ AnyTLS 服务未运行${PLAIN}"
    fi
    if command -v ss >/dev/null 2>&1 && ss -lnt 2>/dev/null | awk '{print $4}' | grep -qE "(^|:|\])${LISTEN_PORT}$"; then
        echo -e "  ${GREEN}✓ TCP ${LISTEN_PORT} 正在监听${PLAIN}"
    else
        echo -e "  ${YELLOW}! 未检测到 TCP ${LISTEN_PORT} 监听${PLAIN}"
    fi
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
        clear
        local _auto_status="${RED}未启用${PLAIN}"
        if command -v crontab >/dev/null 2>&1 && crontab -l 2>/dev/null | grep -qF "$AUTO_UPDATE_SCRIPT"; then
            _auto_status="${GREEN}已启用${PLAIN}"
        fi
        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e "${GREEN}  AnyTLS 工具箱${PLAIN}"
        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e " 自动更新: ${_auto_status}"
        echo -e "${SKYBLUE}───────────────────────────────────────────────${PLAIN}"
        echo -e " 1. 查看系统信息"
        echo -e " 2. 查看 AnyTLS 日志"
        echo -e " 3. 运行状态诊断"
        echo -e " 4. 设置每周自动更新"
        echo -e " 5. 移除自动更新"
        echo -e " 0. 返回"
        read -r -p "请输入选项 [0-5]: " choice
        case "$choice" in
            1) show_system_info ;;
            2) service_logs; read -r -p "按回车返回..." _tmp ;;
            3) diagnose_anytls; read -r -p "按回车返回..." _tmp ;;
            4) setup_auto_update ;;
            5) remove_auto_update ;;
            0|q|quit|exit) return ;;
            *) echo -e "${RED}无效选项${PLAIN}"; sleep 1 ;;
        esac
    done
}

manage_anytls() {
    if [ ! -f "$ANYTLS_CONFIG" ] || [ ! -x "$ANYTLS_BIN" ]; then
        echo -e "${RED}AnyTLS 尚未安装，请先执行安装${PLAIN}"
        sleep 2
        return
    fi
    while true; do
        clear
        local STATUS
        service_is_active && STATUS="${GREEN}运行中${PLAIN}" || STATUS="${RED}已停止${PLAIN}"

        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e "${GREEN}  AnyTLS 服务管理${PLAIN}"
        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e " 当前状态: ${STATUS}"
        echo -e " 1. 启动"
        echo -e " 2. 停止"
        echo -e " 3. 重启"
        echo -e " 4. 查看日志"
        echo -e " 5. 修改配置"
        echo -e " 0. 返回"
        read -r -p "请输入选项 [0-5]: " choice
        case "$choice" in
            1)
                if service_start && sleep 1 && service_is_active; then
                    echo -e "${GREEN}✓ AnyTLS 已启动${PLAIN}"
                else
                    echo -e "${RED}✗ 启动失败，请查看日志${PLAIN}"
                fi
                sleep 1
                ;;
            2)
                service_stop
                sleep 1
                service_is_active && echo -e "${RED}✗ 服务仍在运行${PLAIN}" || echo -e "${GREEN}✓ AnyTLS 已停止${PLAIN}"
                sleep 1
                ;;
            3)
                if service_restart && sleep 1 && service_is_active; then
                    echo -e "${GREEN}✓ AnyTLS 已重启${PLAIN}"
                else
                    echo -e "${RED}✗ 重启失败，请查看日志${PLAIN}"
                fi
                sleep 1
                ;;
            4) service_logs; read -r -p "按回车返回..." _tmp ;;
            5) change_config ;;
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
        clear
        local STATUS _ver_line
        if [ -f "$ANYTLS_CONFIG" ] && [ -x "$ANYTLS_BIN" ] && [ -x "$SING_BOX_BIN" ]; then
            service_is_active && STATUS="${GREEN}运行中${PLAIN}" || STATUS="${RED}已停止${PLAIN}"
        elif [ -e "$ANYTLS_CONFIG" ] || [ -e "$ANYTLS_BIN" ]; then
            STATUS="${YELLOW}安装不完整${PLAIN}"
        else
            STATUS="${RED}未安装${PLAIN}"
        fi
        _ver_line=""
        if [ -x "$SING_BOX_BIN" ]; then
            _ver_line=" ($(get_installed_version))"
        fi

        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e "${GREEN}  AnyTLS Management Script v1.0.3${PLAIN}"
        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e " 项目地址: ${YELLOW}https://github.com/everett7623/hy2${PLAIN}"
        echo -e " 作者    : ${YELLOW}Jensfrank${PLAIN}"
        echo -e " 实现    : ${YELLOW}sing-box 原生 AnyTLS 入站${PLAIN}"
        echo -e "${SKYBLUE}───────────────────────────────────────────────${PLAIN}"
        echo -e " Seedloc博客 : https://seedloc.com"
        echo -e " VPSknow网站 : https://vpsknow.com"
        echo -e " Nodeloc论坛 : https://nodeloc.com"
        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e " 当前状态: $STATUS${_ver_line}"
        echo -e "${SKYBLUE}───────────────────────────────────────────────${PLAIN}"
        echo -e " 1. 安装 / 重装 AnyTLS"
        echo -e " 2. 查看节点信息 / 链接"
        echo -e " 3. 管理 AnyTLS（启动 / 停止 / 重启 / 日志 / 修改）"
        echo -e " 4. 升级 sing-box"
        echo -e " 5. 卸载 AnyTLS"
        echo -e " 6. 服务器工具"
        echo -e " 0. 退出"
        echo -e "${SKYBLUE}===============================================${PLAIN}"

        read -r -p "请输入选项 [0-6]: " choice
        case "$choice" in
            1) install_anytls ;;
            2) show_config ;;
            3) manage_anytls ;;
            4) upgrade_anytls ;;
            5) uninstall_anytls ;;
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
# 入口（ANYTLS_LIB_ONLY=1 时跳过）
# ============================================================
[ "$_ANYTLS_LIB_ONLY" = "1" ] && return 0

check_root
check_sys
detect_init
main_menu
