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
# 实现方式: 使用 anytls/anytls-go 官方发布包，不依赖 sing-box
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

[ ! -t 0 ] && [ -c /dev/tty ] && exec < /dev/tty

if [ -f "$0" ] && grep -q $'\r' "$0" 2>/dev/null; then
    sed -i 's/\r$//' "$0"
    exec bash "$0" "$@"
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
ANYTLS_DIR="${ANYTLS_DIR:-/etc/anytls}"
ANYTLS_CONFIG="${ANYTLS_CONFIG:-${ANYTLS_DIR}/config.env}"
ANYTLS_META="${ANYTLS_META:-${ANYTLS_DIR}/meta}"
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
LISTEN_PORT=""
EXT_PORT=""
PASSWORD=""
NODE_NAME=""
LAST_VERSION_TAG=""


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
            apk update -q >/dev/null 2>&1
            apk add --no-cache bash curl wget ca-certificates unzip iproute2 procps >/dev/null 2>&1
            apk add --no-cache libqrencode >/dev/null 2>&1 || true
            ;;
        centos)
            yum install -y curl wget ca-certificates unzip iproute procps-ng >/dev/null 2>&1
            yum install -y qrencode >/dev/null 2>&1 || true
            ;;
        fedora|rocky)
            dnf install -y curl wget ca-certificates unzip iproute procps-ng >/dev/null 2>&1
            dnf install -y qrencode >/dev/null 2>&1 || true
            ;;
        arch)
            pacman -Sy --noconfirm curl wget ca-certificates unzip iproute2 procps-ng >/dev/null 2>&1
            pacman -S --noconfirm qrencode >/dev/null 2>&1 || true
            ;;
        *)
            if command -v apt-get >/dev/null 2>&1; then
                apt-get update -qq >/dev/null 2>&1
                apt-get install -y -qq curl wget ca-certificates unzip iproute2 procps >/dev/null 2>&1
                apt-get install -y -qq qrencode >/dev/null 2>&1 || true
            else
                echo -e "${RED}无法识别包管理器，请手动安装 curl、wget、unzip、iproute2${PLAIN}"
                return 1
            fi
            ;;
    esac

    local _missing=0 _cmd
    for _cmd in curl wget unzip; do
        if ! command -v "$_cmd" >/dev/null 2>&1; then
            echo -e "${RED}致命错误: 缺少组件 [ $_cmd ]${PLAIN}"
            _missing=1
        fi
    done
    [ "$_missing" -eq 1 ] && return 1
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
    awk -v p="$port" 'BEGIN { exit (p >= 1 && p <= 65535) ? 0 : 1 }'
}

validate_password() {
    local pw="$1"
    local len
    len=$(printf '%s' "$pw" | awk '{ print length }')
    [ "$len" -lt 1 ] && return 1
    [ "$len" -gt 128 ] && return 1
    printf '%s' "$pw" | awk '
    {
        if (index($0, "\"") > 0) { exit 1 }
        if (index($0, "\\") > 0) { exit 1 }
        if (index($0, "$")  > 0) { exit 1 }
        if (index($0, "`")  > 0) { exit 1 }
        if (match($0, /[[:cntrl:]]/)) { exit 1 }
        exit 0
    }' || return 1
    return 0
}

# ============================================================
# 架构 / URL 构建
# ============================================================
detect_arch() {
    local _machine="${1:-$(uname -m)}"
    case "$_machine" in
        x86_64)        echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
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
        amd64|arm64|s390x) ;;
        *) echo -e "${RED}不支持的架构: ${_arch}${PLAIN}" >&2; return 1 ;;
    esac
    local _ver="${_tag#v}"
    printf 'https://github.com/anytls/anytls-go/releases/download/%s/anytls_%s_linux_%s.zip\n' \
        "$_tag" "$_ver" "$_arch"
}

# ============================================================
# 网络检测
# ============================================================
detect_network() {
    echo -e "${YELLOW}正在检测网络环境...${PLAIN}"
    NAT_MODE=0; HAS_IPV4=0; HAS_IPV6=0; PUBLIC_IP=""; PUBLIC_IPV6=""; BIND_FAMILY="v4"
    local _ip _url

    for _url in "https://api6.ipify.org" "https://ipv6.icanhazip.com"; do
        _ip=$(curl -s6 --max-time 6 "$_url" 2>/dev/null | tr -d '[:space:]')
        if echo "$_ip" | grep -q ':'; then PUBLIC_IPV6="$_ip"; HAS_IPV6=1; break; fi
    done

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
    echo -e "${YELLOW}正在获取 anytls-go 最新版本...${PLAIN}"
    LAST_VERSION_TAG=$(curl -Ls --max-time 12 "https://api.github.com/repos/anytls/anytls-go/releases/latest" \
        | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' | head -1)

    if [ -z "$LAST_VERSION_TAG" ]; then
        LAST_VERSION_TAG=$(curl -Ls --max-time 12 -o /dev/null -w "%{url_effective}" \
            "https://github.com/anytls/anytls-go/releases/latest" | sed 's|.*/tag/||')
    fi

    [ -z "$LAST_VERSION_TAG" ] && echo -e "${RED}获取版本失败，请检查网络${PLAIN}" && return 1
    echo -e "${GREEN}最新版本: ${LAST_VERSION_TAG}${PLAIN}"
}

download_anytls() {
    local _arch
    _arch=$(detect_arch) || return 1

    local _ver="${LAST_VERSION_TAG#v}"
    local _asset="anytls_${_ver}_linux_${_arch}.zip"
    local _gh_path="anytls/anytls-go/releases/download/${LAST_VERSION_TAG}/${_asset}"
    local _urls=(
        "https://github.com/${_gh_path}"
        "https://ghproxy.com/https://github.com/${_gh_path}"
        "https://kkgithub.com/${_gh_path}"
        "https://gh.api.99988866.xyz/https://github.com/${_gh_path}"
    )

    local _tmp_zip _tmp_dir _ok=0 _url _host
    _tmp_zip=$(mktemp /tmp/anytls-XXXXXX.zip) || return 1
    _tmp_dir=$(mktemp -d /tmp/anytls-XXXXXX) || { rm -f "$_tmp_zip"; return 1; }

    for _url in "${_urls[@]}"; do
        _host=$(echo "$_url" | awk -F/ '{print $3}')
        echo -e "${YELLOW}正在下载 ${_asset}（来源: ${_host}）${PLAIN}"
        if wget -q --show-progress --timeout=60 -O "$_tmp_zip" "$_url" 2>/dev/null; then
            _ok=1; break
        elif curl -fL --connect-timeout 15 --max-time 120 -o "$_tmp_zip" "$_url" 2>/dev/null; then
            _ok=1; break
        fi
        echo -e "${YELLOW}  ↳ 失败，尝试下一个镜像...${PLAIN}"
    done

    if [ "$_ok" = "0" ]; then
        rm -rf "$_tmp_zip" "$_tmp_dir"
        echo -e "${RED}所有下载源均失败，请检查网络后重试${PLAIN}"
        return 1
    fi

    unzip -q "$_tmp_zip" -d "$_tmp_dir" 2>/dev/null || {
        rm -rf "$_tmp_zip" "$_tmp_dir"
        echo -e "${RED}解压失败，下载文件可能损坏，请重试${PLAIN}"
        return 1
    }

    local _bin
    _bin=$(find "$_tmp_dir" -type f -name "anytls-server" | head -1)
    [ -z "$_bin" ] && _bin=$(find "$_tmp_dir" -type f -name "anytls" | head -1)
    if [ -z "$_bin" ]; then
        rm -rf "$_tmp_zip" "$_tmp_dir"
        echo -e "${RED}未在压缩包中找到 anytls-server 二进制${PLAIN}"
        return 1
    fi

    chmod +x "$_bin"
    if ! validate_elf "$_bin"; then
        rm -rf "$_tmp_zip" "$_tmp_dir"
        echo -e "${RED}二进制 ELF 校验失败（文件损坏或架构不匹配）${PLAIN}"
        return 1
    fi

    mv -f "$_bin" "$ANYTLS_BIN"
    chmod +x "$ANYTLS_BIN"
    rm -rf "$_tmp_zip" "$_tmp_dir"
    echo -e "${GREEN}anytls-server 安装完成: $("$ANYTLS_BIN" version 2>/dev/null | head -1)${PLAIN}"
}

ensure_anytls_bin() {
    if [ -x "$ANYTLS_BIN" ]; then
        return 0
    fi
    get_latest_version || return 1
    download_anytls || return 1
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
    if command -v python3 >/dev/null 2>&1; then
        printf '%s' "$_in" | python3 -c "import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read(), safe=''), end='')" 2>/dev/null && return
    fi
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
    local _server="$1" _port="$2" _password="$3" _name="$4"
    local _host="$_server"
    echo "$_server" | grep -q ':' && _host="[${_server}]"
    local _enc_name
    _enc_name=$(uri_encode "$_name")
    printf 'anytls://%s@%s:%s/?insecure=1#%s\n' "$_password" "$_host" "$_port" "$_enc_name"
}

# ============================================================
# 配置写入 / 读取
# ============================================================
write_config() {
    mkdir -p "$ANYTLS_DIR" "$ANYTLS_META"
    cat > "$ANYTLS_CONFIG" <<CFG
LISTEN_PORT=${LISTEN_PORT}
EXT_PORT=${EXT_PORT}
PASSWORD=${PASSWORD}
NAT_MODE=${NAT_MODE}
BIND_FAMILY=${BIND_FAMILY}
CFG
    printf '%s' "$PUBLIC_IP"   > "$ANYTLS_META/public_ip"
    printf '%s' "$PUBLIC_IPV6" > "$ANYTLS_META/public_ipv6"
}

read_config() {
    [ -f "$ANYTLS_CONFIG" ] || return 1
    # shellcheck source=/dev/null
    . "$ANYTLS_CONFIG"
    [ -z "${PUBLIC_IP:-}"   ] && PUBLIC_IP=$(cat "$ANYTLS_META/public_ip"   2>/dev/null || true)
    [ -z "${PUBLIC_IPV6:-}" ] && PUBLIC_IPV6=$(cat "$ANYTLS_META/public_ipv6" 2>/dev/null || true)
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
    local _listen
    _listen=$(listen_address)
    cat > "$SYSTEMD_SERVICE" <<SVC
[Unit]
Description=AnyTLS Server
After=network.target nss-lookup.target
Wants=network.target

[Service]
Type=simple
User=root
ExecStart=${ANYTLS_BIN} -l ${_listen} -p ${PASSWORD}
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
command_args="-l $(listen_address) -p ${PASSWORD}"
command_background=true
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
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl start anytls-server
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service anytls-server start
    else
        local _listen
        _listen=$(listen_address)
        nohup "$ANYTLS_BIN" -l "$_listen" -p "$PASSWORD" >/var/log/anytls-server.log 2>&1 &
        echo $! > /var/run/anytls-server.pid
    fi
}

service_stop() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl stop anytls-server 2>/dev/null
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service anytls-server stop 2>/dev/null
    else
        [ -f /var/run/anytls-server.pid ] && kill "$(cat /var/run/anytls-server.pid)" 2>/dev/null && rm -f /var/run/anytls-server.pid
        pkill -f "anytls-server" 2>/dev/null || true
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
        validate_port "$LISTEN_PORT" || { echo -e "${RED}端口必须为 1-65535 的整数${PLAIN}"; return 1; }
        EXT_PORT="$LISTEN_PORT"
    fi

    read -r -p "请设置连接密码 [留空自动生成]: " PASSWORD
    [ -z "$PASSWORD" ] && PASSWORD=$(openssl rand -base64 24 | tr -d ' \n\r/+=' | cut -c1-32)
    validate_password "$PASSWORD" || { echo -e "${RED}密码包含非法字符${PLAIN}"; return 1; }

    NODE_NAME="AnyTLS-$(hostname 2>/dev/null | tr -d '\n\r')"
    [ "$NODE_NAME" = "AnyTLS-" ] && NODE_NAME="AnyTLS-Node"
}

install_anytls() {
    install_dependencies || return
    detect_network
    ensure_anytls_bin || return
    configure_anytls || return
    write_config

    if [ "$INIT_SYS" = "systemd" ]; then
        write_systemd_service
    elif [ "$INIT_SYS" = "openrc" ]; then
        write_openrc_service
    fi

    service_enable
    open_ports "$LISTEN_PORT"
    if service_is_active; then service_restart; else service_start; fi

    sleep 2
    if service_is_active; then
        echo -e "${GREEN}✓ AnyTLS 服务端启动成功${PLAIN}"
    else
        echo -e "${RED}✗ AnyTLS 启动失败，请查看日志：${PLAIN}"
        service_logs
        read -r -p "按回车键返回主菜单..." _tmp
        return
    fi

    show_config
}

change_config() {
    if [ ! -f "$ANYTLS_CONFIG" ]; then
        echo -e "${RED}未安装 AnyTLS${PLAIN}"; sleep 2; return
    fi
    read_config
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

    write_config

    if [ "$INIT_SYS" = "systemd" ]; then
        write_systemd_service
    elif [ "$INIT_SYS" = "openrc" ]; then
        write_openrc_service
    fi

    open_ports "$LISTEN_PORT"
    service_restart
    sleep 1
    show_config
}

# ============================================================
# 节点输出
# ============================================================
_show_node() {
    local _server="$1" _port="$2" _tag="$3"
    [ -z "$_server" ] && return

    local _date _node _uri
    _date=$(date +%m%d)
    _node="AnyTLS-${_tag}-${_date}"

    _uri=$(render_uri "$_server" "$_port" "$PASSWORD" "$_node")

    local _display_server="$_server"
    echo "$_server" | grep -q ':' && _display_server="[${_server}]"

    echo -e "\n${GREEN}${_node}${PLAIN}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    echo -e "${BOLD}地址${PLAIN}: ${YELLOW}${_server}${PLAIN}"
    echo -e "${BOLD}端口${PLAIN}: ${YELLOW}${_port}${PLAIN}"
    echo -e "${BOLD}密码${PLAIN}: ${YELLOW}${PASSWORD}${PLAIN}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    echo -e "${GREEN}分享链接:${PLAIN}"
    echo "  $_uri"
    if command -v qrencode >/dev/null 2>&1; then
        echo -e "${GREEN}终端二维码:${PLAIN}"
        qrencode -t ANSIUTF8 -m 2 "$_uri"
    fi
    echo -e "${GREEN}二维码图片链接:${PLAIN}"
    local _enc_uri
    _enc_uri=$(uri_encode "$_uri")
    echo "  https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=${_enc_uri}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
}

show_config() {
    read_config_live || { echo -e "${RED}未找到 AnyTLS 配置${PLAIN}"; sleep 2; return; }

    echo -e "\n${GREEN}AnyTLS 配置详情${PLAIN}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    echo -e "  ${BOLD}配置${PLAIN}: ${ANYTLS_CONFIG}"
    echo -e "  ${BOLD}监听端口${PLAIN}: ${LISTEN_PORT}"
    echo -e "  ${BOLD}对外端口${PLAIN}: ${EXT_PORT}"
    echo -e "  ${BOLD}密码${PLAIN}: ${PASSWORD}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    [ -n "$PUBLIC_IP"   ] && _show_node "$PUBLIC_IP"   "$EXT_PORT" "IPv4"
    [ -n "$PUBLIC_IPV6" ] && _show_node "$PUBLIC_IPV6" "$EXT_PORT" "IPv6"

    if [ -z "$PUBLIC_IP" ] && [ -z "$PUBLIC_IPV6" ]; then
        read -r -p "未检测到公网 IP，请手动输入节点地址: " _manual_addr
        [ -n "$_manual_addr" ] && _show_node "$_manual_addr" "$EXT_PORT" "Manual"
    fi

    read -r -p "按回车键返回主菜单..." _tmp
}

# ============================================================
# 升级 / 卸载 / 工具
# ============================================================
upgrade_anytls() {
    install_dependencies || return
    get_latest_version || return
    download_anytls || return
    if service_is_active; then service_restart; fi
    echo -e "${GREEN}✓ anytls-server 已升级${PLAIN}"
    sleep 2
}

uninstall_anytls() {
    echo -e "${RED}警告：这将删除 AnyTLS 服务、配置和二进制。${PLAIN}"
    read -r -p "确认卸载 AnyTLS？[y/N]: " _confirm
    case "$_confirm" in
        [yY]) ;;
        *) echo "已取消。"; sleep 1; return ;;
    esac

    service_stop
    service_disable
    rm -f "$SYSTEMD_SERVICE" "$OPENRC_SERVICE" "$AUTO_UPDATE_SCRIPT" "$ANYTLS_BIN"
    rm -f /var/run/anytls-server.pid
    rm -rf "$ANYTLS_DIR"
    [ "$INIT_SYS" = "systemd" ] && systemctl daemon-reload
    echo -e "${GREEN}✓ AnyTLS 已卸载${PLAIN}"
    sleep 2
}

setup_auto_update() {
    cat > "$AUTO_UPDATE_SCRIPT" <<'AUTOUPDATE_EOF'
#!/bin/bash
LOG_FILE=/var/log/anytls-autoupdate.log
echo "[$(date '+%F %T')] start anytls-go update" >> "$LOG_FILE"
SCRIPT_PATH=$(realpath "$0" 2>/dev/null || echo "$0")
ANYTLS_SCRIPT=/usr/local/bin/anytls-autoupdate.sh
bash "$ANYTLS_SCRIPT" --upgrade-noninteractive >> "$LOG_FILE" 2>&1 || true
AUTOUPDATE_EOF
    chmod +x "$AUTO_UPDATE_SCRIPT"

    if command -v crontab >/dev/null 2>&1; then
        (crontab -l 2>/dev/null | grep -v "$AUTO_UPDATE_SCRIPT"; echo "17 4 * * 1 $AUTO_UPDATE_SCRIPT") | crontab -
        echo -e "${GREEN}✓ 已设置每周一 04:17 自动升级 anytls-server${PLAIN}"
    else
        echo -e "${YELLOW}系统未安装 crontab，请手动安装 cron 后再设置自动升级${PLAIN}"
    fi
    sleep 2
}

show_system_info() {
    echo -e "\n${GREEN}系统信息${PLAIN}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    echo -e " 主机名: $(hostname 2>/dev/null)"
    echo -e " 内核  : $(uname -r)"
    echo -e " 架构  : $(uname -m)"
    command -v "$ANYTLS_BIN" >/dev/null 2>&1 && echo -e " 核心  : $("$ANYTLS_BIN" version 2>/dev/null | head -1)"
    echo -e " 内存  : $(awk '/MemAvailable/ {printf "%.0f MB available", $2/1024}' /proc/meminfo 2>/dev/null)"
    echo -e " 磁盘  : $(df -h / 2>/dev/null | awk 'NR==2 {print $3" / "$2" ("$5" used)"}')"
    echo -e " 负载  : $(uptime 2>/dev/null | awk -F'load average:' '{print $2}' | xargs)"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    read -r -p "按回车返回..." _tmp
}

server_tools_menu() {
    while true; do
        clear
        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e "${GREEN}  AnyTLS 工具箱${PLAIN}"
        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e " 1. 查看系统信息"
        echo -e " 2. 查看 AnyTLS 日志"
        echo -e " 3. 设置每周自动升级"
        echo -e " 0. 返回"
        read -r -p "请输入选项 [0-3]: " choice
        case "$choice" in
            1) show_system_info ;;
            2) service_logs; read -r -p "按回车返回..." _tmp ;;
            3) setup_auto_update ;;
            0|q|quit|exit) return ;;
            *) echo -e "${RED}无效选项${PLAIN}"; sleep 1 ;;
        esac
    done
}

manage_anytls() {
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
            1) service_start; sleep 1 ;;
            2) service_stop; sleep 1 ;;
            3) service_restart; sleep 1 ;;
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
        if [ -f "$ANYTLS_CONFIG" ]; then
            service_is_active && STATUS="${GREEN}运行中${PLAIN}" || STATUS="${RED}已停止${PLAIN}"
        else
            STATUS="${RED}未安装${PLAIN}"
        fi
        _ver_line=""
        if [ -x "$ANYTLS_BIN" ]; then
            _ver_line=" ($("$ANYTLS_BIN" version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1))"
        fi

        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e "${GREEN}  AnyTLS Management Script v1.0.3${PLAIN}"
        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e " 项目地址: ${YELLOW}https://github.com/everett7623/hy2${PLAIN}"
        echo -e " 作者    : ${YELLOW}Jensfrank${PLAIN}"
        echo -e " 实现    : ${YELLOW}anytls/anytls-go 官方二进制${PLAIN}"
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
        echo -e " 4. 升级 anytls-server"
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
    get_latest_version || exit 1
    download_anytls || exit 1
    if [ -f "$ANYTLS_CONFIG" ]; then
        read_config || true
        service_is_active && service_restart || true
    fi
    exit 0
fi

# ============================================================
# 入口（ANYTLS_LIB_ONLY=1 时跳过）
# ============================================================
[ "$_ANYTLS_LIB_ONLY" = "1" ] && return 0

check_root
check_sys
detect_init
main_menu
