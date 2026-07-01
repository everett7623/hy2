#!/bin/bash
#====================================================================================
# 项目：AnyTLS Management Script (sing-box core)
# 作者：Jensfrank
# 版本：v1.0.0
# GitHub: https://github.com/everett7623/hy2
# Seedloc博客: https://seedloc.com
# VPSknow网站：https://vpsknow.com
# Nodeloc论坛: https://nodeloc.com
# 更新日期: 2026-07-01
#
# 支持系统: Debian / Ubuntu / CentOS / Rocky / Alma / Fedora / Arch / Alpine
# 支持环境: 标准 VPS / NAT 机器 / IPv6 单栈 / 双栈机器
# 实现方式: 不修改 sing-box 框架，直接使用 sing-box 原生 anytls inbound
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

# --- 颜色 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
SKYBLUE='\033[0;36m'
PLAIN='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'

# --- 路径 ---
SB_BIN="/usr/local/bin/sing-box"
ANYTLS_WRAPPER="/usr/local/bin/anytls-server"
SB_CONFIG_DIR="/etc/sing-box"
ANYTLS_CONFIG="/etc/sing-box/anytls.json"
ANYTLS_META="/etc/sing-box/anytls-meta"
ANYTLS_CERT_DIR="/etc/sing-box/anytls-cert"
SERVICE_FILE="/etc/systemd/system/anytls-server.service"
OPENRC_SERVICE="/etc/init.d/anytls-server"
AUTO_UPDATE_SCRIPT="/usr/local/bin/anytls-autoupdate.sh"
AUTO_UPDATE_LOG="/var/log/anytls-autoupdate.log"

# --- 运行时变量 ---
RELEASE="unknown"
INIT_SYS="none"
NAT_MODE=0
IPV6_ONLY=0
HAS_IPV4=0
HAS_IPV6=0
PUBLIC_IP=""
PUBLIC_IPV6=""
LISTEN_PORT=""
EXT_PORT=""
PASSWORD=""
USER_NAME="anytls"
SNI="www.microsoft.com"
TLS_MODE="self"
TLS_INSECURE="true"
CERT_PATH=""
KEY_PATH=""
NODE_NAME=""
LAST_VERSION=""
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
            apk add --no-cache bash curl wget ca-certificates openssl tar gzip iproute2 procps >/dev/null 2>&1
            apk add --no-cache libqrencode >/dev/null 2>&1 || true
            ;;
        centos)
            yum install -y curl wget ca-certificates openssl tar gzip iproute procps-ng >/dev/null 2>&1
            yum install -y qrencode >/dev/null 2>&1 || true
            ;;
        fedora|rocky)
            dnf install -y curl wget ca-certificates openssl tar gzip iproute procps-ng >/dev/null 2>&1
            dnf install -y qrencode >/dev/null 2>&1 || true
            ;;
        arch)
            pacman -Sy --noconfirm curl wget ca-certificates openssl tar gzip iproute2 procps-ng >/dev/null 2>&1
            pacman -S --noconfirm qrencode >/dev/null 2>&1 || true
            ;;
        *)
            if command -v apt-get >/dev/null 2>&1; then
                apt-get update -qq >/dev/null 2>&1
                apt-get install -y -qq curl wget ca-certificates openssl tar gzip iproute2 procps >/dev/null 2>&1
                apt-get install -y -qq qrencode >/dev/null 2>&1 || true
            else
                echo -e "${RED}无法识别包管理器，请手动安装 curl、wget、openssl、tar、iproute2${PLAIN}"
                return 1
            fi
            ;;
    esac

    local _missing=0 _cmd
    for _cmd in curl wget openssl tar; do
        if ! command -v "$_cmd" >/dev/null 2>&1; then
            echo -e "${RED}致命错误: 缺少组件 [ $_cmd ]${PLAIN}"
            _missing=1
        fi
    done
    [ "$_missing" -eq 1 ] && return 1
}

valid_port() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

valid_json_secret() {
    ! echo "$1" | grep -qE '["\\]|[[:cntrl:]]'
}

uri_encode() {
    local _in="$1" _out="" _i _c _hex
    if command -v python3 >/dev/null 2>&1; then
        printf '%s' "$_in" | python3 -c "import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read(), safe=''), end='')" 2>/dev/null && return
    fi
    for ((_i=0; _i<${#_in}; _i++)); do
        _c="${_in:$_i:1}"
        case "$_c" in
            [a-zA-Z0-9.~_-]) _out="${_out}${_c}" ;;
            *) _hex=$(printf '%s' "$_c" | od -An -tx1 | awk '{ for (i=1; i<=NF; i++) printf "%%%s", toupper($i) }'); _out="${_out}${_hex}" ;;
        esac
    done
    printf '%s' "$_out"
}

# ============================================================
# 服务管理
# ============================================================
service_start() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl start anytls-server
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service anytls-server start
    else
        nohup "$SB_BIN" run -c "$ANYTLS_CONFIG" >/var/log/anytls-server.log 2>&1 &
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
        pkill -f "sing-box run -c ${ANYTLS_CONFIG}" 2>/dev/null
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

setup_systemd_service() {
    cat > "$SERVICE_FILE" <<SVC
[Unit]
Description=AnyTLS Server (sing-box)
After=network.target nss-lookup.target
Wants=network.target

[Service]
Type=simple
User=root
ExecStart=${SB_BIN} run -c ${ANYTLS_CONFIG}
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
SVC
}

setup_openrc_service() {
    cat > "$OPENRC_SERVICE" <<'SVCHEAD'
#!/sbin/openrc-run

name="anytls-server"
description="AnyTLS Server (sing-box)"
SVCHEAD
    cat >> "$OPENRC_SERVICE" <<SVC
command="${SB_BIN}"
command_args="run -c ${ANYTLS_CONFIG}"
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

write_wrapper() {
    cat > "$ANYTLS_WRAPPER" <<WRAP
#!/bin/sh
exec ${SB_BIN} run -c ${ANYTLS_CONFIG} "\$@"
WRAP
    chmod +x "$ANYTLS_WRAPPER"
}

# ============================================================
# 网络检测 / 防火墙
# ============================================================
detect_network() {
    echo -e "${YELLOW}正在检测网络环境...${PLAIN}"
    NAT_MODE=0; IPV6_ONLY=0; HAS_IPV4=0; HAS_IPV6=0; PUBLIC_IP=""; PUBLIC_IPV6=""
    local _ip _url

    for _url in "https://api6.ipify.org" "https://ipv6.icanhazip.com"; do
        _ip=$(curl -s6 --max-time 6 "$_url" 2>/dev/null | tr -d '[:space:]')
        if echo "$_ip" | grep -q ':'; then PUBLIC_IPV6="$_ip"; HAS_IPV6=1; break; fi
    done

    for _url in "https://api.ipify.org" "https://ip.gs" "https://ipv4.icanhazip.com"; do
        _ip=$(curl -s4 --connect-timeout 3 --max-time 6 "$_url" 2>/dev/null | tr -d '[:space:]')
        if echo "$_ip" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then PUBLIC_IP="$_ip"; HAS_IPV4=1; break; fi
    done

    # 过滤 WARP / 隧道虚拟 IPv4，避免把出站 IP 当作入站地址
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

    [ "$HAS_IPV4" = "0" ] && [ "$HAS_IPV6" = "1" ] && IPV6_ONLY=1

    if   [ "$NAT_MODE"  = "1" ]; then echo -e "  机器类型: ${YELLOW}NAT 机器${PLAIN}（公网 IPv4: ${PUBLIC_IP}）"
    elif [ "$IPV6_ONLY" = "1" ]; then echo -e "  机器类型: ${YELLOW}纯 IPv6${PLAIN}（IPv6: ${PUBLIC_IPV6}）"
    elif [ "$HAS_IPV6"  = "1" ]; then echo -e "  机器类型: ${GREEN}双栈${PLAIN}（IPv6: ${PUBLIC_IPV6} | IPv4: ${PUBLIC_IP}）"
    elif [ "$HAS_IPV4"  = "1" ]; then echo -e "  机器类型: ${GREEN}标准 IPv4${PLAIN}（IP: ${PUBLIC_IP}）"
    else                               echo -e "  机器类型: ${RED}无法检测，请手动输入节点地址${PLAIN}"
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
# sing-box 获取 / 安装
# ============================================================
get_latest_version() {
    echo -e "${YELLOW}正在获取 sing-box 最新版本...${PLAIN}"
    LAST_VERSION_TAG=$(curl -Ls --max-time 12 "https://api.github.com/repos/SagerNet/sing-box/releases/latest" \
        | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' | head -1)

    if [ -z "$LAST_VERSION_TAG" ]; then
        LAST_VERSION_TAG=$(curl -Ls --max-time 12 -o /dev/null -w "%{url_effective}" \
            "https://github.com/SagerNet/sing-box/releases/latest" | sed 's|.*/tag/||')
    fi

    [ -z "$LAST_VERSION_TAG" ] && echo -e "${RED}获取版本失败，请检查网络${PLAIN}" && return 1
    LAST_VERSION="${LAST_VERSION_TAG#v}"
    echo -e "${GREEN}最新版本: ${LAST_VERSION_TAG}${PLAIN}"
}

download_singbox() {
    local _arch
    case $(uname -m) in
        x86_64)          _arch="amd64" ;;
        aarch64|arm64)   _arch="arm64" ;;
        armv7l|armv7)    _arch="armv7" ;;
        armv6l|armv6)    _arch="armv6" ;;
        s390x)           _arch="s390x" ;;
        loongarch64)     _arch="loong64" ;;
        *) echo -e "${RED}不支持的架构: $(uname -m)${PLAIN}" && return 1 ;;
    esac

    local _asset="sing-box-${LAST_VERSION}-linux-${_arch}.tar.gz"
    local _url="https://github.com/SagerNet/sing-box/releases/download/${LAST_VERSION_TAG}/${_asset}"
    local _tmp_archive _tmp_dir
    _tmp_archive=$(mktemp /tmp/sing-box-XXXXXX.tar.gz) || return 1
    _tmp_dir=$(mktemp -d /tmp/sing-box-XXXXXX) || { rm -f "$_tmp_archive"; return 1; }

    echo -e "${YELLOW}正在下载 ${_asset}...${PLAIN}"
    if ! wget -q --show-progress --timeout=30 -O "$_tmp_archive" "$_url" 2>/dev/null; then
        if ! curl -fL --connect-timeout 20 --max-time 90 -o "$_tmp_archive" "$_url" 2>/dev/null; then
            rm -rf "$_tmp_archive" "$_tmp_dir"
            echo -e "${RED}下载失败: ${_url}${PLAIN}"
            return 1
        fi
    fi

    tar -xzf "$_tmp_archive" -C "$_tmp_dir" >/dev/null 2>&1 || {
        rm -rf "$_tmp_archive" "$_tmp_dir"
        echo -e "${RED}解压失败，下载文件可能无效${PLAIN}"
        return 1
    }

    local _bin
    _bin=$(find "$_tmp_dir" -type f -name sing-box | head -1)
    [ -z "$_bin" ] && { rm -rf "$_tmp_archive" "$_tmp_dir"; echo -e "${RED}未找到 sing-box 二进制${PLAIN}"; return 1; }

    chmod +x "$_bin"
    if ! "$_bin" version >/dev/null 2>&1; then
        rm -rf "$_tmp_archive" "$_tmp_dir"
        echo -e "${RED}sing-box 二进制验证失败${PLAIN}"
        return 1
    fi

    mv -f "$_bin" "$SB_BIN"
    chmod +x "$SB_BIN"
    rm -rf "$_tmp_archive" "$_tmp_dir"
    echo -e "${GREEN}sing-box 安装完成: $($SB_BIN version 2>/dev/null | head -1)${PLAIN}"
}

ensure_singbox() {
    if [ -x "$SB_BIN" ]; then
        return 0
    fi
    if command -v sing-box >/dev/null 2>&1; then
        local _found
        _found=$(command -v sing-box)
        if [ "$_found" != "$SB_BIN" ]; then
            ln -sf "$_found" "$SB_BIN" 2>/dev/null || cp -f "$_found" "$SB_BIN"
        fi
        [ -x "$SB_BIN" ] && return 0
    fi

    get_latest_version || return 1
    download_singbox || return 1
}

# ============================================================
# 配置写入 / 读取
# ============================================================
generate_self_signed_cert() {
    mkdir -p "$ANYTLS_CERT_DIR"
    CERT_PATH="${ANYTLS_CERT_DIR}/cert.pem"
    KEY_PATH="${ANYTLS_CERT_DIR}/key.pem"

    echo -e "${YELLOW}正在生成自签 TLS 证书...${PLAIN}"
    if echo "$SNI" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
        openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
            -keyout "$KEY_PATH" -out "$CERT_PATH" \
            -subj "/CN=${SNI}" -addext "subjectAltName=IP:${SNI}" >/dev/null 2>&1
    else
        openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
            -keyout "$KEY_PATH" -out "$CERT_PATH" \
            -subj "/CN=${SNI}" -addext "subjectAltName=DNS:${SNI}" >/dev/null 2>&1
    fi

    chmod 600 "$KEY_PATH" 2>/dev/null
    [ -s "$CERT_PATH" ] && [ -s "$KEY_PATH" ] || { echo -e "${RED}证书生成失败${PLAIN}"; return 1; }
}

write_config() {
    mkdir -p "$SB_CONFIG_DIR" "$ANYTLS_META"
    local _listen="0.0.0.0"
    [ "$HAS_IPV6" = "1" ] && _listen="::"

    cat > "$ANYTLS_CONFIG" <<JSON
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "anytls",
      "tag": "anytls-in",
      "listen": "${_listen}",
      "listen_port": ${LISTEN_PORT},
      "users": [
        {
          "name": "${USER_NAME}",
          "password": "${PASSWORD}"
        }
      ],
      "padding_scheme": [
        "stop=8",
        "0=30-30",
        "1=100-400",
        "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000",
        "3=9-9,500-1000",
        "4=500-1000",
        "5=500-1000",
        "6=500-1000",
        "7=500-1000"
      ],
      "tls": {
        "enabled": true,
        "server_name": "${SNI}",
        "certificate_path": "${CERT_PATH}",
        "key_path": "${KEY_PATH}",
        "min_version": "1.2",
        "alpn": [
          "h2",
          "http/1.1"
        ]
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "route": {
    "final": "direct"
  }
}
JSON
}

save_meta() {
    mkdir -p "$ANYTLS_META"
    printf '%s' "$NAT_MODE"     > "$ANYTLS_META/nat_mode"
    printf '%s' "$LISTEN_PORT"  > "$ANYTLS_META/listen_port"
    printf '%s' "$EXT_PORT"     > "$ANYTLS_META/ext_port"
    printf '%s' "$PASSWORD"     > "$ANYTLS_META/password"
    printf '%s' "$USER_NAME"    > "$ANYTLS_META/user_name"
    printf '%s' "$SNI"          > "$ANYTLS_META/sni"
    printf '%s' "$TLS_MODE"     > "$ANYTLS_META/tls_mode"
    printf '%s' "$TLS_INSECURE" > "$ANYTLS_META/tls_insecure"
    printf '%s' "$CERT_PATH"    > "$ANYTLS_META/cert_path"
    printf '%s' "$KEY_PATH"     > "$ANYTLS_META/key_path"
    printf '%s' "$PUBLIC_IP"    > "$ANYTLS_META/public_ip"
    printf '%s' "$PUBLIC_IPV6"  > "$ANYTLS_META/public_ipv6"
}

read_config_vars() {
    [ ! -f "$ANYTLS_CONFIG" ] && return 1

    if [ -d "$ANYTLS_META" ]; then
        NAT_MODE=$(cat "$ANYTLS_META/nat_mode" 2>/dev/null); NAT_MODE=${NAT_MODE:-0}
        LISTEN_PORT=$(cat "$ANYTLS_META/listen_port" 2>/dev/null)
        EXT_PORT=$(cat "$ANYTLS_META/ext_port" 2>/dev/null)
        PASSWORD=$(cat "$ANYTLS_META/password" 2>/dev/null)
        USER_NAME=$(cat "$ANYTLS_META/user_name" 2>/dev/null)
        SNI=$(cat "$ANYTLS_META/sni" 2>/dev/null)
        TLS_MODE=$(cat "$ANYTLS_META/tls_mode" 2>/dev/null)
        TLS_INSECURE=$(cat "$ANYTLS_META/tls_insecure" 2>/dev/null)
        CERT_PATH=$(cat "$ANYTLS_META/cert_path" 2>/dev/null)
        KEY_PATH=$(cat "$ANYTLS_META/key_path" 2>/dev/null)
        PUBLIC_IP=$(cat "$ANYTLS_META/public_ip" 2>/dev/null)
        PUBLIC_IPV6=$(cat "$ANYTLS_META/public_ipv6" 2>/dev/null)
    fi

    [ -z "$LISTEN_PORT" ] && LISTEN_PORT=$(grep '"listen_port"' "$ANYTLS_CONFIG" | grep -oE '[0-9]+' | head -1)
    [ -z "$EXT_PORT" ] && EXT_PORT="$LISTEN_PORT"
    [ -z "$PASSWORD" ] && PASSWORD=$(grep -A4 '"users"' "$ANYTLS_CONFIG" | grep '"password"' | awk -F'"' '{print $4}' | head -1)
    [ -z "$USER_NAME" ] && USER_NAME="anytls"
    [ -z "$SNI" ] && SNI=$(grep '"server_name"' "$ANYTLS_CONFIG" | awk -F'"' '{print $4}' | head -1)
    [ -z "$TLS_INSECURE" ] && TLS_INSECURE="true"

    if [ -z "$PUBLIC_IP" ] && [ -z "$PUBLIC_IPV6" ]; then
        PUBLIC_IP=$(curl -s4 --max-time 6 https://api.ipify.org 2>/dev/null | tr -d '[:space:]')
        PUBLIC_IPV6=$(curl -s6 --max-time 6 https://api6.ipify.org 2>/dev/null | tr -d '[:space:]')
    fi
}

# ============================================================
# 安装 / 修改
# ============================================================
configure_anytls() {
    echo -e "\n${SKYBLUE}--- 配置 AnyTLS 协议 ---${PLAIN}"

    if [ "$NAT_MODE" = "1" ]; then
        read -r -p "请输入本机监听端口 [默认 38888]: " LISTEN_PORT
        [[ -z "$LISTEN_PORT" ]] && LISTEN_PORT="38888"
        valid_port "$LISTEN_PORT" || { echo -e "${RED}端口必须为 1-65535 的整数${PLAIN}"; return 1; }
        read -r -p "请输入对外转发端口 [留空=与监听端口相同]: " EXT_PORT
        [[ -z "$EXT_PORT" ]] && EXT_PORT="$LISTEN_PORT"
        valid_port "$EXT_PORT" || { echo -e "${RED}对外端口必须为 1-65535 的整数${PLAIN}"; return 1; }
        echo -e "${YELLOW}提示：请确保宿主机已将 TCP ${EXT_PORT} 转发到本机 TCP ${LISTEN_PORT}${PLAIN}"
    else
        read -r -p "请输入端口 [默认 38888]: " LISTEN_PORT
        [[ -z "$LISTEN_PORT" ]] && LISTEN_PORT="38888"
        valid_port "$LISTEN_PORT" || { echo -e "${RED}端口必须为 1-65535 的整数${PLAIN}"; return 1; }
        EXT_PORT="$LISTEN_PORT"
    fi

    read -r -p "请输入用户名 [默认 anytls]: " USER_NAME
    [[ -z "$USER_NAME" ]] && USER_NAME="anytls"
    valid_json_secret "$USER_NAME" || { echo -e "${RED}用户名不能包含双引号、反斜杠或控制字符${PLAIN}"; return 1; }

    read -r -p "请设置连接密码 [留空自动生成]: " PASSWORD
    [[ -z "$PASSWORD" ]] && PASSWORD=$(openssl rand -base64 24 | tr -d ' \n\r')
    valid_json_secret "$PASSWORD" || { echo -e "${RED}密码不能包含双引号、反斜杠或控制字符${PLAIN}"; return 1; }

    read -r -p "请输入 SNI / 证书域名 [默认 www.microsoft.com]: " SNI
    [[ -z "$SNI" ]] && SNI="www.microsoft.com"
    valid_json_secret "$SNI" || { echo -e "${RED}SNI 不能包含双引号、反斜杠或控制字符${PLAIN}"; return 1; }

    echo ""
    echo -e "${YELLOW}请选择 TLS 证书方式：${PLAIN}"
    echo -e " 1. 自签证书（默认，客户端需 insecure/skip-cert-verify=true）"
    echo -e " 2. 已有真实证书（推荐域名节点，客户端可关闭 insecure）"
    read -r -p "请输入选项 [1/2，默认 1]: " _tls_choice

    if [ "$_tls_choice" = "2" ]; then
        TLS_MODE="custom"
        TLS_INSECURE="false"
        read -r -p "请输入证书 fullchain 路径: " CERT_PATH
        read -r -p "请输入私钥 private key 路径: " KEY_PATH
        [ -s "$CERT_PATH" ] || { echo -e "${RED}证书文件不存在或为空${PLAIN}"; return 1; }
        [ -s "$KEY_PATH" ] || { echo -e "${RED}私钥文件不存在或为空${PLAIN}"; return 1; }
    else
        TLS_MODE="self"
        TLS_INSECURE="true"
        generate_self_signed_cert || return 1
    fi

    NODE_NAME="AnyTLS-$(hostname 2>/dev/null | tr -d '\n\r')"
    [ "$NODE_NAME" = "AnyTLS-" ] && NODE_NAME="AnyTLS-Node"
}

install_anytls() {
    install_dependencies || return
    detect_network
    ensure_singbox || return
    configure_anytls || return
    write_config

    if ! "$SB_BIN" check -c "$ANYTLS_CONFIG" >/tmp/anytls-check.log 2>&1; then
        echo -e "${RED}sing-box 配置检查失败：${PLAIN}"
        cat /tmp/anytls-check.log
        read -r -p "按回车键返回主菜单..." _tmp
        return
    fi

    save_meta
    write_wrapper
    open_ports "$LISTEN_PORT"

    if   [ "$INIT_SYS" = "systemd" ]; then setup_systemd_service
    elif [ "$INIT_SYS" = "openrc"  ]; then setup_openrc_service
    fi

    service_enable
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
        echo -e "${RED}未安装 AnyTLS${PLAIN}"
        sleep 2
        return
    fi
    read_config_vars
    detect_network

    echo -e "\n${YELLOW}修改 AnyTLS 配置，留空则保留原值。${PLAIN}"
    read -r -p "监听端口 [当前 ${LISTEN_PORT}]: " _port
    if [ -n "$_port" ]; then valid_port "$_port" || { echo -e "${RED}端口无效${PLAIN}"; sleep 2; return; }; LISTEN_PORT="$_port"; fi

    read -r -p "对外端口 [当前 ${EXT_PORT:-$LISTEN_PORT}]: " _ext
    if [ -n "$_ext" ]; then valid_port "$_ext" || { echo -e "${RED}端口无效${PLAIN}"; sleep 2; return; }; EXT_PORT="$_ext"; fi
    [ -z "$EXT_PORT" ] && EXT_PORT="$LISTEN_PORT"

    read -r -p "用户名 [当前 ${USER_NAME}]: " _user
    [ -n "$_user" ] && USER_NAME="$_user"
    valid_json_secret "$USER_NAME" || { echo -e "${RED}用户名不能包含特殊字符${PLAIN}"; sleep 2; return; }

    read -r -p "连接密码 [当前已隐藏，留空保留]: " _pass
    [ -n "$_pass" ] && PASSWORD="$_pass"
    valid_json_secret "$PASSWORD" || { echo -e "${RED}密码不能包含特殊字符${PLAIN}"; sleep 2; return; }

    read -r -p "SNI / 证书域名 [当前 ${SNI}]: " _sni
    [ -n "$_sni" ] && SNI="$_sni"
    valid_json_secret "$SNI" || { echo -e "${RED}SNI 不能包含特殊字符${PLAIN}"; sleep 2; return; }

    echo ""
    echo -e "${YELLOW}证书方式：${PLAIN}"
    echo -e " 1. 保持当前证书"
    echo -e " 2. 重新生成自签证书"
    echo -e " 3. 改用已有真实证书"
    read -r -p "请输入选项 [1/2/3，默认 1]: " _cert_choice
    case "$_cert_choice" in
        2) TLS_MODE="self"; TLS_INSECURE="true"; generate_self_signed_cert || return ;;
        3)
            TLS_MODE="custom"; TLS_INSECURE="false"
            read -r -p "请输入证书 fullchain 路径: " CERT_PATH
            read -r -p "请输入私钥 private key 路径: " KEY_PATH
            [ -s "$CERT_PATH" ] || { echo -e "${RED}证书文件不存在或为空${PLAIN}"; sleep 2; return; }
            [ -s "$KEY_PATH" ] || { echo -e "${RED}私钥文件不存在或为空${PLAIN}"; sleep 2; return; }
            ;;
    esac

    write_config
    if ! "$SB_BIN" check -c "$ANYTLS_CONFIG" >/tmp/anytls-check.log 2>&1; then
        echo -e "${RED}配置检查失败：${PLAIN}"
        cat /tmp/anytls-check.log
        read -r -p "按回车键返回..." _tmp
        return
    fi

    save_meta
    write_wrapper
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

    local _display_server="$_server"
    echo "$_server" | grep -q ':' && _display_server="[${_server}]"

    local _date _node _insecure_yaml _insecure_json _singbox_client _mihomo_yaml _surfboard _link _encoded _qr_url
    _date=$(date +%m%d)
    _node="AnyTLS-${_tag}-${_date}"
    _insecure_yaml="false"
    _insecure_json="false"
    if [ "$TLS_INSECURE" = "true" ]; then
        _insecure_yaml="true"
        _insecure_json="true"
    fi

    _singbox_client=$(cat <<JSON
{
  "type": "anytls",
  "tag": "${_node}",
  "server": "${_server}",
  "server_port": ${_port},
  "password": "${PASSWORD}",
  "idle_session_check_interval": "30s",
  "idle_session_timeout": "30s",
  "min_idle_session": 5,
  "tls": {
    "enabled": true,
    "server_name": "${SNI}",
    "insecure": ${_insecure_json}
  }
}
JSON
)

    _mihomo_yaml="  - {name: '${_node}', type: anytls, server: '${_server}', port: ${_port}, password: '${PASSWORD}', sni: '${SNI}', skip-cert-verify: ${_insecure_yaml}}"
    _surfboard="${_node} = anytls, ${_server}, ${_port}, ${PASSWORD}, ${_insecure_yaml}, ${SNI}, , true"
    _link="anytls://${PASSWORD}@${_display_server}:${_port}?sni=${SNI}&insecure=${_insecure_yaml}#${_node}"
    _encoded=$(uri_encode "$_link")
    _qr_url="https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=${_encoded}"

    echo -e "\n${GREEN}${_node}${PLAIN}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    echo -e "${BOLD}地址${PLAIN}: ${YELLOW}${_server}${PLAIN}"
    echo -e "${BOLD}端口${PLAIN}: ${YELLOW}${_port}${PLAIN}"
    echo -e "${BOLD}SNI ${PLAIN}: ${YELLOW}${SNI}${PLAIN}"
    echo -e "${BOLD}TLS ${PLAIN}: ${YELLOW}$([ "$TLS_INSECURE" = "true" ] && echo "自签证书 / skip-cert-verify=true" || echo "真实证书 / skip-cert-verify=false")${PLAIN}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    echo -e "${GREEN}sing-box outbound 配置:${PLAIN}"
    echo "$_singbox_client"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    echo -e "${GREEN}Mihomo / Clash Meta 参考配置:${PLAIN}"
    echo "$_mihomo_yaml"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    echo -e "${GREEN}Surfboard 参考配置:${PLAIN}"
    echo "$_surfboard"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    echo -e "${GREEN}实验性 anytls:// 分享链接（不同客户端支持不一致）:${PLAIN}"
    echo "  $_link"
    if command -v qrencode >/dev/null 2>&1; then
        echo -e "${GREEN}扫码导入（终端二维码，仅当客户端支持 anytls:// 时有效）:${PLAIN}"
        qrencode -t ANSIUTF8 -m 2 "$_link"
    fi
    echo -e "${GREEN}二维码图片链接:${PLAIN}"
    echo "  $_qr_url"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
}

show_config() {
    read_config_vars || { echo -e "${RED}未找到 AnyTLS 配置${PLAIN}"; sleep 2; return; }

    echo -e "\n${GREEN}AnyTLS 配置详情${PLAIN}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    echo -e "  ${BOLD}核心${PLAIN}: $($SB_BIN version 2>/dev/null | head -1)"
    echo -e "  ${BOLD}配置${PLAIN}: ${ANYTLS_CONFIG}"
    echo -e "  ${BOLD}监听端口${PLAIN}: ${LISTEN_PORT}"
    echo -e "  ${BOLD}对外端口${PLAIN}: ${EXT_PORT}"
    echo -e "  ${BOLD}用户名${PLAIN}: ${USER_NAME}"
    echo -e "  ${BOLD}密码${PLAIN}: ${PASSWORD}"
    echo -e "  ${BOLD}SNI${PLAIN}: ${SNI}"
    echo -e "  ${BOLD}证书${PLAIN}: ${CERT_PATH}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    [ -n "$PUBLIC_IP" ] && _show_node "$PUBLIC_IP" "$EXT_PORT" "IPv4"
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
    ensure_singbox || return
    get_latest_version || return
    download_singbox || return
    write_wrapper
    if [ -f "$ANYTLS_CONFIG" ] && ! "$SB_BIN" check -c "$ANYTLS_CONFIG" >/tmp/anytls-check.log 2>&1; then
        echo -e "${RED}升级后配置检查失败：${PLAIN}"
        cat /tmp/anytls-check.log
        read -r -p "按回车返回..." _tmp
        return
    fi
    service_restart
    echo -e "${GREEN}✓ sing-box / AnyTLS 已升级并重启${PLAIN}"
    sleep 2
}

uninstall_anytls() {
    echo -e "${RED}警告：这将删除 AnyTLS 服务、配置、证书和 meta。${PLAIN}"
    echo -e "${YELLOW}默认不会删除 sing-box 二进制，避免影响你其他 sing-box 服务。${PLAIN}"
    read -r -p "确认卸载 AnyTLS？[y/N]: " _confirm
    [[ ! "$_confirm" =~ ^[yY]$ ]] && echo "已取消。" && sleep 1 && return

    service_stop
    service_disable
    rm -f "$SERVICE_FILE" "$OPENRC_SERVICE" "$ANYTLS_WRAPPER" "$AUTO_UPDATE_SCRIPT"
    rm -f /var/run/anytls-server.pid
    rm -rf "$ANYTLS_CONFIG" "$ANYTLS_META" "$ANYTLS_CERT_DIR"
    [ "$INIT_SYS" = "systemd" ] && systemctl daemon-reload
    echo -e "${GREEN}✓ AnyTLS 已卸载${PLAIN}"
    sleep 2
}

setup_auto_update() {
    cat > "$AUTO_UPDATE_SCRIPT" <<AUTO
#!/bin/bash
LOG_FILE="${AUTO_UPDATE_LOG}"
echo "[\$(date '+%F %T')] start anytls sing-box update" >> "\$LOG_FILE"
bash "$0" --upgrade-noninteractive >> "\$LOG_FILE" 2>&1
AUTO
    chmod +x "$AUTO_UPDATE_SCRIPT"

    if command -v crontab >/dev/null 2>&1; then
        (crontab -l 2>/dev/null | grep -v "$AUTO_UPDATE_SCRIPT"; echo "17 4 * * 1 $AUTO_UPDATE_SCRIPT") | crontab -
        echo -e "${GREEN}✓ 已设置每周一 04:17 自动升级 sing-box 核心${PLAIN}"
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
    command -v "$SB_BIN" >/dev/null 2>&1 && echo -e " 核心  : $($SB_BIN version 2>/dev/null | head -1)"
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
        echo -e " 3. 检查 sing-box 配置"
        echo -e " 4. 设置每周自动升级 sing-box"
        echo -e " 0. 返回"
        read -r -p "请输入选项 [0-4]: " choice
        case "$choice" in
            1) show_system_info ;;
            2) service_logs; read -r -p "按回车返回..." _tmp ;;
            3)
                if [ -f "$ANYTLS_CONFIG" ]; then
                    "$SB_BIN" check -c "$ANYTLS_CONFIG"
                else
                    echo -e "${RED}未找到配置${PLAIN}"
                fi
                read -r -p "按回车返回..." _tmp
                ;;
            4) setup_auto_update ;;
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
        if [ -x "$SB_BIN" ]; then
            _ver_line=" ($($SB_BIN version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1))"
        fi

        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e "${GREEN}  AnyTLS Management Script v1.0.0${PLAIN}"
        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e " 项目地址: ${YELLOW}https://github.com/everett7623/hy2${PLAIN}"
        echo -e " 作者    : ${YELLOW}Jensfrank${PLAIN}"
        echo -e " 实现    : ${YELLOW}sing-box 原生 AnyTLS inbound${PLAIN}"
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
        echo -e " 4. 升级 sing-box 核心"
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
    download_singbox || exit 1
    write_wrapper
    [ -f "$ANYTLS_CONFIG" ] && "$SB_BIN" check -c "$ANYTLS_CONFIG" || exit 1
    service_restart
    exit 0
fi

# ============================================================
# 入口
# ============================================================
check_root
check_sys
detect_init
main_menu
