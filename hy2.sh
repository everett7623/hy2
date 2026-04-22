#!/bin/bash
#====================================================================================
# 项目：Hysteria2 Management Script
# 作者：Jensfrank
# 版本：v2.1.2
# GitHub: https://github.com/everett7623/hy2
# Seedloc博客: https://seedloc.com
# VPSknow网站：https://vpsknow.com
# Nodeloc论坛: https://nodeloc.com
# 更新日期: 2026-04-22
#
# 支持系统:
#   Debian 10/11/12+
#   Ubuntu 20.04/22.04/24.04+
#   CentOS 7/8/9
#   Rocky Linux 8/9
#   AlmaLinux 8/9
#   Fedora 38+
#   Arch Linux / Manjaro
#   Alpine Linux 3.x
#
# 支持环境:
#   标准 VPS / 独立服务器
#   NAT 机器（内外端口不同）
#   IPv6 单栈 / 双栈机器
#   低配 VPS（无需 jq，低内存友好）
#====================================================================================

# ============================================================
# 自举：确保以 bash 运行（兼容 curl | sh 方式执行）
# Alpine 等系统默认 sh 为 busybox，不支持 bash 语法
# ============================================================
if [ -z "$BASH_VERSION" ]; then
    if command -v bash >/dev/null 2>&1; then
        exec bash "$0" "$@"
    else
        # bash 还没装：先用 sh 兼容方式装 bash，再重启
        if [ -f /etc/alpine-release ]; then
            apk add --no-cache bash >/dev/null 2>&1
        elif command -v apt-get >/dev/null 2>&1; then
            apt-get install -y -qq bash >/dev/null 2>&1
        elif command -v yum >/dev/null 2>&1; then
            yum install -y bash >/dev/null 2>&1
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y bash >/dev/null 2>&1
        fi
        exec bash "$0" "$@"
    fi
fi

# --- 修复交互输入 ---
if [ ! -t 0 ]; then
    [ -c /dev/tty ] && exec < /dev/tty
fi

# --- 修复 Windows 换行符 ---
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

# --- 路径 ---
HY_BIN="/usr/local/bin/hysteria"
HY_CONFIG="/etc/hysteria/config.yaml"
HY_CERT_DIR="/etc/hysteria/cert"
HY_META="/etc/hysteria/meta"
SERVICE_FILE="/etc/systemd/system/hysteria-server.service"
OPENRC_SERVICE="/etc/init.d/hysteria-server"

# --- 运行时变量 ---
NAT_MODE=0
IPV6_ONLY=0
HAS_IPV4=0
HAS_IPV6=0
PUBLIC_IP=""
PUBLIC_IPV6=""
LISTEN_PORT=""
EXT_PORT=""
SNI="amd.com"

# ============================================================
# 环境检测
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
    [ "$RELEASE" = "unknown" ] && echo -e "${YELLOW}警告: 未检测到已知系统，将尝试通用安装${PLAIN}"
}

detect_init() {
    if command -v systemctl >/dev/null 2>&1 && systemctl --version >/dev/null 2>&1; then
        INIT_SYS="systemd"
    elif command -v rc-service >/dev/null 2>&1; then
        INIT_SYS="openrc"
    else
        INIT_SYS="none"
    fi
}

# ============================================================
# 服务管理
# ============================================================

service_start() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl start hysteria-server
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service hysteria-server start
    else
        nohup "$HY_BIN" server -c "$HY_CONFIG" >/var/log/hysteria.log 2>&1 &
        echo $! > /var/run/hysteria.pid
    fi
}

service_stop() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl stop hysteria-server 2>/dev/null
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service hysteria-server stop 2>/dev/null
    else
        [ -f /var/run/hysteria.pid ] && kill "$(cat /var/run/hysteria.pid)" 2>/dev/null && rm -f /var/run/hysteria.pid
        pkill -f "hysteria server" 2>/dev/null
    fi
}

service_restart() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl restart hysteria-server
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service hysteria-server restart
    else
        service_stop; sleep 1; service_start
    fi
}

service_enable() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl daemon-reload
        systemctl enable hysteria-server >/dev/null 2>&1
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-update add hysteria-server default >/dev/null 2>&1
    fi
}

service_disable() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl disable hysteria-server 2>/dev/null
        systemctl daemon-reload
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-update del hysteria-server default 2>/dev/null
    fi
}

service_is_active() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl is-active --quiet hysteria-server
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service hysteria-server status 2>/dev/null | grep -q "started"
    else
        [ -f /var/run/hysteria.pid ] && kill -0 "$(cat /var/run/hysteria.pid)" 2>/dev/null
    fi
}

service_logs() {
    if [ "$INIT_SYS" = "systemd" ]; then
        journalctl -u hysteria-server -n 20 --no-pager
    else
        tail -n 20 /var/log/hysteria.log 2>/dev/null || echo -e "${YELLOW}暂无日志${PLAIN}"
    fi
}

setup_systemd_service() {
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Hysteria 2 Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=${HY_BIN} server -c ${HY_CONFIG}
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
}

setup_openrc_service() {
    cat > "$OPENRC_SERVICE" <<'SVCHEAD'
#!/sbin/openrc-run

name="hysteria-server"
description="Hysteria 2 Server"
SVCHEAD
    cat >> "$OPENRC_SERVICE" <<EOF
command="${HY_BIN}"
command_args="server -c ${HY_CONFIG}"
command_background=true
pidfile="/var/run/hysteria.pid"
output_log="/var/log/hysteria.log"
error_log="/var/log/hysteria.log"

depend() {
    need net
    after firewall
}
EOF
    chmod +x "$OPENRC_SERVICE"
}

# ============================================================
# 网络检测
# ============================================================

detect_network() {
    echo -e "${YELLOW}正在检测网络环境...${PLAIN}"

    local _ip _url
    for _url in "https://api.ipify.org" "https://ip.gs" "https://ipv4.icanhazip.com"; do
        _ip=$(curl -s4 --max-time 6 "$_url" 2>/dev/null | tr -d '[:space:]')
        if echo "$_ip" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
            PUBLIC_IP="$_ip"; HAS_IPV4=1; break
        fi
    done

    for _url in "https://api6.ipify.org" "https://ipv6.icanhazip.com"; do
        _ip=$(curl -s6 --max-time 6 "$_url" 2>/dev/null | tr -d '[:space:]')
        if echo "$_ip" | grep -q ':'; then
            PUBLIC_IPV6="$_ip"; HAS_IPV6=1; break
        fi
    done

    # NAT 判断：本机接口 IP 列表里找不到公网 IPv4
    if [ "$HAS_IPV4" = "1" ]; then
        local _local_ips
        _local_ips=$(ip addr show 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
            | grep -v '^127\.' | grep -v '^169\.254\.')
        echo "$_local_ips" | grep -q "^${PUBLIC_IP}$" || NAT_MODE=1
    fi

    [ "$HAS_IPV4" = "0" ] && [ "$HAS_IPV6" = "1" ] && IPV6_ONLY=1

    if   [ "$NAT_MODE"  = "1" ]; then echo -e "  机器类型: ${YELLOW}NAT 机器${PLAIN}（公网 IPv4: ${PUBLIC_IP}）"
    elif [ "$IPV6_ONLY" = "1" ]; then echo -e "  机器类型: ${YELLOW}纯 IPv6${PLAIN}（IPv6: ${PUBLIC_IPV6}）"
    elif [ "$HAS_IPV6"  = "1" ]; then echo -e "  机器类型: ${GREEN}双栈${PLAIN}（IPv4: ${PUBLIC_IP} | IPv6: ${PUBLIC_IPV6}）"
    elif [ "$HAS_IPV4"  = "1" ]; then echo -e "  机器类型: ${GREEN}标准 IPv4${PLAIN}（IP: ${PUBLIC_IP}）"
    else                               echo -e "  机器类型: ${RED}无法检测，请手动输入${PLAIN}"
    fi
}

# ============================================================
# 依赖安装（不装 jq，bash 已在自举阶段装好）
# ============================================================

install_dependencies() {
    echo -e "${YELLOW}正在安装依赖...${PLAIN}"
    case "$RELEASE" in
        alpine)       apk update -q >/dev/null 2>&1; apk add --no-cache bash curl wget openssl >/dev/null 2>&1 ;;
        centos)       yum  install -y curl wget openssl >/dev/null 2>&1 ;;
        fedora|rocky) dnf  install -y curl wget openssl >/dev/null 2>&1 ;;
        arch)         pacman -Sy --noconfirm curl wget openssl >/dev/null 2>&1 ;;
        *)            apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq curl wget openssl >/dev/null 2>&1 ;;
    esac
}

# ============================================================
# 下载 Hysteria2（不依赖 jq，带重试）
# ============================================================

get_latest_version() {
    echo -e "${YELLOW}正在获取最新版本...${PLAIN}"
    LAST_VERSION=$(curl -Ls --max-time 10 "https://api.github.com/repos/apernet/hysteria/releases/latest" \
        | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' | head -1)

    if [ -z "$LAST_VERSION" ]; then
        LAST_VERSION=$(curl -Ls --max-time 10 -o /dev/null -w "%{url_effective}" \
            "https://github.com/apernet/hysteria/releases/latest" | sed 's|.*/tag/||')
    fi

    [ -z "$LAST_VERSION" ] && echo -e "${RED}获取版本失败，请检查网络${PLAIN}" && exit 1
    echo -e "${GREEN}最新版本: ${LAST_VERSION}${PLAIN}"
}

download_hy2() {
    local _arch
    case $(uname -m) in
        x86_64)        _arch="amd64" ;;
        aarch64|arm64) _arch="arm64" ;;
        armv7l|armv7)  _arch="armv7" ;;
        s390x)         _arch="s390x" ;;
        *) echo -e "${RED}不支持的架构: $(uname -m)${PLAIN}" && exit 1 ;;
    esac

    local _url="https://github.com/apernet/hysteria/releases/download/${LAST_VERSION}/hysteria-linux-${_arch}"

    # 杀旧进程 + 删旧二进制，避免 "Text file busy"
    pkill -f "hysteria server" 2>/dev/null
    sleep 1
    rm -f "$HY_BIN"

    echo -e "${YELLOW}正在下载 (${_arch})...${PLAIN}"
    local _retry=3 _ok=0
    while [ $_retry -gt 0 ]; do
        wget -q --show-progress -O "$HY_BIN" "$_url" && _ok=1 && break
        _retry=$((_retry - 1))
        [ $_retry -gt 0 ] && echo -e "${YELLOW}下载失败，重试中...${PLAIN}" && sleep 3
    done
    [ $_ok -eq 0 ] && echo -e "${RED}下载失败，请检查网络${PLAIN}" && exit 1
    chmod +x "$HY_BIN"
}

# ============================================================
# 端口配置
# ============================================================

configure_nat_port() {
    echo ""
    echo -e "${YELLOW}检测到 NAT 机器，请配置端口信息：${PLAIN}"
    echo -e "${SKYBLUE}说明：${PLAIN}"
    echo -e "  • 监听端口：Hysteria 在本容器/本机监听的端口"
    echo -e "  • 对外端口：宿主机转发后，客户端实际连接的端口"
    echo -e "  • 若面板内外端口一致，两者填相同即可"
    echo ""
    read -r -p "请输入本机监听端口 [默认 18888]: " LISTEN_PORT
    [[ -z "$LISTEN_PORT" ]] && LISTEN_PORT="18888"
    read -r -p "请输入对外端口（客户端连接端口）[留空=与监听端口相同]: " EXT_PORT
    [[ -z "$EXT_PORT" ]] && EXT_PORT="$LISTEN_PORT"
    echo -e "${YELLOW}提示: 请确保宿主机已将 UDP ${EXT_PORT} 转发到本机 UDP ${LISTEN_PORT}${PLAIN}"
}

configure_std_port() {
    read -r -p "请输入监听端口 [默认 18888]: " LISTEN_PORT
    [[ -z "$LISTEN_PORT" ]] && LISTEN_PORT="18888"
    EXT_PORT="$LISTEN_PORT"
}

# ============================================================
# 安装
# ============================================================

install_hy2() {
    install_dependencies
    detect_network
    echo ""
    get_latest_version
    download_hy2

    mkdir -p /etc/hysteria "$HY_CERT_DIR" "$HY_META"

    echo -e "\n${SKYBLUE}--- 配置 Hysteria2 ---${PLAIN}"

    if [ "$NAT_MODE" = "1" ]; then
        configure_nat_port
    else
        configure_std_port
    fi

    read -r -p "请设置连接密码 [留空自动生成]: " PASSWORD
    if [ -z "$PASSWORD" ]; then
        if command -v openssl >/dev/null 2>&1; then
            PASSWORD=$(openssl rand -base64 12)
        else
            PASSWORD=$(tr -dc 'A-Za-z0-9' < /dev/urandom 2>/dev/null | head -c 16)
        fi
    fi

    # IPv6 Only：监听双栈
    local LISTEN_ADDR=":${LISTEN_PORT}"
    if [ "$IPV6_ONLY" = "1" ]; then
        echo -e "${YELLOW}纯 IPv6 机器，将监听 [::]:${LISTEN_PORT}${PLAIN}"
        LISTEN_ADDR="[::]:${LISTEN_PORT}"
    fi

    echo -e "${YELLOW}生成自签名证书...${PLAIN}"
    openssl req -x509 -newkey rsa:2048 -days 3650 -nodes -sha256 \
        -keyout "$HY_CERT_DIR/server.key" -out "$HY_CERT_DIR/server.crt" \
        -subj "/CN=${SNI}" >/dev/null 2>&1

    # 带宽参数
    local BW_UP="50 mbps" BW_DOWN="100 mbps"
    echo ""
    read -r -p "是否使用默认保守带宽参数(50up/100down mbps)? [Y/n]: " LOW_BW
    if [[ "$LOW_BW" =~ ^[nN]$ ]]; then
        read -r -p "请输入上行带宽 mbps [默认 50]: " _up
        read -r -p "请输入下行带宽 mbps [默认 100]: " _dn
        [[ -n "$_up" ]] && BW_UP="${_up} mbps"
        [[ -n "$_dn" ]] && BW_DOWN="${_dn} mbps"
    fi

    cat > "$HY_CONFIG" <<EOF
listen: $LISTEN_ADDR

tls:
  cert: $HY_CERT_DIR/server.crt
  key: $HY_CERT_DIR/server.key

auth:
  type: password
  password: "$PASSWORD"

bandwidth:
  up: $BW_UP
  down: $BW_DOWN

masquerade:
  type: proxy
  proxy:
    url: https://$SNI/
    rewriteHost: true
EOF

    # 保存元数据
    echo "$NAT_MODE"    > "$HY_META/nat_mode"
    echo "$EXT_PORT"    > "$HY_META/ext_port"
    echo "$LISTEN_PORT" > "$HY_META/listen_port"
    [ -n "$PUBLIC_IP"   ] && echo "$PUBLIC_IP"   > "$HY_META/public_ip"
    [ -n "$PUBLIC_IPV6" ] && echo "$PUBLIC_IPV6" > "$HY_META/public_ipv6"

    # 注册服务
    if   [ "$INIT_SYS" = "systemd" ]; then setup_systemd_service
    elif [ "$INIT_SYS" = "openrc"  ]; then setup_openrc_service
    fi
    service_enable
    service_start

    # 启动验证
    sleep 2
    echo -e "${YELLOW}验证服务状态...${PLAIN}"
    if service_is_active; then
        echo -e "${GREEN}✓ Hysteria2 启动成功${PLAIN}"
        command -v ss >/dev/null 2>&1 && \
            ss -unlp 2>/dev/null | grep -q ":${LISTEN_PORT}" \
            && echo -e "${GREEN}✓ UDP ${LISTEN_PORT} 端口监听正常${PLAIN}" \
            || echo -e "${YELLOW}⚠ 未检测到端口监听，请查看日志${PLAIN}"
    else
        echo -e "${RED}✗ 启动失败，请查看日志${PLAIN}"
        service_logs
        return
    fi

    echo -e "${GREEN}安装完成！${PLAIN}"
    show_config
}

# ============================================================
# 读取配置变量
# ============================================================

read_config_vars() {
    [ ! -f "$HY_CONFIG" ] && return 1

    LISTEN_PORT=$(grep "^listen:" "$HY_CONFIG" | head -1 | grep -oE '[0-9]+$')
    PASSWORD=$(grep "password:" "$HY_CONFIG" | grep -v "^#" | head -1 \
        | sed 's/.*password:[[:space:]]*//' | tr -d '"' | tr -d "'")
    SNI="amd.com"

    if [ -d "$HY_META" ]; then
        NAT_MODE=$(cat "$HY_META/nat_mode"       2>/dev/null); NAT_MODE=${NAT_MODE:-0}
        EXT_PORT=$(cat "$HY_META/ext_port"       2>/dev/null)
        PUBLIC_IP=$(cat "$HY_META/public_ip"     2>/dev/null)
        PUBLIC_IPV6=$(cat "$HY_META/public_ipv6" 2>/dev/null)
    fi

    [[ -z "$EXT_PORT" ]] && EXT_PORT="$LISTEN_PORT"
    [[ -z "$NAT_MODE" ]] && NAT_MODE=0

    # IP 兜底（元数据为空时重新检测）
    if [ -z "$PUBLIC_IP" ] && [ -z "$PUBLIC_IPV6" ]; then
        PUBLIC_IP=$(curl -s4 --max-time 6 https://api.ipify.org 2>/dev/null | tr -d '[:space:]')
        PUBLIC_IPV6=$(curl -s6 --max-time 6 https://api6.ipify.org 2>/dev/null | tr -d '[:space:]')
    fi
}

# ============================================================
# URL encode — 纯 bash，不依赖 jq / python
# 修复语法解析错误，并严格全转义以确保二维码 API 正常识别
# ============================================================
uri_encode() {
    local _in="$1" _out="" _i=0 _c _hex _byte
    local _len=${#_in}
    while [ $_i -lt $_len ]; do
        _c="${_in:_i:1}"
        case "$_c" in
            # 仅保留最基础的字母数字和几个安全符号，其余全部强制转义
            [a-zA-Z0-9.~_-])
                _out+="$_c"
                ;;
            *)
                _hex=$(printf '%s' "$_c" | od -An -tx1 | tr -d ' \n' | tr 'a-f' 'A-F')
                for _byte in $_hex; do
                    _out+="%${_byte}"
                done
                ;;
        esac
        _i=$((_i + 1))
    done
    echo "$_out"
}

# ============================================================
# 展示单个节点（IPv4 或 IPv6）
# $1=IP  $2=Port  $3=标签(v4/v6)
# ============================================================

show_node() {
    local _ip="$1" _port="$2" _tag="$3"

    # URI 中 IPv6 加方括号
    local _host="$_ip"
    echo "$_ip" | grep -q ':' && _host="[${_ip}]"

    local _node="HY2-${_tag}-$(date +%m%d)"
    local _link="hysteria2://${PASSWORD}@${_host}:${_port}/?insecure=1&sni=${SNI}#${_node}"
    local _encoded
    _encoded=$(uri_encode "$_link")
    local _qr="https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=${_encoded}"

    echo -e "${GREEN} 分享链接 (V2rayN / NekoBox / Shadowrocket):${PLAIN}"
    echo -e "  ${_link}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    echo -e "${GREEN} 二维码链接:${PLAIN}"
    echo -e "  ${_qr}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    echo -e "${GREEN} Clash Meta / Stash / Clash Verge 配置:${PLAIN}"
    echo -e "  - {name: '${_node}', type: hysteria2, server: ${_ip}, port: ${_port}, password: ${PASSWORD}, sni: ${SNI}, skip-cert-verify: true, up: 50, down: 100 }"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    # Surge/Surfboard：原始 IP，不加方括号
    echo -e "${GREEN} Surge / Surfboard (Android) 配置:${PLAIN}"
    echo -e "  ${_node} = hysteria2, ${_ip}, ${_port}, password=${PASSWORD}, sni=${SNI}, skip-cert-verify=true"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    echo -e "${GREEN} Loon 配置:${PLAIN}"
    echo -e "  ${_node} = Hysteria2, ${_ip}, ${_port}, \"${PASSWORD}\", udp=true, sni=${SNI}, skip-cert-verify=true"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    echo -e "${GREEN} Sing-box 配置 (Outbound):${PLAIN}"
    echo -e "  { \"type\": \"hysteria2\", \"tag\": \"${_node}\", \"server\": \"${_ip}\", \"server_port\": ${_port}, \"password\": \"${PASSWORD}\", \"tls\": { \"enabled\": true, \"server_name\": \"${SNI}\", \"insecure\": true } }"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
}

# ============================================================
# 显示配置
# ============================================================

show_config() {
    if [ ! -f "$HY_CONFIG" ]; then
        echo -e "${RED}未找到配置文件${PLAIN}"
        read -r -p "按回车返回..." _tmp
        return
    fi

    read_config_vars

    echo -e ""
    echo -e "${GREEN}Hysteria2 配置详情${PLAIN}"
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
    echo -e "  ${BOLD}伪装 SNI${PLAIN}: ${YELLOW}${SNI}${PLAIN}"
    echo -e "  ${BOLD}自签证书${PLAIN}: ${RED}Insecure / Skip Cert Verify = True${PLAIN}"
    [ "$NAT_MODE" = "1" ] && echo -e "  ${BOLD}机器类型${PLAIN}: ${YELLOW}NAT 机器${PLAIN}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    # IPv4 节点
    [ -n "$PUBLIC_IP" ] && show_node "$PUBLIC_IP" "$EXT_PORT" "v4"

    # IPv6 节点（双栈或纯 IPv6）
    if [ -n "$PUBLIC_IPV6" ]; then
        echo -e "${YELLOW}▼ IPv6 节点${PLAIN}"
        show_node "$PUBLIC_IPV6" "$EXT_PORT" "v6"
    fi

    echo -e "${YELLOW}提示: Quantumult X 暂不支持 Hy2 协议。${PLAIN}"
    [ "$NAT_MODE" = "1" ] && \
        echo -e "${YELLOW}NAT 提示: 若无法连接，请确认宿主机已将 UDP ${EXT_PORT} 转发到本机 UDP ${LISTEN_PORT}${PLAIN}"
    echo ""
    read -r -p "按回车键返回主菜单..." _tmp
}

# ============================================================
# 管理
# ============================================================

manage_hy2() {
    clear
    echo -e "\n${SKYBLUE}--- 管理 Hysteria2 ---${PLAIN}"
    echo -e "1. 查看配置 (全客户端兼容)"
    echo -e "2. 重启服务"
    echo -e "3. 停止服务"
    echo -e "4. 查看日志"
    echo -e "0. 返回"
    read -r -p "请选择: " opt
    case $opt in
        1) show_config ;;
        2) service_restart && echo -e "${GREEN}服务已重启${PLAIN}" && sleep 1 ;;
        3) service_stop    && echo -e "${YELLOW}服务已停止${PLAIN}" && sleep 1 ;;
        4) service_logs; read -r -p "按回车继续..." _tmp ;;
        0) return ;;
        *) echo -e "${RED}输入错误${PLAIN}"; sleep 1 ;;
    esac
}

# ============================================================
# 卸载
# ============================================================

uninstall_hy2() {
    read -r -p "确定卸载? [y/N]: " confirm
    [[ ! "$confirm" =~ ^[yY]$ ]] && return
    service_stop
    service_disable
    rm -f "$SERVICE_FILE" "$OPENRC_SERVICE" "$HY_BIN"
    rm -rf /etc/hysteria
    echo -e "${GREEN}已卸载完成${PLAIN}"
    sleep 1
}

# ============================================================
# 主菜单
# ============================================================

main_menu() {
    while true; do
        clear
        if [ -f "$HY_BIN" ]; then
            service_is_active && STATUS="${GREEN}运行中${PLAIN}" || STATUS="${RED}已停止${PLAIN}"
        else
            STATUS="${RED}未安装${PLAIN}"
        fi

        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e "${GREEN}    Hysteria2 Management Script v2.1.2${PLAIN}"
        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e " 项目地址: ${YELLOW}https://github.com/everett7623/hy2${PLAIN}"
        echo -e " 作者    : ${YELLOW}Jensfrank${PLAIN}"
        echo -e "${SKYBLUE}───────────────────────────────────────────────${PLAIN}"
        echo -e " Seedloc博客 : https://seedloc.com"
        echo -e " VPSknow网站 : https://vpsknow.com"
        echo -e " Nodeloc论坛 : https://nodeloc.com"
        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e " 当前状态: $STATUS"
        echo -e "${SKYBLUE}───────────────────────────────────────────────${PLAIN}"
        echo -e " 1. 安装 Hysteria2"
        echo -e " 2. 管理 Hysteria2 (查看配置)"
        echo -e " 3. 卸载 Hysteria2"
        echo -e " 0. 退出"
        echo -e "${SKYBLUE}===============================================${PLAIN}"

        read -r -p "请输入选项: " choice
        case $choice in
            1) install_hy2 ;;
            2) manage_hy2 ;;
            3) uninstall_hy2 ;;
            0) exit 0 ;;
            *) echo -e "${RED}输入错误...${PLAIN}"; sleep 1 ;;
        esac
    done
}

# ============================================================
# 入口
# ============================================================

check_root
check_sys
detect_init
main_menu
