#!/bin/bash
#====================================================================================
# 项目：Shadowsocks-Rust Management Script
# 作者：Jensfrank
# 版本：v2.1.2 (Ultimate Linux Compatibility & Anti-Flashback)
# GitHub: https://github.com/shadowsocks/shadowsocks-rust
# Seedloc博客: https://seedloc.com
# VPSknow网站：https://vpsknow.com
# Nodeloc论坛: https://nodeloc.com
# 更新日期: 2026-04-22
#
# 支持系统: 完美兼容 Debian, Ubuntu, CentOS, Rocky, Alma, Alpine, Arch 等
# 支持环境: 标准 VPS / NAT 机器 / IPv6 单双栈 / 极简系统环境
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
            apt-get install -y -qq bash >/dev/null 2>&1
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y bash >/dev/null 2>&1
        elif command -v yum >/dev/null 2>&1; then
            yum install -y bash >/dev/null 2>&1
        fi
        exec bash "$0" "$@"
    fi
fi

if [ ! -t 0 ]; then
    [ -c /dev/tty ] && exec < /dev/tty
fi

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
SS_BIN="/usr/local/bin/ssserver"
SS_CONFIG="/etc/shadowsocks-rust/config.json"
SS_META="/etc/shadowsocks-rust/meta"
SERVICE_FILE="/etc/systemd/system/shadowsocks-server.service"
OPENRC_SERVICE="/etc/init.d/shadowsocks-server"

# --- 运行时变量 ---
NAT_MODE=0
IPV6_ONLY=0
HAS_IPV4=0
HAS_IPV6=0
PUBLIC_IP=""
PUBLIC_IPV6=""
LISTEN_PORT=""
EXT_PORT=""

# ============================================================
# 环境检测
# ============================================================

check_root() {
    [ "$EUID" -ne 0 ] && echo -e "${RED}错误: 请以 root 权限运行${PLAIN}" && exit 1
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

    if [ "$HAS_IPV4" = "1" ]; then
        local _local_ips
        _local_ips=$(ip addr show 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -v '^127\.' | grep -v '^169\.254\.')
        echo "$_local_ips" | grep -q "^${PUBLIC_IP}$" || NAT_MODE=1
    fi

    [ "$HAS_IPV4" = "0" ] && [ "$HAS_IPV6" = "1" ] && IPV6_ONLY=1

    if   [ "$NAT_MODE"  = "1" ]; then echo -e "  机器类型: ${YELLOW}NAT 机器${PLAIN}（公网 IPv4: ${PUBLIC_IP}）"
    elif [ "$IPV6_ONLY" = "1" ]; then echo -e "  机器类型: ${YELLOW}纯 IPv6${PLAIN}（IPv6: ${PUBLIC_IPV6}）"
    elif [ "$HAS_IPV6"  = "1" ]; then echo -e "  机器类型: ${GREEN}双栈${PLAIN}（IPv4: ${PUBLIC_IP} | IPv6: ${PUBLIC_IPV6}）"
    elif [ "$HAS_IPV4"  = "1" ]; then echo -e "  机器类型: ${GREEN}标准 IPv4${PLAIN}（IP: ${PUBLIC_IP}）"
    else                               echo -e "  机器类型: ${RED}无法检测，请手动输入${PLAIN}"
    fi

    if [ "$HAS_IPV6" = "0" ]; then
        echo -e "\n${RED}==========================================================${PLAIN}"
        echo -e "${RED}警告：未检测到公网 IPv6 地址！${PLAIN}"
        echo -e "${RED}Shadowsocks 协议在纯 IPv4 环境下较易被识别并封锁。${PLAIN}"
        echo -e "${YELLOW}建议在 双栈(IPv4+IPv6) 或 纯IPv6 的 VPS 上使用。${PLAIN}"
        echo -e "${RED}==========================================================${PLAIN}"
        read -r -p "是否强制继续安装？(风险自负) [y/N]: " _force
        [[ ! "$_force" =~ ^[yY]$ ]] && echo "已取消。" && exit 1
    fi
}

# ============================================================
# 服务管理
# ============================================================

service_start() {
    if [ "$INIT_SYS" = "systemd" ]; then systemctl start shadowsocks-server
    elif [ "$INIT_SYS" = "openrc" ]; then rc-service shadowsocks-server start
    else nohup "$SS_BIN" -c "$SS_CONFIG" >/var/log/ssserver.log 2>&1 & echo $! > /var/run/ssserver.pid
    fi
}

service_stop() {
    if [ "$INIT_SYS" = "systemd" ]; then systemctl stop shadowsocks-server 2>/dev/null
    elif [ "$INIT_SYS" = "openrc" ]; then rc-service shadowsocks-server stop 2>/dev/null
    else [ -f /var/run/ssserver.pid ] && kill "$(cat /var/run/ssserver.pid)" 2>/dev/null && rm -f /var/run/ssserver.pid; pkill -f "ssserver" 2>/dev/null
    fi
}

service_restart() { service_stop; sleep 1; service_start; }

service_enable() {
    if [ "$INIT_SYS" = "systemd" ]; then systemctl daemon-reload; systemctl enable shadowsocks-server >/dev/null 2>&1
    elif [ "$INIT_SYS" = "openrc" ]; then rc-update add shadowsocks-server default >/dev/null 2>&1
    fi
}

service_disable() {
    if [ "$INIT_SYS" = "systemd" ]; then systemctl disable shadowsocks-server 2>/dev/null; systemctl daemon-reload
    elif [ "$INIT_SYS" = "openrc" ]; then rc-update del shadowsocks-server default 2>/dev/null
    fi
}

service_is_active() {
    if [ "$INIT_SYS" = "systemd" ]; then systemctl is-active --quiet shadowsocks-server
    elif [ "$INIT_SYS" = "openrc" ]; then rc-service shadowsocks-server status 2>/dev/null | grep -q "started"
    else [ -f /var/run/ssserver.pid ] && kill -0 "$(cat /var/run/ssserver.pid)" 2>/dev/null
    fi
}

service_logs() {
    if [ "$INIT_SYS" = "systemd" ]; then journalctl -u shadowsocks-server -n 20 --no-pager
    else tail -n 20 /var/log/ssserver.log 2>/dev/null || echo -e "${YELLOW}暂无日志${PLAIN}"
    fi
}

setup_systemd_service() {
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Shadowsocks-Rust Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=${SS_BIN} -c ${SS_CONFIG}
Restart=on-failure
RestartSec=5s
LimitNOFILE=512000

[Install]
WantedBy=multi-user.target
EOF
}

setup_openrc_service() {
    cat > "$OPENRC_SERVICE" <<'SVCHEAD'
#!/sbin/openrc-run

name="shadowsocks-server"
description="Shadowsocks-Rust Server"
SVCHEAD
    cat >> "$OPENRC_SERVICE" <<EOF
command="${SS_BIN}"
command_args="-c ${SS_CONFIG}"
command_background=true
pidfile="/var/run/ssserver.pid"
output_log="/var/log/ssserver.log"
error_log="/var/log/ssserver.log"

depend() {
    need net
    after firewall
}
EOF
    chmod +x "$OPENRC_SERVICE"
}

# ============================================================
# 依赖安装 & 配置生成
# ============================================================

install_dependencies() {
    echo -e "${YELLOW}正在安装必要依赖...${PLAIN}"
    
    # 临时放行 SELinux 防止 Rocky/CentOS 端口被拦截 (关键修复)
    if command -v setenforce >/dev/null 2>&1; then
        setenforce 0 2>/dev/null
    fi

    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq >/dev/null 2>&1
        apt-get install -y -qq curl wget openssl tar xz-utils >/dev/null 2>&1
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y curl wget openssl tar xz >/dev/null 2>&1
    elif command -v yum >/dev/null 2>&1; then
        yum install -y curl wget openssl tar xz >/dev/null 2>&1
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Sy --noconfirm curl wget openssl tar xz >/dev/null 2>&1
    elif command -v apk >/dev/null 2>&1; then
        apk update -q >/dev/null 2>&1
        apk add --no-cache bash curl wget openssl tar xz >/dev/null 2>&1
    fi
    
    local _missing=0
    for pkg in curl wget openssl tar; do
        if ! command -v $pkg >/dev/null 2>&1; then
            echo -e "${RED}致命错误: 系统中缺少组件 [ $pkg ]${PLAIN}"
            _missing=1
        fi
    done
    [ "$_missing" -eq 1 ] && exit 1
}

install_ss() {
    detect_network
    install_dependencies
    
    echo -e "${YELLOW}正在获取 Shadowsocks-Rust 最新版本...${PLAIN}"
    LAST_VERSION=$(curl -Ls --max-time 10 "https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' | head -1)
    [ -z "$LAST_VERSION" ] && LAST_VERSION=$(curl -Ls -o /dev/null -w "%{url_effective}" "https://github.com/shadowsocks/shadowsocks-rust/releases/latest" | sed 's|.*/tag/||')
    [ -z "$LAST_VERSION" ] && echo -e "${RED}获取版本失败${PLAIN}" && exit 1
    
    echo -e "${GREEN}检测到最新版本: ${LAST_VERSION}${PLAIN}"

    # 智能识别 C 库版本 (兼容 Alpine 的 musl 和标准 Linux 的 gnu)
    local _libc="gnu"
    if command -v ldd >/dev/null 2>&1 && ldd --version 2>&1 | grep -qi 'musl'; then
        _libc="musl"
    elif [ -f /etc/alpine-release ]; then
        _libc="musl"
    fi

    local _arch
    case $(uname -m) in
        x86_64)        _arch="x86_64-unknown-linux-${_libc}" ;;
        aarch64|arm64) _arch="aarch64-unknown-linux-${_libc}" ;;
        *) echo -e "${RED}不支持的架构: $(uname -m)${PLAIN}" && exit 1 ;;
    esac
    
    local _url="https://github.com/shadowsocks/shadowsocks-rust/releases/download/${LAST_VERSION}/shadowsocks-${LAST_VERSION}.${_arch}.tar.xz"
    
    service_stop
    rm -f "$SS_BIN"
    
    echo -e "${YELLOW}正在下载核心文件...${PLAIN}"
    wget -q --show-progress -O /tmp/ss-rust.tar.xz "$_url" || { echo -e "${RED}下载失败${PLAIN}"; exit 1; }
    
    tar -xf /tmp/ss-rust.tar.xz -C /tmp/ ssserver || { echo -e "${RED}解压失败${PLAIN}"; exit 1; }
    mv /tmp/ssserver "$SS_BIN"
    chmod +x "$SS_BIN"
    rm -f /tmp/ss-rust.tar.xz
    
    mkdir -p /etc/shadowsocks-rust "$SS_META"

    echo -e "\n${SKYBLUE}--- 配置 Shadowsocks 2022 ---${PLAIN}"
    
    if [ "$NAT_MODE" = "1" ]; then
        read -r -p "请输入本机监听端口 [默认 28888]: " LISTEN_PORT
        [[ -z "$LISTEN_PORT" ]] && LISTEN_PORT="28888"
        read -r -p "请输入对外转发端口 [留空=与监听端口相同]: " EXT_PORT
        [[ -z "$EXT_PORT" ]] && EXT_PORT="$LISTEN_PORT"
    else
        read -r -p "请输入端口 [默认 28888]: " LISTEN_PORT
        [[ -z "$LISTEN_PORT" ]] && LISTEN_PORT="28888"
        EXT_PORT="$LISTEN_PORT"
    fi

    METHOD="2022-blake3-aes-256-gcm"
    echo -e "${YELLOW}协议已默认设置为 ${METHOD}${PLAIN}"
    PASSWORD=$(openssl rand -base64 32 | tr -d ' \n\r')
    echo -e "${GREEN}自动生成 32 字节密钥 -> ${PASSWORD}${PLAIN}"

    # 强制兼容 IPv4/IPv6 绑定
    local LISTEN_ADDR="0.0.0.0"
    [ "$HAS_IPV6" = "1" ] && LISTEN_ADDR="::"
    
    cat > "$SS_CONFIG" <<EOF
{
    "server": "$LISTEN_ADDR",
    "server_port": $LISTEN_PORT,
    "password": "$PASSWORD",
    "method": "$METHOD",
    "mode": "tcp_and_udp",
    "timeout": 300
}
EOF

    echo "$NAT_MODE"    > "$SS_META/nat_mode"
    echo "$EXT_PORT"    > "$SS_META/ext_port"
    echo "$LISTEN_PORT" > "$SS_META/listen_port"
    echo "$PASSWORD"    > "$SS_META/password"
    echo "$METHOD"      > "$SS_META/method"
    [ -n "$PUBLIC_IP"   ] && echo "$PUBLIC_IP"   > "$SS_META/public_ip"
    [ -n "$PUBLIC_IPV6" ] && echo "$PUBLIC_IPV6" > "$SS_META/public_ipv6"

    if   [ "$INIT_SYS" = "systemd" ]; then setup_systemd_service
    elif [ "$INIT_SYS" = "openrc"  ]; then setup_openrc_service
    fi
    service_enable
    service_start

    sleep 2
    if service_is_active; then
        echo -e "${GREEN}✓ Shadowsocks 2022 启动成功${PLAIN}"
    else
        echo -e "${RED}✗ 启动失败，请查看以下日志排查原因：${PLAIN}"
        service_logs
        # 【重点修复】增加 read 暂停，防止清屏闪退
        read -r -p "按回车键返回主菜单..." _tmp 
        return
    fi
    show_config
}

# ============================================================
# URL 编码与展示
# ============================================================
uri_encode() {
    local _in="$1" _out="" _i=0 _c _hex _byte
    local _len=${#_in}
    while [ $_i -lt $_len ]; do
        _c="${_in:_i:1}"
        case "$_c" in
            [a-zA-Z0-9.~_-]) _out+="$_c" ;;
            *)
                _hex=$(printf '%s' "$_c" | od -An -tx1 | tr -d ' \n' | tr 'a-f' 'A-F')
                for _byte in $_hex; do _out+="%${_byte}"; done
                ;;
        esac
        _i=$((_i + 1))
    done
    echo "$_out"
}

read_config_vars() {
    [ ! -f "$SS_CONFIG" ] && return 1
    if [ -d "$SS_META" ]; then
        NAT_MODE=$(cat "$SS_META/nat_mode" 2>/dev/null); NAT_MODE=${NAT_MODE:-0}
        EXT_PORT=$(cat "$SS_META/ext_port" 2>/dev/null)
        LISTEN_PORT=$(cat "$SS_META/listen_port" 2>/dev/null)
        PASSWORD=$(cat "$SS_META/password" 2>/dev/null)
        METHOD=$(cat "$SS_META/method" 2>/dev/null)
        PUBLIC_IP=$(cat "$SS_META/public_ip" 2>/dev/null)
        PUBLIC_IPV6=$(cat "$SS_META/public_ipv6" 2>/dev/null)
    fi
    [[ -z "$EXT_PORT" ]] && EXT_PORT=$(grep '"server_port"' "$SS_CONFIG" | grep -oE '[0-9]+' | head -1)
    [[ -z "$PASSWORD" ]] && PASSWORD=$(grep '"password"' "$SS_CONFIG" | awk -F'"' '{print $4}' | head -1)
    [[ -z "$METHOD" ]] && METHOD=$(grep '"method"' "$SS_CONFIG" | awk -F'"' '{print $4}' | head -1)
    if [ -z "$PUBLIC_IP" ] && [ -z "$PUBLIC_IPV6" ]; then
        PUBLIC_IP=$(curl -s4 --max-time 6 https://api.ipify.org 2>/dev/null | tr -d '[:space:]')
        PUBLIC_IPV6=$(curl -s6 --max-time 6 https://api6.ipify.org 2>/dev/null | tr -d '[:space:]')
    fi
}

show_node() {
    local _ip="$1" _port="$2" _tag="$3"
    local _host="$_ip"
    echo "$_ip" | grep -q ':' && _host="[${_ip}]"
    local _node="SS22-${_tag}-$(date +%m%d)"
    local _credentials
    _credentials=$(printf "%s:%s" "$METHOD" "$PASSWORD" | base64 | tr -d ' \n\r')
    local _link="ss://${_credentials}@${_host}:${_port}#${_node}"
    local _encoded
    _encoded=$(uri_encode "$_link")
    local _qr="https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=${_encoded}"

    echo -e "${GREEN} 分享链接 (SIP002 标准):${PLAIN}\n  ${_link}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    echo -e "${GREEN} 二维码链接:${PLAIN}\n  ${_qr}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    echo -e "${GREEN} Clash Meta / Stash 配置:${PLAIN}"
    echo -e "  - {name: '${_node}', type: ss, server: '${_ip}', port: ${_port}, cipher: ${METHOD}, password: '${PASSWORD}', udp: true }"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    echo -e "${GREEN} Surge / Surfboard 配置:${PLAIN}"
    echo -e "  ${_node} = ss, ${_ip}, ${_port}, encrypt-method=${METHOD}, password=${PASSWORD}, udp-relay=true"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    echo -e "${GREEN} Loon 配置:${PLAIN}"
    echo -e "  ${_node} = Shadowsocks, ${_ip}, ${_port}, ${METHOD}, \"${PASSWORD}\", udp=true"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    echo -e "${GREEN} Quantumult X 配置:${PLAIN}"
    echo -e "  shadowsocks=${_ip}:${_port}, method=${METHOD}, password=${PASSWORD}, fast-open=false, udp-relay=true, tag=${_node}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    echo -e "${GREEN} Sing-box 配置 (Outbound):${PLAIN}"
    echo -e "  { \"type\": \"shadowsocks\", \"tag\": \"${_node}\", \"server\": \"${_ip}\", \"server_port\": ${_port}, \"method\": \"${METHOD}\", \"password\": \"${PASSWORD}\" }"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
}

show_config() {
    read_config_vars
    [ -z "$EXT_PORT" ] && echo -e "${RED}未找到有效配置${PLAIN}" && read -r -p "按回车返回..." _tmp && return

    echo -e "\n${GREEN}Shadowsocks 配置详情${PLAIN}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    [ -n "$PUBLIC_IP"   ] && echo -e "  ${BOLD}IPv4地址${PLAIN}: ${YELLOW}${PUBLIC_IP}${PLAIN}"
    [ -n "$PUBLIC_IPV6" ] && echo -e "  ${BOLD}IPv6地址${PLAIN}: ${YELLOW}${PUBLIC_IPV6} (推荐)${PLAIN}"
    if [ "$NAT_MODE" = "1" ] && [ "$EXT_PORT" != "$LISTEN_PORT" ]; then
        echo -e "  ${BOLD}监听端口${PLAIN}: ${YELLOW}${LISTEN_PORT}${PLAIN}  ${RED}← 本机监听${PLAIN}"
        echo -e "  ${BOLD}对外端口${PLAIN}: ${YELLOW}${EXT_PORT}${PLAIN}  ${RED}← 客户端连接此端口${PLAIN}"
    else
        echo -e "  ${BOLD}端口Port${PLAIN}: ${YELLOW}${EXT_PORT}${PLAIN}"
    fi
    echo -e "  ${BOLD}密码Pass${PLAIN}: ${YELLOW}${PASSWORD}${PLAIN}"
    echo -e "  ${BOLD}加密方式${PLAIN}: ${YELLOW}${METHOD}${PLAIN}"
    [ "$NAT_MODE" = "1" ] && echo -e "  ${BOLD}机器类型${PLAIN}: ${YELLOW}NAT 机器${PLAIN}"
    
    echo -e "\n${RED}⚠️ 注意：SS-2022 协议对时间误差极其敏感！${PLAIN}"
    echo -e "${YELLOW}请确保您的手机/电脑【本地时间】与世界标准时间完全同步。${PLAIN}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    [ -n "$PUBLIC_IPV6" ] && echo -e "${YELLOW}▼ IPv6 节点配置 (推荐)${PLAIN}" && show_node "$PUBLIC_IPV6" "$EXT_PORT" "v6"
    [ -n "$PUBLIC_IP" ]   && echo -e "${YELLOW}▼ IPv4 节点配置${PLAIN}" && show_node "$PUBLIC_IP" "$EXT_PORT" "v4"

    echo ""
    read -r -p "按回车键返回主菜单..." _tmp
}

manage_ss() {
    clear
    echo -e "\n${SKYBLUE}--- 管理 Shadowsocks ---${PLAIN}"
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

uninstall_ss() {
    read -r -p "确定卸载? [y/N]: " confirm
    [[ ! "$confirm" =~ ^[yY]$ ]] && return
    service_stop
    service_disable
    rm -f "$SERVICE_FILE" "$OPENRC_SERVICE" "$SS_BIN"
    rm -rf /etc/shadowsocks-rust
    echo -e "${GREEN}已卸载完成${PLAIN}"
    sleep 1
}

main_menu() {
    while true; do
        clear
        if [ -f "$SS_BIN" ]; then
            service_is_active && STATUS="${GREEN}运行中${PLAIN}" || STATUS="${RED}已停止${PLAIN}"
        else
            STATUS="${RED}未安装${PLAIN}"
        fi

        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e "${GREEN} Shadowsocks-Rust Management Script v2.1.2${PLAIN}"
        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e " 项目地址: ${YELLOW}https://github.com/shadowsocks/shadowsocks-rust${PLAIN}"
        echo -e " 作者    : ${YELLOW}Jensfrank${PLAIN}"
        echo -e "${SKYBLUE}───────────────────────────────────────────────${PLAIN}"
        echo -e " 当前状态: $STATUS"
        echo -e " 核心协议: ${YELLOW}Shadowsocks 2022${PLAIN} (自动配置 32 字节密钥)"
        echo -e "${SKYBLUE}───────────────────────────────────────────────${PLAIN}"
        echo -e " 1. 安装 Shadowsocks 2022"
        echo -e " 2. 管理 Shadowsocks 2022 (查看配置)"
        echo -e " 3. 卸载 Shadowsocks 2022"
        echo -e " 0. 退出"
        echo -e "${SKYBLUE}===============================================${PLAIN}"
        
        read -r -p "请输入选项: " choice
        case $choice in
            1) install_ss ;;
            2) manage_ss ;;
            3) uninstall_ss ;;
            0) exit 0 ;;
            *) echo -e "${RED}输入错误...${PLAIN}"; sleep 1 ;;
        esac
    done
}

check_root
detect_init
main_menu
