#!/bin/bash
#====================================================================================
# 项目：Sing-box Multi-Protocol Tools — 一键管理入口
# 脚本：AnyTLS · Hysteria2 · Shadowsocks · EUserv IPv6 HY2
# 作者：Jensfrank
# 版本：v2.0.0
# GitHub  : https://github.com/everett7623/hy2
# 博客    : https://seedloc.com
# 测评    : https://vpsknow.com
# 论坛    : https://nodeloc.com
# 更新日期: 2026-07-02
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

# ---- 颜色 ----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
SKYBLUE='\033[0;36m'
CYAN='\033[1;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
PLAIN='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'

# ---- 脚本地址 / 路径 ----
BASE_URL="https://raw.githubusercontent.com/everett7623/hy2/main"
INSTALL_URL="${BASE_URL}/install.sh"
HY2_URL="${BASE_URL}/hy2.sh"
SS_URL="${BASE_URL}/ss.sh"
ANYTLS_URL="${BASE_URL}/anytls.sh"
EUSERV_URL="${BASE_URL}/euservhy2.sh"
BACKUP_DIR="/root/singbox-tools/backup"
SCRIPT_CACHE_DIR="/root/singbox-tools/scripts"

# ============================================================
# 基础工具
# ============================================================
check_root() {
    [ "$EUID" -ne 0 ] && echo -e "${RED}错误: 请以 root 权限运行${PLAIN}" && exit 1
}

pause_return() {
    echo ""
    read -r -p "按回车键返回..." _tmp
}

install_curl_if_missing() {
    command -v curl >/dev/null 2>&1 && return 0
    echo -e "${YELLOW}[WARN] curl 未安装，正在尝试安装...${PLAIN}"
    if command -v apk >/dev/null 2>&1; then
        apk add --no-cache curl ca-certificates >/dev/null 2>&1
    elif command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq >/dev/null 2>&1
        apt-get install -y -qq curl ca-certificates >/dev/null 2>&1
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y curl ca-certificates >/dev/null 2>&1
    elif command -v yum >/dev/null 2>&1; then
        yum install -y curl ca-certificates >/dev/null 2>&1
    fi
    command -v curl >/dev/null 2>&1
}

run_script() {
    local _name="$1" _url="$2"
    echo ""
    echo -e "${SKYBLUE}───────────────────────────────────────────────${PLAIN}"
    echo -e "正在加载 ${BOLD}${_name}${PLAIN} ..."
    echo -e "${SKYBLUE}───────────────────────────────────────────────${PLAIN}"

    install_curl_if_missing || {
        echo -e "${RED}[ERROR] curl 安装失败，无法下载脚本${PLAIN}"
        sleep 2
        return 1
    }

    local _tmp
    _tmp=$(mktemp /tmp/singbox_tools_XXXXXX.sh 2>/dev/null) || {
        echo -e "${RED}[ERROR] 无法创建临时文件${PLAIN}"
        sleep 2
        return 1
    }
    if curl -fsSL --connect-timeout 15 --max-time 60 "$_url" -o "$_tmp" 2>/dev/null; then
        if ! [ -s "$_tmp" ] || ! bash -n "$_tmp" 2>/dev/null; then
            echo -e "${RED}[ERROR] 下载内容无效或脚本语法检查失败${PLAIN}"
            rm -f "$_tmp"
            sleep 3
            return 1
        fi
        chmod +x "$_tmp"
        bash "$_tmp"
        rm -f "$_tmp"
    else
        rm -f "$_tmp"
        echo -e "${RED}[ERROR] 下载失败，请检查网络${PLAIN}"
        echo -e "${YELLOW}也可直接运行: bash <(curl -fsSL ${_url})${PLAIN}"
        sleep 3
        return 1
    fi
}

service_active() {
    local _service="$1" _pidfile="$2"
    if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
        systemctl is-active --quiet "$_service" 2>/dev/null
    elif command -v rc-service >/dev/null 2>&1; then
        rc-service "$_service" status 2>/dev/null | grep -q "started"
    else
        [ -f "$_pidfile" ] && kill -0 "$(cat "$_pidfile" 2>/dev/null)" 2>/dev/null
    fi
}

service_action() {
    local _service="$1" _action="$2" _pidfile="$3"
    if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
        systemctl "$_action" "$_service"
    elif command -v rc-service >/dev/null 2>&1; then
        rc-service "$_service" "$_action"
    else
        case "$_service:$_action" in
            anytls-server:start) nohup /usr/local/bin/anytls-server >/var/log/anytls-server.log 2>&1 & echo $! > "$_pidfile" ;;
            anytls-server:stop)  [ -f "$_pidfile" ] && kill "$(cat "$_pidfile" 2>/dev/null)" 2>/dev/null; rm -f "$_pidfile" ;;
            hysteria-server:start) nohup /usr/local/bin/hysteria server -c /etc/hysteria/config.yaml >/var/log/hysteria.log 2>&1 & echo $! > "$_pidfile" ;;
            hysteria-server:stop)  [ -f "$_pidfile" ] && kill "$(cat "$_pidfile" 2>/dev/null)" 2>/dev/null; rm -f "$_pidfile" ;;
            shadowsocks-server:start) nohup /usr/local/bin/ssserver -c /etc/shadowsocks-rust/config.json >/var/log/ssserver.log 2>&1 & echo $! > "$_pidfile" ;;
            shadowsocks-server:stop)  [ -f "$_pidfile" ] && kill "$(cat "$_pidfile" 2>/dev/null)" 2>/dev/null; rm -f "$_pidfile" ;;
            *:restart) service_action "$_service" stop "$_pidfile"; sleep 1; service_action "$_service" start "$_pidfile" ;;
            *) return 1 ;;
        esac
    fi
}

service_logs() {
    local _service="$1" _log="$2"
    if [ -d /run/systemd/system ] && command -v journalctl >/dev/null 2>&1; then
        journalctl -u "$_service" -n 80 --no-pager
    else
        tail -n 80 "$_log" 2>/dev/null || echo -e "${YELLOW}[WARN] 暂无日志${PLAIN}"
    fi
}

get_real_ipv6() {
    command -v ip >/dev/null 2>&1 || return 1
    ip -6 addr show scope global 2>/dev/null | awk '
        /^[0-9]+:/ { iface=$2; sub(/:.*/,"",iface) }
        /inet6/ && iface !~ /wgcf|warp|^tun|^wg|tailscale|zt/ {
            addr=$2; sub(/\/.*/,"",addr)
            if (addr !~ /^fe80/ && addr !~ /^2606:4700:/) { print addr; exit }
        }
    '
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

get_country_name() {
    case "$1" in
        US) printf 'United States' ;; DE) printf 'Germany' ;; JP) printf 'Japan' ;; SG) printf 'Singapore' ;;
        HK) printf 'Hong Kong' ;; TW) printf 'Taiwan' ;; KR) printf 'South Korea' ;; GB) printf 'United Kingdom' ;;
        FR) printf 'France' ;; NL) printf 'Netherlands' ;; CA) printf 'Canada' ;; AU) printf 'Australia' ;;
        RU) printf 'Russia' ;; IN) printf 'India' ;; VN) printf 'Vietnam' ;; TH) printf 'Thailand' ;;
        UN) printf 'Unknown' ;; *) printf 'Unknown' ;;
    esac
}

get_bbr_status() {
    local _cc _qdisc
    _cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    _qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null)
    if echo "${_cc:-}" | grep -qi bbr; then
        printf '%s / %s' "${_cc}" "${_qdisc:-unknown}"
    else
        printf 'disabled (%s / %s)' "${_cc:-unknown}" "${_qdisc:-unknown}"
    fi
}

get_status() {
    local _ver _ipv6 _country
    NET_IPV4=$(curl -4 -s --max-time 3 ip.sb 2>/dev/null | tr -d '[:space:]')
    _ipv6=$(get_real_ipv6 2>/dev/null || true)
    [ -z "$_ipv6" ] && _ipv6=$(curl -6 -s --max-time 3 api6.ipify.org 2>/dev/null | tr -d '[:space:]')
    NET_IPV6="${_ipv6:-无}"
    NET_IPV4="${NET_IPV4:-无}"
    OS_INFO=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2 || uname -s)
    ARCH_INFO=$(uname -m)
    KERNEL_INFO=$(uname -r)
    BBR_STATUS=$(get_bbr_status)
    _country=""
    [ "$NET_IPV4" != "无" ] && _country=$(get_ip_country "$NET_IPV4" 2>/dev/null || true)
    [ -z "$_country" ] && [ "$NET_IPV6" != "无" ] && _country=$(get_ip_country "$NET_IPV6" 2>/dev/null || true)
    [ -z "$_country" ] && _country="UN"
    COUNTRY_INFO="${_country} / $(get_country_name "$_country")"

    if [ -f "/usr/local/bin/hysteria" ]; then
        _ver=$(/usr/local/bin/hysteria version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        service_active hysteria-server /var/run/hysteria.pid \
            && HY2_STATUS="${GREEN}● 运行中${PLAIN}${DIM} ${_ver}${PLAIN}" \
            || HY2_STATUS="${YELLOW}● 已停止${PLAIN}${DIM} ${_ver}${PLAIN}"
    else
        HY2_STATUS="${RED}● 未安装${PLAIN}"
    fi

    if [ -f "/usr/local/bin/ssserver" ]; then
        _ver=$(/usr/local/bin/ssserver --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        service_active shadowsocks-server /var/run/ssserver.pid \
            && SS_STATUS="${GREEN}● 运行中${PLAIN}${DIM} v${_ver}${PLAIN}" \
            || SS_STATUS="${YELLOW}● 已停止${PLAIN}${DIM} v${_ver}${PLAIN}"
    else
        SS_STATUS="${RED}● 未安装${PLAIN}"
    fi

    if [ -x "/usr/local/bin/anytls-server" ] && [ -f "/etc/sing-box/anytls.json" ]; then
        service_active anytls-server /var/run/anytls-server.pid \
            && ANYTLS_STATUS="${GREEN}● 运行中${PLAIN}" \
            || ANYTLS_STATUS="${YELLOW}● 已停止${PLAIN}"
    else
        ANYTLS_STATUS="${RED}● 未安装${PLAIN}"
    fi

    if [ "$NET_IPV6" != "无" ]; then
        [ "$NET_IPV4" = "无" ] \
            && EUSERV_STATUS="${CYAN}● 纯 IPv6 可用${PLAIN}" \
            || EUSERV_STATUS="${SKYBLUE}● IPv6 双栈可用${PLAIN}"
    else
        EUSERV_STATUS="${RED}● 不适用${PLAIN}"
    fi
}

# ============================================================
# UI
# ============================================================
show_header() {
    clear
    echo -e "  ${SKYBLUE}${BOLD}==========================================================${PLAIN}"
    echo -e "  ${WHITE}${BOLD}Sing-box Multi-Protocol Tools${PLAIN} ${GREEN}${BOLD}v2.0${PLAIN}"
    echo -e "  ${DIM}AnyTLS | Hysteria2 | Shadowsocks | EUserv HY2${PLAIN}"
    echo -e "  ${SKYBLUE}${BOLD}==========================================================${PLAIN}"
    echo -e "  ${DIM}作者${PLAIN}   ${WHITE}Jensfrank${PLAIN}  ${DIM}│${PLAIN}  ${DIM}项目${PLAIN}  ${YELLOW}github.com/everett7623/hy2${PLAIN}"
    echo -e "  ${DIM}博客${PLAIN}   ${SKYBLUE}seedloc.com${PLAIN}     ${DIM}│${PLAIN}  ${DIM}测评${PLAIN}  ${SKYBLUE}vpsknow.com${PLAIN}"
    echo -e "  ${DIM}论坛${PLAIN}   ${SKYBLUE}nodeloc.com${PLAIN}"
    echo -e "  ${SKYBLUE}──────────────────────────────────────────────────────────${PLAIN}"
}

show_status_summary() {
    get_status
    echo -e "  ${DIM}IPv4${PLAIN}        ${WHITE}${NET_IPV4}${PLAIN}"
    echo -e "  ${DIM}IPv6${PLAIN}        ${WHITE}${NET_IPV6}${PLAIN}"
    echo -e "  ${DIM}系统${PLAIN}        ${WHITE}${OS_INFO} ${ARCH_INFO}${PLAIN}"
    echo -e "  ${DIM}内核${PLAIN}        ${WHITE}${KERNEL_INFO}${PLAIN}"
    echo -e "  ${DIM}BBR${PLAIN}         ${WHITE}${BBR_STATUS}${PLAIN}"
    echo -e "  ${DIM}国家/地区${PLAIN}   ${WHITE}${COUNTRY_INFO}${PLAIN}"
    echo -e "  ${SKYBLUE}──────────────────────────────────────────────────────────${PLAIN}"
    echo -e "  AnyTLS        $(echo -e "$ANYTLS_STATUS")"
    echo -e "  Hysteria2     $(echo -e "$HY2_STATUS")"
    echo -e "  Shadowsocks   $(echo -e "$SS_STATUS")"
    echo -e "  EUserv HY2    $(echo -e "$EUSERV_STATUS")"
    echo -e "  ${SKYBLUE}──────────────────────────────────────────────────────────${PLAIN}"
}

select_protocol_and_run() {
    local _title="$1"
    while true; do
        show_header
        echo -e "${WHITE}${BOLD}${_title}${PLAIN}"
        echo ""
        echo -e "  [1] AnyTLS"
        echo -e "  [2] Hysteria2"
        echo -e "  [3] Shadowsocks"
        echo -e "  [4] EUserv IPv6-only HY2"
        echo -e "  [0] 返回"
        echo ""
        read -r -p "  请选择协议 [0-4]: " p
        case "$p" in
            1) run_script "AnyTLS" "$ANYTLS_URL"; return ;;
            2) run_script "Hysteria2" "$HY2_URL"; return ;;
            3) run_script "Shadowsocks" "$SS_URL"; return ;;
            4) run_script "EUserv IPv6 HY2" "$EUSERV_URL"; return ;;
            0) return ;;
            *) echo -e "${RED}无效选项${PLAIN}"; sleep 1 ;;
        esac
    done
}

install_menu() {
    select_protocol_and_run "安装 / 重装协议"
}

node_info_menu() {
    select_protocol_and_run "查看节点信息"
}

export_config_menu() {
    while true; do
        show_header
        echo -e "${WHITE}${BOLD}导出客户端配置${PLAIN}"
        echo -e "${DIM}选择格式后会加载对应协议脚本的节点详情页；协议脚本会输出当前支持的全部格式。${PLAIN}"
        echo ""
        echo -e "  [1] URI 分享链接"
        echo -e "  [2] Throne URI"
        echo -e "  [3] Mihomo / Clash Meta / Clash Verge 单行配置"
        echo -e "  [4] Loon 配置"
        echo -e "  [5] Surfboard 配置"
        echo -e "  [6] Shadowrocket 配置"
        echo -e "  [7] Quantumult X 配置"
        echo -e "  [8] 全部输出"
        echo -e "  [9] Sing-box JSON 配置"
        echo -e "  [0] 返回"
        echo ""
        read -r -p "  请选择导出格式 [0-9]: " fmt
        case "$fmt" in
            1|2|3|4|5|6|7|8|9) select_protocol_and_run "选择协议以导出配置"; return ;;
            0) return ;;
            *) echo -e "${RED}无效选项${PLAIN}"; sleep 1 ;;
        esac
    done
}

list_listening_ports() {
    echo -e "\n${WHITE}${BOLD}监听端口${PLAIN}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    if command -v ss >/dev/null 2>&1; then
        ss -tulnp 2>/dev/null | head -30
    elif command -v netstat >/dev/null 2>&1; then
        netstat -tulnp 2>/dev/null | head -30
    else
        echo -e "${YELLOW}[WARN] 未找到 ss/netstat，无法查看监听端口${PLAIN}"
    fi
}

show_all_services() {
    get_status
    echo -e "AnyTLS      : $(echo -e "$ANYTLS_STATUS")"
    echo -e "Hysteria2   : $(echo -e "$HY2_STATUS")"
    echo -e "Shadowsocks : $(echo -e "$SS_STATUS")"
    echo -e "EUserv HY2  : $(echo -e "$EUSERV_STATUS")"
}

protocol_service_menu() {
    local _label="$1" _service="$2" _pidfile="$3" _log="$4" _script_name="$5" _script_url="$6"
    while true; do
        show_header
        echo -e "${WHITE}${BOLD}${_label} 服务管理${PLAIN}"
        service_active "$_service" "$_pidfile" \
            && echo -e "当前状态: ${GREEN}运行中${PLAIN}" \
            || echo -e "当前状态: ${YELLOW}未运行 / 未安装${PLAIN}"
        echo ""
        echo -e "  [1] 查看状态"
        echo -e "  [2] 启动服务"
        echo -e "  [3] 停止服务"
        echo -e "  [4] 重启服务"
        echo -e "  [5] 查看日志"
        echo -e "  [6] 查看监听端口"
        echo -e "  [7] 修改配置"
        echo -e "  [0] 返回"
        echo ""
        read -r -p "  请选择 [0-7]: " opt
        case "$opt" in
            1) show_all_services; pause_return ;;
            2) service_action "$_service" start "$_pidfile" && echo -e "${GREEN}[OK] 服务已启动${PLAIN}" || echo -e "${RED}[ERROR] 启动失败${PLAIN}"; sleep 1 ;;
            3) service_action "$_service" stop "$_pidfile" && echo -e "${GREEN}[OK] 服务已停止${PLAIN}" || echo -e "${RED}[ERROR] 停止失败${PLAIN}"; sleep 1 ;;
            4)
                if service_action "$_service" restart "$_pidfile"; then
                    sleep 1
                    service_active "$_service" "$_pidfile" && echo -e "${GREEN}[OK] 服务已重启${PLAIN}" || { echo -e "${RED}[ERROR] 重启后未运行，最近日志：${PLAIN}"; service_logs "$_service" "$_log"; }
                else
                    echo -e "${RED}[ERROR] 重启失败，最近日志：${PLAIN}"
                    service_logs "$_service" "$_log"
                fi
                pause_return
                ;;
            5) service_logs "$_service" "$_log"; pause_return ;;
            6) list_listening_ports; pause_return ;;
            7) echo -e "${YELLOW}[WARN] 修改配置前会由对应协议脚本自动备份并回滚失败变更。${PLAIN}"; sleep 1; run_script "$_script_name" "$_script_url" ;;
            0) return ;;
            *) echo -e "${RED}无效选项${PLAIN}"; sleep 1 ;;
        esac
    done
}

service_management_menu() {
    while true; do
        show_header
        echo -e "${WHITE}${BOLD}服务管理${PLAIN}"
        echo ""
        echo -e "  [1] AnyTLS 服务管理"
        echo -e "  [2] Hysteria2 服务管理"
        echo -e "  [3] Shadowsocks 服务管理"
        echo -e "  [4] EUserv HY2 服务管理"
        echo -e "  [5] 查看所有服务状态"
        echo -e "  [6] 查看监听端口"
        echo -e "  [7] 查看最近日志"
        echo -e "  [0] 返回"
        echo ""
        read -r -p "  请选择 [0-7]: " opt
        case "$opt" in
            1) protocol_service_menu "AnyTLS" "anytls-server" "/var/run/anytls-server.pid" "/var/log/anytls-server.log" "AnyTLS" "$ANYTLS_URL" ;;
            2) protocol_service_menu "Hysteria2" "hysteria-server" "/var/run/hysteria.pid" "/var/log/hysteria.log" "Hysteria2" "$HY2_URL" ;;
            3) protocol_service_menu "Shadowsocks" "shadowsocks-server" "/var/run/ssserver.pid" "/var/log/ssserver.log" "Shadowsocks" "$SS_URL" ;;
            4) protocol_service_menu "EUserv HY2" "hysteria-server" "/var/run/hysteria.pid" "/var/log/hysteria.log" "EUserv IPv6 HY2" "$EUSERV_URL" ;;
            5) show_all_services; pause_return ;;
            6) list_listening_ports; pause_return ;;
            7)
                echo -e "${WHITE}${BOLD}最近日志${PLAIN}"
                service_logs anytls-server /var/log/anytls-server.log
                service_logs hysteria-server /var/log/hysteria.log
                service_logs shadowsocks-server /var/log/ssserver.log
                pause_return
                ;;
            0) return ;;
            *) echo -e "${RED}无效选项${PLAIN}"; sleep 1 ;;
        esac
    done
}

qrcode_menu() {
    select_protocol_and_run "生成二维码"
}

system_detect() {
    show_header
    get_status
    echo -e "${WHITE}${BOLD}系统检测${PLAIN}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    echo "OS       : ${OS_INFO}"
    echo "Arch     : ${ARCH_INFO}"
    echo "Kernel   : ${KERNEL_INFO}"
    echo "IPv4     : ${NET_IPV4}"
    echo "IPv6     : ${NET_IPV6}"
    echo "Country  : ${COUNTRY_INFO}"
    if [ -x /usr/local/bin/sing-box ]; then
        echo "sing-box : installed, $(/usr/local/bin/sing-box version 2>/dev/null | head -1)"
    else
        echo "sing-box : not installed"
    fi
    [ -x /usr/local/bin/hysteria ] && echo "hysteria : $(/usr/local/bin/hysteria version 2>/dev/null | head -1)" || echo "hysteria : not installed"
    [ -x /usr/local/bin/ssserver ] && echo "ssserver : $(/usr/local/bin/ssserver --version 2>/dev/null | head -1)" || echo "ssserver : not installed"
    echo "AnyTLS   : $(echo -e "$ANYTLS_STATUS" | sed 's/\x1b\[[0-9;]*m//g')"
    echo "HY2      : $(echo -e "$HY2_STATUS" | sed 's/\x1b\[[0-9;]*m//g')"
    echo "SS       : $(echo -e "$SS_STATUS" | sed 's/\x1b\[[0-9;]*m//g')"
    echo "BBR      : ${BBR_STATUS}"
    echo "Time     : $(date '+%F %T %Z')"
    echo "Disk     : $(df -h / 2>/dev/null | awk 'NR==2 {print $3" / "$2" ("$5" used)"}')"
    echo "Memory   : $(awk '/MemTotal/ {t=$2} /MemAvailable/ {a=$2} END { if (t) printf "%.0fMB / %.0fMB", (t-a)/1024, t/1024 }' /proc/meminfo 2>/dev/null)"
    echo "Load     : $(uptime 2>/dev/null | awk -F'load average:' '{print $2}' | awk '{$1=$1; print}')"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    list_listening_ports
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    echo -ne "IPv4 网络: "
    curl -4 -s --max-time 5 https://api.ipify.org >/dev/null 2>&1 && echo "OK" || echo "FAILED"
    echo -ne "IPv6 网络: "
    curl -6 -s --max-time 5 https://api6.ipify.org >/dev/null 2>&1 && echo "OK" || echo "FAILED"
    pause_return
}

backup_config() {
    mkdir -p "$BACKUP_DIR"
    local _file="${BACKUP_DIR}/backup-$(date '+%Y%m%d-%H%M%S').tar.gz"
    local _items=""
    [ -d /etc/sing-box ] && _items="${_items} etc/sing-box"
    [ -d /etc/hysteria ] && _items="${_items} etc/hysteria"
    [ -d /etc/shadowsocks-rust ] && _items="${_items} etc/shadowsocks-rust"
    [ -f /etc/shadowsocks.json ] && _items="${_items} etc/shadowsocks.json"
    [ -f /etc/systemd/system/anytls-server.service ] && _items="${_items} etc/systemd/system/anytls-server.service"
    [ -f /etc/systemd/system/hysteria-server.service ] && _items="${_items} etc/systemd/system/hysteria-server.service"
    [ -f /etc/systemd/system/shadowsocks-server.service ] && _items="${_items} etc/systemd/system/shadowsocks-server.service"
    [ -f /etc/init.d/anytls-server ] && _items="${_items} etc/init.d/anytls-server"
    [ -f /etc/init.d/hysteria-server ] && _items="${_items} etc/init.d/hysteria-server"
    [ -f /etc/init.d/shadowsocks-server ] && _items="${_items} etc/init.d/shadowsocks-server"
    if [ -z "$_items" ]; then
        echo -e "${YELLOW}[WARN] 未找到可备份配置${PLAIN}"
        return 1
    fi
    ( cd / && tar -czf "$_file" $_items 2>/dev/null ) || {
        echo -e "${RED}[ERROR] 备份失败${PLAIN}"
        return 1
    }
    printf '%s\n' "script_version=v2.0.0" > "${BACKUP_DIR}/latest-version.txt"
    echo -e "${GREEN}[OK] 备份完成: ${_file}${PLAIN}"
}

restore_config() {
    mkdir -p "$BACKUP_DIR"
    echo -e "${WHITE}${BOLD}备份列表${PLAIN}"
    ls -1 "$BACKUP_DIR"/backup-*.tar.gz 2>/dev/null || { echo -e "${YELLOW}[WARN] 暂无备份${PLAIN}"; return 1; }
    echo ""
    read -r -p "请输入要恢复的完整备份路径: " _file
    [ -f "$_file" ] || { echo -e "${RED}[ERROR] 备份文件不存在${PLAIN}"; return 1; }
    echo -e "${YELLOW}[WARN] 恢复前将自动备份当前配置${PLAIN}"
    backup_config || true
    tar -xzf "$_file" -C / 2>/dev/null || {
        echo -e "${RED}[ERROR] 恢复失败，请检查备份文件${PLAIN}"
        return 1
    }
    [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload
    service_action anytls-server restart /var/run/anytls-server.pid >/dev/null 2>&1 || true
    service_action hysteria-server restart /var/run/hysteria.pid >/dev/null 2>&1 || true
    service_action shadowsocks-server restart /var/run/ssserver.pid >/dev/null 2>&1 || true
    echo -e "${GREEN}[OK] 恢复完成，已尝试重启相关服务${PLAIN}"
}

backup_restore_menu() {
    while true; do
        show_header
        echo -e "${WHITE}${BOLD}备份 / 恢复${PLAIN}"
        echo ""
        echo -e "  [1] 备份当前配置"
        echo -e "  [2] 查看备份列表"
        echo -e "  [3] 恢复指定备份"
        echo -e "  [4] 删除旧备份"
        echo -e "  [0] 返回"
        echo ""
        read -r -p "  请选择 [0-4]: " opt
        case "$opt" in
            1) backup_config; pause_return ;;
            2) ls -lh "$BACKUP_DIR"/backup-*.tar.gz 2>/dev/null || echo -e "${YELLOW}[WARN] 暂无备份${PLAIN}"; pause_return ;;
            3) restore_config; pause_return ;;
            4)
                mkdir -p "$BACKUP_DIR"
                read -r -p "确认删除 30 天前备份？[y/N]: " c
                case "$c" in
                    [yY]) find "$BACKUP_DIR" -maxdepth 1 -name 'backup-*.tar.gz' -type f -mtime +30 -print -delete ;;
                    *) echo "已取消。" ;;
                esac
                pause_return
                ;;
            0) return ;;
            *) echo -e "${RED}无效选项${PLAIN}"; sleep 1 ;;
        esac
    done
}

download_script_to_cache() {
    local _name="$1" _url="$2" _dest="${SCRIPT_CACHE_DIR}/${_name}"
    mkdir -p "$SCRIPT_CACHE_DIR"
    install_curl_if_missing || return 1
    curl -fsSL --connect-timeout 15 --max-time 60 "$_url" -o "$_dest.tmp" 2>/dev/null || return 1
    bash -n "$_dest.tmp" 2>/dev/null || { rm -f "$_dest.tmp"; return 1; }
    mv -f "$_dest.tmp" "$_dest"
    chmod +x "$_dest"
    echo -e "${GREEN}[OK] 已更新缓存脚本: ${_dest}${PLAIN}"
}

update_menu() {
    while true; do
        show_header
        echo -e "${WHITE}${BOLD}更新脚本 / 更新核心${PLAIN}"
        echo ""
        echo -e "  [1] 更新 install.sh 主入口"
        echo -e "  [2] 更新 AnyTLS / sing-box core"
        echo -e "  [3] 更新 Hysteria2 core"
        echo -e "  [4] 更新 Shadowsocks-Rust core"
        echo -e "  [5] 更新全部脚本"
        echo -e "  [6] 更新全部核心"
        echo -e "  [0] 返回"
        echo ""
        read -r -p "  请选择 [0-6]: " opt
        case "$opt" in
            1)
                backup_config || true
                if [ -f "$0" ]; then
                    install_curl_if_missing && curl -fsSL --connect-timeout 15 --max-time 60 "$INSTALL_URL" -o "${0}.tmp" && bash -n "${0}.tmp" && mv -f "${0}.tmp" "$0" \
                        && echo -e "${GREEN}[OK] install.sh 已更新${PLAIN}" || echo -e "${RED}[ERROR] 更新失败，已保留当前脚本${PLAIN}"
                else
                    echo -e "${YELLOW}[WARN] 当前是进程替换运行，无法原地更新 install.sh${PLAIN}"
                fi
                pause_return
                ;;
            2) backup_config || true; run_script "AnyTLS" "$ANYTLS_URL" ;;
            3) backup_config || true; run_script "Hysteria2" "$HY2_URL" ;;
            4) backup_config || true; run_script "Shadowsocks" "$SS_URL" ;;
            5)
                download_script_to_cache install.sh "$INSTALL_URL"
                download_script_to_cache anytls.sh "$ANYTLS_URL"
                download_script_to_cache hy2.sh "$HY2_URL"
                download_script_to_cache ss.sh "$SS_URL"
                download_script_to_cache euservhy2.sh "$EUSERV_URL"
                pause_return
                ;;
            6) backup_config || true; run_script "AnyTLS" "$ANYTLS_URL"; run_script "Hysteria2" "$HY2_URL"; run_script "Shadowsocks" "$SS_URL" ;;
            0) return ;;
            *) echo -e "${RED}无效选项${PLAIN}"; sleep 1 ;;
        esac
    done
}

uninstall_menu() {
    while true; do
        show_header
        echo -e "${WHITE}${BOLD}卸载协议${PLAIN}"
        echo ""
        echo -e "  [1] 卸载 AnyTLS"
        echo -e "  [2] 卸载 Hysteria2"
        echo -e "  [3] 卸载 Shadowsocks"
        echo -e "  [4] 卸载 EUserv HY2"
        echo -e "  [5] 卸载全部协议"
        echo -e "  [6] 删除所有配置"
        echo -e "  [7] 删除所有备份"
        echo -e "  [0] 返回"
        echo ""
        read -r -p "  请选择 [0-7]: " opt
        case "$opt" in
            1) run_script "AnyTLS" "$ANYTLS_URL" ;;
            2) run_script "Hysteria2" "$HY2_URL" ;;
            3) run_script "Shadowsocks" "$SS_URL" ;;
            4) run_script "EUserv IPv6 HY2" "$EUSERV_URL" ;;
            5) read -r -p "确认加载所有协议脚本执行卸载？[y/N]: " c; case "$c" in [yY]) run_script "AnyTLS" "$ANYTLS_URL"; run_script "Hysteria2" "$HY2_URL"; run_script "Shadowsocks" "$SS_URL"; run_script "EUserv IPv6 HY2" "$EUSERV_URL" ;; *) echo "已取消。" ;; esac ;;
            6)
                echo -e "${RED}这会删除 /etc/sing-box、/etc/hysteria、/etc/shadowsocks-rust 和相关服务文件。${PLAIN}"
                read -r -p "请输入 DELETE-CONFIG 确认: " c
                if [ "$c" = "DELETE-CONFIG" ]; then
                    backup_config || true
                    service_action anytls-server stop /var/run/anytls-server.pid >/dev/null 2>&1 || true
                    service_action hysteria-server stop /var/run/hysteria.pid >/dev/null 2>&1 || true
                    service_action shadowsocks-server stop /var/run/ssserver.pid >/dev/null 2>&1 || true
                    rm -rf /etc/sing-box /etc/hysteria /etc/shadowsocks-rust
                    rm -f /etc/shadowsocks.json /etc/systemd/system/anytls-server.service /etc/systemd/system/hysteria-server.service /etc/systemd/system/shadowsocks-server.service
                    rm -f /etc/init.d/anytls-server /etc/init.d/hysteria-server /etc/init.d/shadowsocks-server
                    [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload
                    echo -e "${GREEN}[OK] 配置与服务文件已删除${PLAIN}"
                else
                    echo "已取消。"
                fi
                pause_return
                ;;
            7)
                echo -e "${RED}这会删除 ${BACKUP_DIR} 下所有备份。${PLAIN}"
                read -r -p "请输入 DELETE-BACKUP 确认: " c
                if [ "$c" = "DELETE-BACKUP" ] && [ -d "$BACKUP_DIR" ]; then
                    find "$BACKUP_DIR" -maxdepth 1 -name 'backup-*.tar.gz' -type f -print -delete
                    echo -e "${GREEN}[OK] 备份已删除${PLAIN}"
                else
                    echo "已取消。"
                fi
                pause_return
                ;;
            0) return ;;
            *) echo -e "${RED}无效选项${PLAIN}"; sleep 1 ;;
        esac
    done
}

main_menu() {
    while true; do
        show_header
        show_status_summary
        echo -e "  ${WHITE}${BOLD}主菜单${PLAIN}"
        echo ""
        echo -e "  [1] 安装 / 重装协议"
        echo -e "  [2] 查看节点信息"
        echo -e "  [3] 导出客户端配置"
        echo -e "  [4] 服务管理"
        echo -e "  [5] 生成二维码"
        echo -e "  [6] 系统检测"
        echo -e "  [7] 备份 / 恢复"
        echo -e "  [8] 更新脚本 / 更新核心"
        echo -e "  [9] 卸载协议"
        echo -e "  [0] 退出"
        echo ""
        read -r -p "  请输入选项 [0-9]: " choice

        case "$choice" in
            1) install_menu ;;
            2) node_info_menu ;;
            3) export_config_menu ;;
            4) service_management_menu ;;
            5) qrcode_menu ;;
            6) system_detect ;;
            7) backup_restore_menu ;;
            8) update_menu ;;
            9) uninstall_menu ;;
            0|q|quit|exit)
                echo ""
                echo -e "${DIM}感谢使用 Sing-box Multi-Protocol Tools，再见！${PLAIN}"
                echo ""
                exit 0
                ;;
            *) echo -e "${RED}无效选项，请输入 0-9${PLAIN}"; sleep 1 ;;
        esac
    done
}

check_root
main_menu
