#!/bin/bash
#====================================================================================
# 项目：AnyTLS Management Script
# 作者：Jensfrank
# 版本：v1.0.1
# GitHub: https://github.com/everett7623/hy2
# 更新日期: 2026-07-01
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

# ---- 路径 ----
BIN="/usr/local/bin/anytls-server"
SERVICE_FILE="/etc/systemd/system/anytls.service"
OPENRC_SERVICE="/etc/init.d/anytls"
CONFIG_DIR="/etc/anytls"
META_DIR="/etc/anytls/meta"
LOG_FILE="/var/log/anytls.log"

# ---- 运行时变量 ----
INIT_SYS=""
LATEST_TAG=""
LATEST_VERSION=""
CURRENT_VERSION=""
LISTEN_PORT=""
PASSWORD=""
PUBLIC_IPV4=""
PUBLIC_IPV6=""

# ============================================================
# 工具函数
# ============================================================
check_root() {
    [ "$EUID" -ne 0 ] && echo -e "${RED}错误: 请以 root 权限运行${PLAIN}" && exit 1
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

service_start() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl start anytls
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service anytls start
    else
        nohup "$BIN" -l "0.0.0.0:${LISTEN_PORT}" -p "$PASSWORD" >/var/log/anytls.log 2>&1 &
        echo $! > /var/run/anytls.pid
    fi
}

service_stop() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl stop anytls 2>/dev/null
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service anytls stop 2>/dev/null
    else
        [ -f /var/run/anytls.pid ] && kill "$(cat /var/run/anytls.pid)" 2>/dev/null && rm -f /var/run/anytls.pid
        pkill -f "anytls-server" 2>/dev/null
    fi
}

service_restart() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl restart anytls
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service anytls restart
    else
        service_stop
        sleep 1
        service_start
    fi
}

service_enable() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl daemon-reload
        systemctl enable anytls >/dev/null 2>&1
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-update add anytls default >/dev/null 2>&1
    fi
}

service_disable() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl disable anytls 2>/dev/null
        systemctl daemon-reload
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-update del anytls default 2>/dev/null
    fi
}

service_is_active() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl is-active --quiet anytls
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service anytls status 2>/dev/null | grep -q "started"
    else
        [ -f /var/run/anytls.pid ] && kill -0 "$(cat /var/run/anytls.pid)" 2>/dev/null
    fi
}

service_logs() {
    if [ "$INIT_SYS" = "systemd" ]; then
        journalctl -u anytls -n 50 --no-pager 2>/dev/null
    else
        tail -n 50 /var/log/anytls.log 2>/dev/null || echo -e "${YELLOW}暂无日志${PLAIN}"
    fi
}

valid_port() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

valid_password() {
    echo "$1" | grep -qE '^[A-Za-z0-9]+$'
}

gen_password() {
    local _pass=""
    while [ ${#_pass} -lt 24 ]; do
        _pass="${_pass}$(openssl rand -base64 32 2>/dev/null | tr -dc 'A-Za-z0-9' | tr -d '\n')"
    done
    printf '%s' "$(printf '%s' "$_pass" | cut -c 1-24)"
}

detect_network() {
    PUBLIC_IPV4=""
    PUBLIC_IPV6=""

    local _ip _url
    for _url in "https://api.ipify.org" "https://ip.sb" "https://ipv4.icanhazip.com"; do
        _ip=$(curl -4 -s --max-time 4 "$_url" 2>/dev/null | tr -d '[:space:]')
        if echo "$_ip" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
            PUBLIC_IPV4="$_ip"
            break
        fi
    done

    for _url in "https://api6.ipify.org" "https://ipv6.icanhazip.com"; do
        _ip=$(curl -6 -s --max-time 4 "$_url" 2>/dev/null | tr -d '[:space:]')
        if echo "$_ip" | grep -q ':'; then
            PUBLIC_IPV6="$_ip"
            break
        fi
    done
}

install_dependencies() {
    echo -e "${YELLOW}正在安装依赖...${PLAIN}"
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq >/dev/null 2>&1
        apt-get install -y -qq curl wget unzip ca-certificates openssl procps >/dev/null 2>&1
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y curl wget unzip ca-certificates openssl procps-ng >/dev/null 2>&1
    elif command -v yum >/dev/null 2>&1; then
        yum install -y curl wget unzip ca-certificates openssl procps-ng >/dev/null 2>&1
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Sy --noconfirm curl wget unzip ca-certificates openssl procps-ng >/dev/null 2>&1
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache curl wget unzip ca-certificates openssl procps >/dev/null 2>&1
    fi

    local _cmd
    for _cmd in curl wget unzip openssl; do
        command -v "$_cmd" >/dev/null 2>&1 || {
            echo -e "${RED}依赖安装失败: 缺少 ${_cmd}${PLAIN}"
            return 1
        }
    done
}

get_latest_version() {
    echo -e "${YELLOW}正在获取最新版本...${PLAIN}"

    local _raw_tag
    _raw_tag=$(curl -Ls --max-time 15 "https://api.github.com/repos/anytls/anytls-go/releases/latest" \
        | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' | head -1)

    if [ -z "$_raw_tag" ]; then
        _raw_tag=$(curl -Ls --max-time 15 -o /dev/null -w "%{url_effective}" \
            "https://github.com/anytls/anytls-go/releases/latest" | sed 's|.*/tag/||')
    fi

    [ -z "$_raw_tag" ] && echo -e "${RED}获取版本失败，请检查网络${PLAIN}" && return 1

    LATEST_TAG="$_raw_tag"
    LATEST_VERSION="${_raw_tag#v}"
    echo -e "${GREEN}最新版本: ${LATEST_VERSION}${PLAIN}"
}

detect_arch() {
    case $(uname -m) in
        x86_64)        echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        *) echo -e "${RED}不支持的架构: $(uname -m)${PLAIN}" ; return 1 ;;
    esac
}

download_anytls() {
    local _arch _url _tmp_zip _tmp_dir _candidate
    _arch=$(detect_arch) || return 1
    _url="https://github.com/anytls/anytls-go/releases/download/${LATEST_TAG}/anytls_${LATEST_VERSION}_linux_${_arch}.zip"
    _tmp_zip=$(mktemp /tmp/anytls-XXXXXX.zip 2>/dev/null) || {
        echo -e "${RED}无法创建下载临时文件${PLAIN}"
        return 1
    }
    _tmp_dir=$(mktemp -d /tmp/anytls-XXXXXX 2>/dev/null) || {
        rm -f "$_tmp_zip"
        echo -e "${RED}无法创建解压临时目录${PLAIN}"
        return 1
    }

    echo -e "${YELLOW}正在下载 anytls_${LATEST_VERSION}_linux_${_arch}.zip...${PLAIN}"
    wget -q --show-progress --timeout=30 -O "$_tmp_zip" "$_url" 2>/dev/null || {
        rm -f "$_tmp_zip"
        rm -rf "$_tmp_dir"
        echo -e "${RED}下载失败，请检查网络${PLAIN}"
        return 1
    }

    unzip -o "$_tmp_zip" -d "$_tmp_dir" >/dev/null 2>&1 || {
        rm -f "$_tmp_zip"
        rm -rf "$_tmp_dir"
        echo -e "${RED}解压失败${PLAIN}"
        return 1
    }

    _candidate=$(find "$_tmp_dir" -type f -name anytls-server -print -quit 2>/dev/null)
    if [ -z "$_candidate" ]; then
        rm -f "$_tmp_zip"
        rm -rf "$_tmp_dir"
        echo -e "${RED}未找到 anytls-server 二进制${PLAIN}"
        return 1
    fi

    chmod +x "$_candidate"
    mv -f "$_candidate" "$BIN"
    rm -f "$_tmp_zip"
    rm -rf "$_tmp_dir"
    echo -e "${GREEN}下载完成${PLAIN}"
}

save_meta() {
    mkdir -p "$META_DIR"
    echo "$LATEST_VERSION" > "$META_DIR/version"
    echo "$LISTEN_PORT" > "$META_DIR/listen_port"
    echo "$PASSWORD" > "$META_DIR/password"
    [ -n "$PUBLIC_IPV4" ] && echo "$PUBLIC_IPV4" > "$META_DIR/public_ipv4"
    [ -n "$PUBLIC_IPV6" ] && echo "$PUBLIC_IPV6" > "$META_DIR/public_ipv6"
}

read_meta() {
    CURRENT_VERSION=$(cat "$META_DIR/version" 2>/dev/null || true)
    LISTEN_PORT=$(cat "$META_DIR/listen_port" 2>/dev/null || true)
    PASSWORD=$(cat "$META_DIR/password" 2>/dev/null || true)
    PUBLIC_IPV4=$(cat "$META_DIR/public_ipv4" 2>/dev/null || true)
    PUBLIC_IPV6=$(cat "$META_DIR/public_ipv6" 2>/dev/null || true)
}

setup_systemd_service() {
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=AnyTLS Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=${BIN} -l 0.0.0.0:${LISTEN_PORT} -p ${PASSWORD}
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

name="anytls"
description="AnyTLS Server"
SVCHEAD
    cat >> "$OPENRC_SERVICE" <<EOF
command="${BIN}"
command_args="-l 0.0.0.0:${LISTEN_PORT} -p ${PASSWORD}"
command_background=true
pidfile="/var/run/anytls.pid"
output_log="/var/log/anytls.log"
error_log="/var/log/anytls.log"

depend() {
    need net
}
EOF
    chmod +x "$OPENRC_SERVICE"
}

build_uri() {
    local _host="$1"
    case "$_host" in
        *:*) _host="[${_host}]" ;;
    esac
    printf 'anytls://%s@%s:%s' "$PASSWORD" "$_host" "$LISTEN_PORT"
}

show_config() {
    detect_network
    read_meta

    echo ""
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    echo -e "  ${BOLD}AnyTLS 连接信息${PLAIN}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    echo -e "  状态: ${GREEN}已安装${PLAIN} ${DIM}${CURRENT_VERSION:-未知}${PLAIN}"
    echo -e "  监听端口: ${YELLOW}${LISTEN_PORT:-8443}${PLAIN}"

    if [ -n "$PUBLIC_IPV4" ]; then
        echo -e "  IPv4 URI: ${YELLOW}$(build_uri "$PUBLIC_IPV4")${PLAIN}"
    fi
    if [ -n "$PUBLIC_IPV6" ]; then
        echo -e "  IPv6 URI: ${YELLOW}$(build_uri "$PUBLIC_IPV6")${PLAIN}"
    fi
    if [ -z "$PUBLIC_IPV4" ] && [ -z "$PUBLIC_IPV6" ]; then
        echo -e "  URI: ${YELLOW}anytls://$PASSWORD@服务器IP:${LISTEN_PORT}${PLAIN}"
    fi

    if command -v qrencode >/dev/null 2>&1 && [ -n "$PUBLIC_IPV4" ]; then
        echo ""
        qrencode -t ANSIUTF8 "$(build_uri "$PUBLIC_IPV4")" 2>/dev/null || true
    fi

    echo ""
    read -r -p "按回车继续..." _tmp
}

show_banner() {
    echo -e "${CYAN}"
    echo "  █████╗ ███╗   ██╗██╗   ██╗████████╗██╗     ███████╗"
    echo "  ██╔══██╗████╗  ██║╚██╗ ██╔╝╚══██╔══╝██║     ██╔════╝"
    echo "  ███████║██╔██╗ ██║ ╚████╔╝    ██║   ██║     ███████╗"
    echo "  ██╔══██║██║╚██╗██║  ╚██╔╝     ██║   ██║     ╚════██║"
    echo "  ██║  ██║██║ ╚████║   ██║      ██║   ███████╗███████║"
    echo "  ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝      ╚═╝   ╚══════╝╚══════╝"
    echo -e "${PLAIN}"
}

show_status() {
    read_meta
    if [ -f "$BIN" ]; then
        if service_is_active; then
            echo -e "  当前状态: ${GREEN}● 运行中${PLAIN}${DIM} ${CURRENT_VERSION:-未知}${PLAIN}"
        else
            echo -e "  当前状态: ${YELLOW}● 已停止${PLAIN}${DIM} ${CURRENT_VERSION:-未知}${PLAIN}"
        fi
    else
        echo -e "  当前状态: ${RED}● 未安装${PLAIN}"
    fi
}

# ============================================================
# 安装 / 升级 / 卸载
# ============================================================
install_anytls() {
    install_dependencies || return
    detect_init
    get_latest_version || return
    download_anytls || return

    mkdir -p "$CONFIG_DIR" "$META_DIR"

    echo ""
    echo -e "${YELLOW}配置 AnyTLS 服务器${PLAIN}"
    read -r -p "请输入监听端口 [默认 8443]: " LISTEN_PORT
    [[ -z "$LISTEN_PORT" ]] && LISTEN_PORT="8443"
    valid_port "$LISTEN_PORT" || { echo -e "${RED}端口必须为 1-65535 的整数${PLAIN}"; return; }

    read -r -p "请输入连接密码 [留空自动生成]: " PASSWORD
    if [ -z "$PASSWORD" ]; then
        PASSWORD=$(gen_password)
    fi
    valid_password "$PASSWORD" || {
        echo -e "${RED}密码只能包含字母和数字，避免 URI 和服务文件解析问题${PLAIN}"
        return
    }

    if [ "$INIT_SYS" = "systemd" ]; then
        setup_systemd_service
    elif [ "$INIT_SYS" = "openrc" ]; then
        setup_openrc_service
    fi

    service_enable
    save_meta
    service_start
    sleep 2

    if service_is_active; then
        echo -e "${GREEN}✓ AnyTLS 安装成功${PLAIN}"
        show_config
    else
        echo -e "${RED}✗ AnyTLS 启动失败，请查看日志${PLAIN}"
        service_logs
        sleep 2
    fi
}

upgrade_anytls() {
    if [ ! -f "$BIN" ]; then
        echo -e "${RED}未检测到已安装的 AnyTLS，请先安装${PLAIN}"
        sleep 2
        return
    fi

    read_meta
    get_latest_version || return

    if [ -n "$CURRENT_VERSION" ] && [ "$CURRENT_VERSION" = "$LATEST_VERSION" ]; then
        echo -e "${GREEN}已是最新版本，无需升级${PLAIN}"
        sleep 2
        return
    fi

    echo -e "${YELLOW}开始升级: ${CURRENT_VERSION:-未知} → ${LATEST_VERSION}${PLAIN}"
    cp "$BIN" "${BIN}.bak" 2>/dev/null || {
        echo -e "${RED}无法备份当前二进制，取消升级${PLAIN}"
        return
    }

    if download_anytls; then
        service_restart
        sleep 2
        if service_is_active; then
            echo "$LATEST_VERSION" > "$META_DIR/version"
            rm -f "${BIN}.bak"
            echo -e "${GREEN}✓ 升级成功${PLAIN}"
        else
            mv -f "${BIN}.bak" "$BIN"
            service_restart
            echo -e "${RED}✗ 升级后服务启动失败，已回滚${PLAIN}"
            service_logs
        fi
    else
        mv -f "${BIN}.bak" "$BIN"
        echo -e "${RED}✗ 下载失败，已回滚${PLAIN}"
    fi
    sleep 2
}

uninstall_anytls() {
    read -r -p "确定卸载 AnyTLS? [y/N]: " confirm
    [[ ! "$confirm" =~ ^[yY]$ ]] && return

    service_stop
    service_disable
    rm -f "$SERVICE_FILE" "$OPENRC_SERVICE" "$BIN" "$LOG_FILE"
    rm -rf "$CONFIG_DIR"
    rm -f /var/run/anytls.pid

    echo -e "${GREEN}已卸载完成${PLAIN}"
    sleep 2
}

# ============================================================
# 管理菜单
# ============================================================
manage_anytls() {
    while true; do
        clear
        show_banner
        show_status
        echo ""
        echo -e "  ${WHITE}${BOLD}1.${PLAIN} 查看连接信息"
        echo -e "  ${WHITE}${BOLD}2.${PLAIN} 重启服务"
        echo -e "  ${WHITE}${BOLD}3.${PLAIN} 停止服务"
        echo -e "  ${WHITE}${BOLD}4.${PLAIN} 启动服务"
        echo -e "  ${WHITE}${BOLD}5.${PLAIN} 查看日志"
        echo -e "  ${YELLOW}${BOLD}0.${PLAIN} 返回"
        echo ""
        read -r -p "请选择: " opt
        case "$opt" in
            1) show_config ;;
            2) service_restart && echo -e "${GREEN}服务已重启${PLAIN}" && sleep 1 ;;
            3) service_stop && echo -e "${YELLOW}服务已停止${PLAIN}" && sleep 1 ;;
            4) service_start && echo -e "${GREEN}服务已启动${PLAIN}" && sleep 1 ;;
            5) service_logs; echo ""; read -r -p "按回车继续..." _tmp ;;
            0) return ;;
            *) echo -e "${RED}输入错误${PLAIN}"; sleep 1 ;;
        esac
    done
}

# ============================================================
# 主菜单
# ============================================================
main_menu() {
    while true; do
        clear
        show_banner
        show_status
        echo ""
        echo -e "  ${GREEN}${BOLD}1.${PLAIN} 安装 AnyTLS"
        echo -e "  ${GREEN}${BOLD}2.${PLAIN} 管理 AnyTLS"
        echo -e "  ${GREEN}${BOLD}3.${PLAIN} 升级 AnyTLS"
        echo -e "  ${GREEN}${BOLD}4.${PLAIN} 卸载 AnyTLS"
        echo -e "  ${YELLOW}${BOLD}0.${PLAIN} 退出"
        echo ""
        read -r -p "请输入选项 [0-4]: " choice
        case "$choice" in
            1) install_anytls ;;
            2) manage_anytls ;;
            3) upgrade_anytls ;;
            4) uninstall_anytls ;;
            0|q|quit|exit)
                echo ""
                echo -e "  ${DIM}感谢使用 AnyTLS Tools，再见！${PLAIN}"
                echo ""
                exit 0
                ;;
            *)
                echo -e "  ${RED}无效选项，请输入 0-4${PLAIN}"
                sleep 1
                ;;
        esac
    done
}

# ============================================================
# 入口
# ============================================================
check_root
main_menu
