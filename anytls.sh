#!/bin/bash
#====================================================================================
# 项目：AnyTLS Management Script
# 作者：Jensfrank
# 版本：v1.0.2
# GitHub: https://github.com/everett7623/hy2
# Seedloc博客: https://seedloc.com
# VPSknow网站：https://vpsknow.com
# Nodeloc论坛: https://nodeloc.com
# 更新日期: 2026-06-30
#
# AnyTLS Management Script v1.0.2
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
#
# v1.0.1: AnyTLS 协议支持 - TCP 传输，适合 UDP 受限网络
#====================================================================================

# ============================================================
# 自举：确保以 bash 运行
# Alpine 等系统默认 sh 为 busybox，不支持 bash 语法
# ============================================================
if [ -z "$BASH_VERSION" ]; then
    if command -v bash >/dev/null 2>&1; then
        exec bash "$0" "$@"
    else
        if [ -f /etc/alpine-release ]; then
            apk add --no-cache bash >/dev/null 2>&1
        elif command -v apt-get >/dev/null 2>&1; then
            apt-get update -qq >/dev/null 2>&1
            apt-get install -y -qq bash >/dev/null 2>&1
        elif command -v yum >/dev/null 2>&1; then
            yum install -y bash >/dev/null 2>&1
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y bash >/dev/null 2>&1
        fi
        command -v bash >/dev/null 2>&1 || { echo "错误: 无法安装 bash，请手动安装后重试"; exit 1; }
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
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
PLAIN='\033[0m'
BOLD='\033[1m'

# --- 路径 ---
ANYTLS_BIN="/usr/local/bin/anytls-go"
ANYTLS_CONFIG="/etc/anytls/config.yaml"
ANYTLS_CERT_DIR="/etc/anytls/cert"
ANYTLS_META="/etc/anytls/meta"
SERVICE_FILE="/etc/systemd/system/anytls-server.service"
OPENRC_SERVICE="/etc/init.d/anytls-server"
AUTO_UPDATE_SCRIPT="/usr/local/bin/anytls-autoupdate.sh"
AUTO_UPDATE_LOG="/var/log/anytls-autoupdate.log"
BBR_CONFIG="/etc/sysctl.d/99-anytls-bbr.conf"

# --- 运行时变量 ---
NAT_MODE=0
HAS_IPV4=0
HAS_IPV6=0
PUBLIC_IP=""
PUBLIC_IPV6=""
LISTEN_PORT=""
EXT_PORT=""
PASSWORD=""
SNI="microsoft.com"
INIT_SYS=""

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
}

detect_init() {
    if command -v systemctl >/dev/null 2>&1 && systemctl --version >/dev/null 2>&1; then
        INIT_SYS="systemd"
    elif command -v rc-service >/dev/null 2>&1 && [ -d /etc/init.d ]; then
        INIT_SYS="openrc"
    else
        INIT_SYS="none"
    fi
}

detect_network() {
    HAS_IPV4=0
    HAS_IPV6=0
    PUBLIC_IP=""
    PUBLIC_IPV6=""

    # IPv4 检测
    for api in "https://api.ipify.org" "https://ip4.seeip.org" "https://icanhazip.com"; do
        ip=$(curl -s --connect-timeout 3 --max-time 6 "$api" 2>/dev/null)
        if [ -n "$ip" ] && echo "$ip" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
            PUBLIC_IP="$ip"
            HAS_IPV4=1
            break
        fi
    done

    # IPv6 检测
    for api in "https://api6.ipify.org" "https://ip6.seeip.org"; do
        ip=$(curl -s --max-time 6 "$api" 2>/dev/null)
        if [ -n "$ip" ] && echo "$ip" | grep -q ':'; then
            PUBLIC_IPV6="$ip"
            HAS_IPV6=1
            break
        fi
    done

    # 如果 API 失败，回退到本地地址
    if [ $HAS_IPV4 -eq 0 ]; then
        LOCAL_IP=$(ip addr show 2>/dev/null | awk '/inet / && !/127\.0\.0\.1/ {print $2}' | cut -d/ -f1 | head -n1)
        if [ -n "$LOCAL_IP" ]; then
            PUBLIC_IP="$LOCAL_IP"
            HAS_IPV4=1
        fi
    fi

    if [ $HAS_IPV6 -eq 0 ]; then
        # 过滤 WARP/tunnel 网卡和链路本地地址
        LOCAL_IPV6=$(ip addr show 2>/dev/null | awk '/inet6/ {
            iface=$2
            getline
            if ($0 ~ /inet6/) {
                addr=$2
                gsub(/\/.*/, "", addr)
                # 排除 fe80 链路本地
                if (addr !~ /^fe80:/ && addr !~ /^2606:4700:/) {
                    # 排除 WARP/tunnel 网卡
                    if (iface !~ /wgcf|warp|tun|wg|tailscale|zt/) {
                        print addr
                        exit
                    }
                }
            }
        }' | head -n1)
        if [ -n "$LOCAL_IPV6" ]; then
            PUBLIC_IPV6="$LOCAL_IPV6"
            HAS_IPV6=1
        fi
    fi
}

install_dependencies() {
    echo -e "${YELLOW}正在安装依赖...${PLAIN}"

    case "$RELEASE" in
        debian)
            apt-get update -qq
            apt-get install -y -qq curl wget openssl ca-certificates iproute2 >/dev/null 2>&1
            ;;
        centos|rocky)
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y -q curl wget openssl ca-certificates iproute >/dev/null 2>&1
            else
                yum install -y -q curl wget openssl ca-certificates iproute >/dev/null 2>&1
            fi
            ;;
        fedora)
            dnf install -y -q curl wget openssl ca-certificates iproute >/dev/null 2>&1
            ;;
        alpine)
            apk add --no-cache curl wget openssl ca-certificates iproute2 >/dev/null 2>&1
            ;;
        arch)
            pacman -Sy --noconfirm curl wget openssl ca-certificates iproute2 >/dev/null 2>&1
            ;;
        *)
            echo -e "${YELLOW}警告: 未知系统，跳过依赖安装${PLAIN}"
            ;;
    esac
}

# ============================================================
# 验证函数
# ============================================================

validate_port() {
    local port="$1"
    # 空值检查
    [ -z "$port" ] && return 1
    # 纯数字检查（不含前导零，"0" 除外）
    if [ "$port" = "0" ]; then
        return 1
    fi
    echo "$port" | grep -qE '^[0-9]+$' || return 1
    # 拒绝前导零
    [ "${port#0}" != "$port" ] && return 1
    # 范围检查 [1, 65535]
    [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || return 1
    return 0
}

validate_password() {
    local pw="$1"
    # 长度检查 [1, 128]
    [ -z "$pw" ] && return 1
    [ ${#pw} -gt 128 ] && return 1
    # 禁止字符: " \ ` $ 和控制字符
    case "$pw" in
        *\"*|*\\*|*\`*|*\$*) return 1 ;;
    esac
    # 检查控制字符 (0x00-0x1F, 0x7F)
    if echo "$pw" | grep -q $'[\x00-\x1F\x7F]'; then
        return 1
    fi
    return 0
}

validate_domain() {
    local domain="$1"
    [ -z "$domain" ] && return 1
    # 仅允许字母、数字、点号、连字符
    echo "$domain" | grep -qE '^[a-zA-Z0-9.-]+$' || return 1
    # 不以点号或连字符开头/结尾
    case "$domain" in
        .*|*.-|-.*) return 1 ;;
    esac
    # 禁止协议前缀和端口号
    echo "$domain" | grep -qE '^(http|https)://' && return 1
    echo "$domain" | grep -qE ':' && return 1
    return 0
}

validate_binary() {
    local bin="$1"
    [ -f "$bin" ] || return 1
    # 检查 ELF magic bytes
    local magic
    magic=$(od -A d -t x1 -N 4 "$bin" 2>/dev/null | awk 'NR==1 { print $2, $3, $4, $5 }')
    [ "$magic" = "7f 45 4c 46" ] && return 0
    # 或尝试执行 version 子命令
    if [ -x "$bin" ]; then
        "$bin" version >/dev/null 2>&1 && return 0
    fi
    return 1
}

# ============================================================
# 下载与版本
# ============================================================

get_latest_version() {
    local version
    version=$(curl -s "https://api.github.com/repos/anytls/anytls-go/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    echo "$version"
}

download_anytls() {
    local version="$1"
    local arch

    case "$(uname -m)" in
        x86_64)   arch="amd64" ;;
        aarch64)  arch="arm64" ;;
        armv7l)   arch="arm" ;;
        s390x)    arch="s390x" ;;
        loongarch64) arch="loong64" ;;
        *)        echo -e "${RED}不支持的架构: $(uname -m)${PLAIN}"; return 1 ;;
    esac

    local url="https://github.com/anytls/anytls-go/releases/download/${version}/anytls-linux-${arch}"
    local tmp_bin
    tmp_bin=$(mktemp /tmp/anytls-XXXXXX 2>/dev/null) || {
        echo -e "${RED}无法创建下载临时文件${PLAIN}"
        return 1
    }

    echo -e "${YELLOW}正在下载 AnyTLS ${version} (${arch})...${PLAIN}"
    if ! wget -q --show-progress --timeout=30 -O "$tmp_bin" "$url"; then
        echo -e "${RED}下载失败${PLAIN}"
        rm -f "$tmp_bin"
        return 1
    fi

    chmod +x "$tmp_bin"

    # 验证二进制
    if ! validate_binary "$tmp_bin"; then
        echo -e "${RED}下载的文件无效${PLAIN}"
        rm -f "$tmp_bin"
        return 1
    fi

    mv "$tmp_bin" "$ANYTLS_BIN"
    chmod +x "$ANYTLS_BIN"
    echo -e "${GREEN}下载完成${PLAIN}"
    return 0
}

# ============================================================
# 备份回滚
# ============================================================

backup_binary() {
    [ -f "$ANYTLS_BIN" ] || return 0
    cp "$ANYTLS_BIN" "${ANYTLS_BIN}.bak" || return 1
}

rollback_binary() {
    [ -f "${ANYTLS_BIN}.bak" ] || return 1
    mv "${ANYTLS_BIN}.bak" "$ANYTLS_BIN" || return 1
    chmod +x "$ANYTLS_BIN"
}

# ============================================================
# 防火墙管理
# ============================================================

open_firewall_port() {
    local port="$1"
    local proto="${2:-tcp}"

    if command -v ufw >/dev/null 2>&1; then
        ufw allow "${port}/${proto}" >/dev/null 2>&1
    elif command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port="${port}/${proto}" >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
    else
        # iptables 幂等检查
        if command -v iptables >/dev/null 2>&1; then
            iptables -C INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null || \
                iptables -I INPUT -p "$proto" --dport "$port" -j ACCEPT
        fi
        if command -v ip6tables >/dev/null 2>&1; then
            ip6tables -C INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null || \
                ip6tables -I INPUT -p "$proto" --dport "$port" -j ACCEPT
        fi
        # 持久化
        command -v iptables-save >/dev/null 2>&1 && iptables-save >/etc/iptables/rules.v4 2>/dev/null
        command -v ip6tables-save >/dev/null 2>&1 && ip6tables-save >/etc/iptables/rules.v6 2>/dev/null
    fi
}

close_firewall_port() {
    local port="$1"
    local proto="${2:-tcp}"

    if command -v ufw >/dev/null 2>&1; then
        ufw delete allow "${port}/${proto}" >/dev/null 2>&1
    elif command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --remove-port="${port}/${proto}" >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
    else
        if command -v iptables >/dev/null 2>&1; then
            iptables -D INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null
        fi
        if command -v ip6tables >/dev/null 2>&1; then
            ip6tables -D INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null
        fi
    fi
}

# ============================================================
# 服务管理
# ============================================================

service_start() {
    case "$INIT_SYS" in
        systemd)
            systemctl start anytls-server
            systemctl enable anytls-server >/dev/null 2>&1
            ;;
        openrc)
            rc-service anytls-server start
            rc-update add anytls-server default >/dev/null 2>&1
            ;;
        *)
            "$ANYTLS_BIN" -c "$ANYTLS_CONFIG" >/dev/null 2>&1 &
            ;;
    esac
}

service_stop() {
    case "$INIT_SYS" in
        systemd)
            systemctl stop anytls-server
            systemctl disable anytls-server >/dev/null 2>&1
            ;;
        openrc)
            rc-service anytls-server stop
            rc-update del anytls-server default >/dev/null 2>&1
            ;;
        *)
            pkill -f "anytls-go" >/dev/null 2>&1
            ;;
    esac
}

service_restart() {
    case "$INIT_SYS" in
        systemd)
            systemctl restart anytls-server
            ;;
        openrc)
            rc-service anytls-server restart
            ;;
        *)
            service_stop
            sleep 1
            service_start
            ;;
    esac
}

service_is_active() {
    case "$INIT_SYS" in
        systemd)
            systemctl is-active anytls-server >/dev/null 2>&1
            ;;
        openrc)
            rc-service anytls-server status | grep -q "started"
            ;;
        *)
            pgrep -f "anytls-go" >/dev/null
            ;;
    esac
}

# ============================================================
# 配置生成
# ============================================================

gen_cert() {
    mkdir -p "$ANYTLS_CERT_DIR"
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout "$ANYTLS_CERT_DIR/key.pem" \
        -out "$ANYTLS_CERT_DIR/cert.pem" \
        -subj "/CN=$SNI" >/dev/null 2>&1
}

gen_config() {
    mkdir -p /etc/anytls

    cat > "$ANYTLS_CONFIG" << EOF
listen: 0.0.0.0:$LISTEN_PORT
cert: $ANYTLS_CERT_DIR/cert.pem
key: $ANYTLS_CERT_DIR/key.pem
sni: $SNI
password: $PASSWORD
EOF

    # 保存元数据
    mkdir -p "$ANYTLS_META"
    cat > "$ANYTLS_META/config" << EOF
LISTEN_PORT=$LISTEN_PORT
EXT_PORT=$EXT_PORT
PASSWORD=$PASSWORD
SNI=$SNI
VERSION=$(get_latest_version)
EOF
}

show_config() {
    if [ ! -f "$ANYTLS_META/config" ]; then
        echo -e "${RED}未找到配置信息${PLAIN}"
        return
    fi

    . "$ANYTLS_META/config"

    local display_port="$LISTEN_PORT"
    [ "$NAT_MODE" = "1" ] && display_port="$EXT_PORT"

    echo -e "${GREEN}=== AnyTLS 节点信息 ===${PLAIN}"
    echo -e "${CYAN}服务器地址:${PLAIN} ${PUBLIC_IP:-$PUBLIC_IPV6}"
    echo -e "${CYAN}端口:${PLAIN} $display_port"
    echo -e "${CYAN}密码:${PLAIN} $PASSWORD"
    echo -e "${CYAN}SNI:${PLAIN} $SNI"
    echo -e "${CYAN}协议:${PLAIN} anytls"

    # Shadowrocket URI
    local uri="anytls://$PASSWORD@${PUBLIC_IP:-$PUBLIC_IPV6}:$display_port?sni=$SNI"
    echo -e "\n${CYAN}Shadowrocket URI:${PLAIN}"
    echo "$uri"

    # Clash Meta 配置
    echo -e "\n${CYAN}Clash Meta 配置:${PLAIN}"
    cat << EOF
- name: AnyTLS
  type: anytls
  server: ${PUBLIC_IP:-$PUBLIC_IPV6}
  port: $display_port
  password: $PASSWORD
  sni: $SNI
EOF

    # 二维码
    if command -v qrencode >/dev/null 2>&1; then
        echo -e "\n${CYAN}二维码:${PLAIN}"
        qrencode -t ANSIUTF8 "$uri"
    fi
}

# ============================================================
# 配置修改
# ============================================================

change_port() {
    echo -e "${YELLOW}当前端口: $LISTEN_PORT${PLAIN}"
    read -rp "请输入新端口 [1-65535]: " new_port

    if ! validate_port "$new_port"; then
        echo -e "${RED}端口无效${PLAIN}"
        return
    fi

    # 备份配置
    cp "$ANYTLS_CONFIG" "${ANYTLS_CONFIG}.bak"

    # 修改配置
    LISTEN_PORT="$new_port"
    if [ "$NAT_MODE" = "1" ]; then
        read -rp "请输入外网映射端口: " new_ext
        if validate_port "$new_ext"; then
            EXT_PORT="$new_ext"
        else
            echo -e "${RED}外网端口无效${PLAIN}"
            mv "${ANYTLS_CONFIG}.bak" "$ANYTLS_CONFIG"
            return
        fi
    else
        EXT_PORT="$new_port"
    fi

    gen_config

    # 重启服务
    service_restart
    sleep 3

    if service_is_active; then
        echo -e "${GREEN}端口修改成功${PLAIN}"
        rm -f "${ANYTLS_CONFIG}.bak"
        close_firewall_port "$(grep '^LISTEN_PORT=' "${ANYTLS_META}.bak" | cut -d= -f2)"
        open_firewall_port "$LISTEN_PORT"
    else
        echo -e "${RED}服务启动失败，回滚配置${PLAIN}"
        mv "${ANYTLS_CONFIG}.bak" "$ANYTLS_CONFIG"
        service_restart
    fi
}

change_password() {
    echo -e "${YELLOW}当前密码: $PASSWORD${PLAIN}"
    read -rp "请输入新密码 [1-128字符]: " new_pw

    if ! validate_password "$new_pw"; then
        echo -e "${RED}密码无效${PLAIN}"
        return
    fi

    cp "$ANYTLS_CONFIG" "${ANYTLS_CONFIG}.bak"
    PASSWORD="$new_pw"
    gen_config

    service_restart
    sleep 3

    if service_is_active; then
        echo -e "${GREEN}密码修改成功${PLAIN}"
        rm -f "${ANYTLS_CONFIG}.bak"
    else
        echo -e "${RED}服务启动失败，回滚配置${PLAIN}"
        mv "${ANYTLS_CONFIG}.bak" "$ANYTLS_CONFIG"
        service_restart
    fi
}

change_sni() {
    echo -e "${YELLOW}当前 SNI: $SNI${PLAIN}"
    read -rp "请输入新 SNI 域名: " new_sni

    if ! validate_domain "$new_sni"; then
        echo -e "${RED}域名无效${PLAIN}"
        return
    fi

    cp "$ANYTLS_CONFIG" "${ANYTLS_CONFIG}.bak"
    SNI="$new_sni"
    gen_cert
    gen_config

    service_restart
    sleep 3

    if service_is_active; then
        echo -e "${GREEN}SNI 修改成功${PLAIN}"
        rm -f "${ANYTLS_CONFIG}.bak"
    else
        echo -e "${RED}服务启动失败，回滚配置${PLAIN}"
        mv "${ANYTLS_CONFIG}.bak" "$ANYTLS_CONFIG"
        service_restart
    fi
}

# ============================================================
# 安装/升级/卸载
# ============================================================

install_anytls() {
    echo -e "${GREEN}=== AnyTLS 安装 ===${PLAIN}"

    check_root
    check_sys
    detect_init
    detect_network
    install_dependencies

    # 获取版本
    local version
    version=$(get_latest_version)
    [ -z "$version" ] && { echo -e "${RED}获取版本失败${PLAIN}"; return 1; }
    echo -e "${CYAN}最新版本: $version${PLAIN}"

    # 下载
    download_anytls "$version" || return 1

    # 用户输入
    read -rp "请输入监听端口 [默认 14444]: " input_port
    LISTEN_PORT="${input_port:-14444}"
    validate_port "$LISTEN_PORT" || { echo -e "${RED}端口无效${PLAIN}"; return 1; }

    read -rp "是否为 NAT 机器? [y/N]: " nat_confirm
    if [ "$nat_confirm" = "y" ] || [ "$nat_confirm" = "Y" ]; then
        NAT_MODE=1
        read -rp "请输入外网映射端口: " ext_port
        EXT_PORT="$ext_port"
        validate_port "$EXT_PORT" || { echo -e "${RED}外网端口无效${PLAIN}"; return 1; }
    else
        EXT_PORT="$LISTEN_PORT"
    fi

    read -rp "请输入密码 [随机生成]: " input_pw
    if [ -z "$input_pw" ]; then
        PASSWORD=$(openssl rand -base64 16 | tr -d '/+=')
    else
        PASSWORD="$input_pw"
        validate_password "$PASSWORD" || { echo -e "${RED}密码无效${PLAIN}"; return 1; }
    fi

    read -rp "请输入 SNI 域名 [默认 microsoft.com]: " input_sni
    SNI="${input_sni:-microsoft.com}"
    validate_domain "$SNI" || { echo -e "${RED}域名无效${PLAIN}"; return 1; }

    # 生成配置
    gen_cert
    gen_config

    # 创建服务文件
    if [ "$INIT_SYS" = "systemd" ]; then
        cat > "$SERVICE_FILE" << EOF
[Unit]
Description=AnyTLS Server
After=network.target

[Service]
Type=simple
ExecStart=$ANYTLS_BIN -c $ANYTLS_CONFIG
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
    elif [ "$INIT_SYS" = "openrc" ]; then
        cat > "$OPENRC_SERVICE" << 'EOF'
#!/sbin/openrc-run

command="/usr/local/bin/anytls-go"
command_args="-c /etc/anytls/config.yaml"
command_background=true
pidfile="/run/anytls.pid"

depend() {
    need net
    after firewall
}
EOF
        chmod +x "$OPENRC_SERVICE"
    fi

    # 放行防火墙
    open_firewall_port "$LISTEN_PORT"

    # 启动服务
    service_start
    sleep 3

    if service_is_active; then
        echo -e "${GREEN}AnyTLS 安装成功${PLAIN}"
        show_config
    else
        echo -e "${RED}服务启动失败${PLAIN}"
        return 1
    fi
}

upgrade_anytls() {
    echo -e "${GREEN}=== AnyTLS 升级 ===${PLAIN}"

    [ ! -f "$ANYTLS_BIN" ] && { echo -e "${RED}未安装 AnyTLS${PLAIN}"; return 1; }

    local current_version
    local latest_version
    current_version=$("$ANYTLS_BIN" version 2>/dev/null | head -n1)
    latest_version=$(get_latest_version)

    echo -e "${CYAN}当前版本: $current_version${PLAIN}"
    echo -e "${CYAN}最新版本: $latest_version${PLAIN}"

    if [ "$current_version" = "$latest_version" ]; then
        echo -e "${GREEN}已是最新版本${PLAIN}"
        return
    fi

    read -rp "是否升级? [y/N]: " confirm
    [ "$confirm" != "y" ] && [ "$confirm" != "Y" ] && return

    # 备份
    backup_binary || { echo -e "${RED}备份失败${PLAIN}"; return 1; }

    # 下载
    download_anytls "$latest_version" || {
        echo -e "${RED}下载失败，回滚${PLAIN}"
        rollback_binary
        return 1
    }

    # 重启服务
    service_restart
    sleep 3

    if service_is_active; then
        echo -e "${GREEN}升级成功${PLAIN}"
        rm -f "${ANYTLS_BIN}.bak"
    else
        echo -e "${RED}服务启动失败，回滚${PLAIN}"
        rollback_binary
        service_restart
    fi
}

uninstall_anytls() {
    echo -e "${YELLOW}=== AnyTLS 卸载 ===${PLAIN}"
    read -rp "确认卸载? [y/N]: " confirm
    [ "$confirm" != "y" ] && [ "$confirm" != "Y" ] && return

    # 停止服务
    service_stop

    # 删除服务文件
    [ -f "$SERVICE_FILE" ] && {
        systemctl disable anytls-server >/dev/null 2>&1
        rm -f "$SERVICE_FILE"
        systemctl daemon-reload
    }
    [ -f "$OPENRC_SERVICE" ] && {
        rc-update del anytls-server default >/dev/null 2>&1
        rm -f "$OPENRC_SERVICE"
    }

    # 删除二进制
    rm -f "$ANYTLS_BIN" "${ANYTLS_BIN}.bak"

    # 删除配置
    rm -rf /etc/anytls

    # 删除自动更新
    rm -f "$AUTO_UPDATE_SCRIPT" "$AUTO_UPDATE_LOG"
    crontab -l 2>/dev/null | grep -v "anytls-autoupdate" | crontab -

    # 删除防火墙规则
    if [ -f "$ANYTLS_META/config" ]; then
        . "$ANYTLS_META/config"
        close_firewall_port "$LISTEN_PORT"
    fi

    # 删除 BBR 配置
    rm -f "$BBR_CONFIG"

    echo -e "${GREEN}卸载完成${PLAIN}"
}

# ============================================================
# 服务器工具
# ============================================================

enable_bbr() {
    local kernel_version
    kernel_version=$(uname -r | cut -d. -f1-2)

    if [ "$(echo "$kernel_version" | cut -d. -f1)" -lt 4 ] || \
       [ "$(echo "$kernel_version" | cut -d. -f1)" -eq 4 ] && [ "$(echo "$kernel_version" | cut -d. -f2)" -lt 9 ]; then
        echo -e "${RED}内核版本过低，不支持 BBR${PLAIN}"
        return 1
    fi

    # 尝试 BBR3
    if [ "$(echo "$kernel_version" | cut -d. -f1)" -ge 5 ] && [ "$(echo "$kernel_version" | cut -d. -f2)" -ge 15 ]; then
        modprobe tcp_bbr 2>/dev/null
        if sysctl net.ipv4.tcp_congestion_control=bbr3 >/dev/null 2>&1; then
            echo "net.core.default_qdisc=fq" > "$BBR_CONFIG"
            echo "net.ipv4.tcp_congestion_control=bbr3" >> "$BBR_CONFIG"
            sysctl -p "$BBR_CONFIG" >/dev/null 2>&1
            echo -e "${GREEN}BBR3 已启用${PLAIN}"
            return 0
        fi
    fi

    # 回退 BBR
    modprobe tcp_bbr 2>/dev/null
    echo "net.core.default_qdisc=fq" > "$BBR_CONFIG"
    echo "net.ipv4.tcp_congestion_control=bbr" >> "$BBR_CONFIG"
    sysctl -p "$BBR_CONFIG" >/dev/null 2>&1
    echo -e "${GREEN}BBR 已启用${PLAIN}"
}

setup_autoupdate() {
    cat > "$AUTO_UPDATE_SCRIPT" <<'AUTOUPDATE_EOF'
#!/bin/bash
set -e

ANYTLS_BIN="/usr/local/bin/anytls-go"
LOG="/var/log/anytls-autoupdate.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG"
}

log "开始检查更新"

latest_version=$(curl -s "https://api.github.com/repos/anytls/anytls-go/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
current_version=$("$ANYTLS_BIN" version 2>/dev/null | head -n1)

if [ "$latest_version" != "$current_version" ]; then
    log "发现新版本: $current_version -> $latest_version"

    arch=$(uname -m)
    case "$arch" in
        x86_64) arch="amd64" ;;
        aarch64) arch="arm64" ;;
        armv7l) arch="arm" ;;
        s390x) arch="s390x" ;;
        loongarch64) arch="loong64" ;;
        *) log "不支持的架构: $arch"; exit 1 ;;
    esac

    url="https://github.com/anytls/anytls-go/releases/download/${latest_version}/anytls-linux-${arch}"
    tmp_bin=$(mktemp /tmp/anytls-autoupdate-XXXXXX)

    if wget -q --timeout=60 -O "$tmp_bin" "$url"; then
        chmod +x "$tmp_bin"
        if od -A d -t x1 -N 4 "$tmp_bin" 2>/dev/null | awk 'NR==1 { print $2, $3, $4, $5 }' | grep -q "7f 45 4c 46"; then
            cp "$ANYTLS_BIN" "${ANYTLS_BIN}.autoupdate.bak"
            mv "$tmp_bin" "$ANYTLS_BIN"
            chmod +x "$ANYTLS_BIN"
            systemctl restart anytls-server >/dev/null 2>&1 || rc-service anytls-server restart >/dev/null 2>&1
            log "更新成功"
            rm -f "${ANYTLS_BIN}.autoupdate.bak"
        else
            log "下载文件无效"
            rm -f "$tmp_bin"
        fi
    else
        log "下载失败"
        rm -f "$tmp_bin"
    fi
else
    log "已是最新版本"
fi
AUTOUPDATE_EOF

    chmod +x "$AUTO_UPDATE_SCRIPT"

    # 添加 cron
    (crontab -l 2>/dev/null | grep -v "anytls-autoupdate"; echo "0 3 * * * $AUTO_UPDATE_SCRIPT") | crontab -

    echo -e "${GREEN}自动更新已启用（每天 03:00）${PLAIN}"
}

remove_autoupdate() {
    rm -f "$AUTO_UPDATE_SCRIPT" "$AUTO_UPDATE_LOG"
    crontab -l 2>/dev/null | grep -v "anytls-autoupdate" | crontab -
    echo -e "${GREEN}自动更新已禁用${PLAIN}"
}

show_sys_info() {
    echo -e "${GREEN}=== 系统信息 ===${PLAIN}"
    local os_name
    os_name=$(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)
    echo -e "${CYAN}操作系统:${PLAIN} $os_name"
    echo -e "${CYAN}内核版本:${PLAIN} $(uname -r)"
    echo -e "${CYAN}CPU:${PLAIN} $(uname -m)"
    echo -e "${CYAN}内存:${PLAIN} $(free -h | grep Mem | awk '{print $2}')"
    echo -e "${CYAN}磁盘:${PLAIN} $(df -h / | tail -n1 | awk '{print $2}')"
    echo -e "${CYAN}负载:${PLAIN} $(uptime | awk -F'load average:' '{print $2}')"

    # BBR 状态
    if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
        echo -e "${CYAN}BBR:${PLAIN} ${GREEN}已启用${PLAIN}"
    else
        echo -e "${CYAN}BBR:${PLAIN} ${RED}未启用${PLAIN}"
    fi

    # 自动更新状态
    if crontab -l 2>/dev/null | grep -q "anytls-autoupdate"; then
        echo -e "${CYAN}自动更新:${PLAIN} ${GREEN}已启用${PLAIN}"
    else
        echo -e "${CYAN}自动更新:${PLAIN} ${RED}未启用${PLAIN}"
    fi
}

server_tools_menu() {
    while true; do
        echo -e "\n${GREEN}=== 服务器工具 ===${PLAIN}"
        echo "1. 开启 BBR 加速"
        echo "2. 开启自动更新"
        echo "3. 关闭自动更新"
        echo "4. 查看系统信息"
        echo "5. 查看运行日志"
        echo "0. 返回主菜单"

        read -rp "请选择 [0-5]: " choice

        case "$choice" in
            1) enable_bbr ;;
            2) setup_autoupdate ;;
            3) remove_autoupdate ;;
            4) show_sys_info ;;
            5)
                if [ "$INIT_SYS" = "systemd" ]; then
                    journalctl -u anytls-server -f
                else
                    echo -e "${YELLOW}OpenRC 不支持日志查看${PLAIN}"
                fi
                ;;
            0) break ;;
            *) echo -e "${RED}无效选择${PLAIN}" ;;
        esac
    done
}

# ============================================================
# 主菜单
# ============================================================

main_menu() {
    check_root
    check_sys
    detect_init
    detect_network

    while true; do
        clear

        local installed=0
        [ -f "$ANYTLS_BIN" ] && installed=1

        echo -e "\n${BOLD}${GREEN}AnyTLS Management Script v1.0.2${PLAIN}"
        echo -e "${CYAN}https://github.com/everett7623/hy2${PLAIN}\n"

        if [ $installed -eq 1 ]; then
            echo -e "${GREEN}状态: ${PLAIN}$(service_is_active && echo "${GREEN}运行中${PLAIN}" || echo "${RED}已停止${PLAIN}")"
        else
            echo -e "${YELLOW}状态: 未安装${PLAIN}"
        fi

        echo -e "\n${BOLD}主菜单${PLAIN}"

        if [ $installed -eq 0 ]; then
            echo "1. 安装 AnyTLS"
        else
            echo "1. 查看 AnyTLS 节点信息"
            echo "2. 修改配置"
            echo "3. 升级 AnyTLS"
            echo "4. 卸载 AnyTLS"
        fi

        echo "5. 服务器工具"
        echo "0. 退出"

        read -rp "请选择 [0-5]: " choice

        case "$choice" in
            1)
                if [ $installed -eq 0 ]; then
                    install_anytls && installed=1
                else
                    show_config
                fi
                ;;
            2)
                if [ $installed -eq 1 ]; then
                    echo -e "\n${BOLD}修改配置${PLAIN}"
                    echo "1. 修改端口"
                    echo "2. 修改密码"
                    echo "3. 修改 SNI"
                    echo "0. 返回"
                    read -rp "请选择 [0-3]: " sub_choice
                    case "$sub_choice" in
                        1) change_port ;;
                        2) change_password ;;
                        3) change_sni ;;
                        0) ;;
                        *) echo -e "${RED}无效选项，请输入 0-3${PLAIN}"; sleep 1 ;;
                    esac
                else
                    echo -e "${YELLOW}AnyTLS 尚未安装，请先选择 1 安装${PLAIN}"
                    sleep 1
                fi
                ;;
            3)
                if [ $installed -eq 1 ]; then
                    upgrade_anytls
                else
                    echo -e "${YELLOW}AnyTLS 尚未安装，请先选择 1 安装${PLAIN}"
                    sleep 1
                fi
                ;;
            4)
                if [ $installed -eq 1 ]; then
                    uninstall_anytls
                else
                    echo -e "${YELLOW}AnyTLS 尚未安装，无需卸载${PLAIN}"
                    sleep 1
                fi
                ;;
            5)
                server_tools_menu
                ;;
            0|q|quit|exit)
                echo -e "${GREEN}再见${PLAIN}"
                exit 0
                ;;
            *)
                echo -e "${RED}无效选项，请输入 0-5${PLAIN}"
                sleep 1
                ;;
        esac
    done
}

# ============================================================
main_menu
