#!/bin/bash
# Hysteria2 + Cloudflare Tunnel 一键安装脚本 (IPv6 Only VPS)
# GitHub: https://github.com/everett7623/hy2ipv6
# 增强版 - 支持完善的卸载和重试机制 + 优化改进

set -e

# ========= 基础配置 =========
PORT=443 # Hysteria2 服务端口
PASSWORD=$(openssl rand -base64 16) # 自动生成 Hysteria2 密码
SNI=www.bing.com   # 可改成任意域名伪装，用于 Hysteria2 TLS SNI 和客户端配置
TUNNEL_NAME=hy2-tunnel # Cloudflare Tunnel 的名称。如果检测到冲突或为首次安装，会生成更独特的名称。

# 全局变量
CF_CONFIG_DIR="/etc/cloudflared"
HYSTERIA_CONFIG_DIR="/etc/hysteria"
SCRIPT_LOG="/var/log/hysteria_install.log"
BACKUP_DIR="/opt/hysteria_backup"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $1"
    echo -e "${GREEN}$msg${NC}" | tee -a "$SCRIPT_LOG"
}

log_warn() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] $1"
    echo -e "${YELLOW}$msg${NC}" | tee -a "$SCRIPT_LOG"
}

log_error() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $1"
    echo -e "${RED}$msg${NC}" | tee -a "$SCRIPT_LOG"
}

log_debug() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [DEBUG] $1"
    echo -e "${CYAN}$msg${NC}" | tee -a "$SCRIPT_LOG"
}

# 显示横幅
show_banner() {
    echo -e "${PURPLE}"
    cat << "EOF"
╔═══════════════════════════════════════════════╗
║         Hysteria2 + Cloudflare Tunnel         ║
║              IPv6 Only VPS 专用               ║
║                增强版本 v2.1                   ║
╚═══════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# 显示帮助信息
show_help() {
    show_banner
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo -e "  ${GREEN}install${NC}         安装 Hysteria2 + Cloudflare Tunnel (默认)"
    echo -e "  ${RED}uninstall${NC}       完全卸载所有组件"
    echo -e "  ${BLUE}reinstall${NC}       卸载后重新安装"
    echo -e "  ${YELLOW}status${NC}          查看服务状态"
    echo -e "  ${CYAN}config${NC}          显示客户端配置"
    echo -e "  ${PURPLE}hysteria-only${NC} 仅安装 Hysteria2（跳过 Cloudflare）"
    echo -e "  ${PURPLE}repair${NC}          尝试修复损坏的安装"
    echo -e "  ${PURPLE}backup${NC}          备份当前配置"
    echo -e "  ${PURPLE}restore${NC}         恢复备份配置"
    echo -e "  ${PURPLE}test${NC}            测试连接 (Hysteria2 & Cloudflare Tunnel)"
    echo -e "  ${NC}-h, --help      显示此帮助信息"
    echo ""
}

# 检测系统类型和版本
check_system() {
    log_info "检测系统信息..."
    
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_NAME=$NAME
        OS_VERSION=$VERSION
        log_info "操作系统: $OS_NAME $OS_VERSION"
    fi
    
    if [ -f /etc/debian_version ]; then
        log_info "检测到 Debian/Ubuntu 系统"
        
        # 检查系统版本兼容性
        if command -v lsb_release &> /dev/null; then
            local version=$(lsb_release -rs | cut -d. -f1)
            if [ "$version" -lt 18 ]; then
                log_warn "系统版本较老，可能存在兼容性问题"
            fi
        fi
        return 0
    elif [ -f /etc/redhat-release ]; then
        log_error "暂不支持 RedHat/CentOS 系统"
        exit 1
    else
        log_warn "无法确定系统类型，假设为 Debian/Ubuntu"
    fi
}

# 检查是否为 root 用户
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "请使用 root 用户运行此脚本"
        echo -e "${RED}提示: 使用 'sudo bash $0' 或切换到 root 用户${NC}"
        exit 1
    fi
}

# 增强的 IPv6 连通性检查
check_ipv6() {
    log_info "检查 IPv6 配置和连通性..."
    
    # 检查 IPv6 是否启用
    if [ ! -f /proc/net/if_inet6 ]; then
        log_error "系统未启用 IPv6。请确保您的VPS支持IPv6并已正确配置。"
        exit 1
    fi
    
    # 获取 IPv6 地址
    local ipv6_addresses=$(ip -6 addr show scope global | grep inet6 | awk '{print $2}' | cut -d/ -f1)
    if [ -z "$ipv6_addresses" ]; then
        log_error "未找到全局 IPv6 地址。请检查网络配置。"
        exit 1
    fi
    
    log_info "找到 IPv6 地址:"
    echo "$ipv6_addresses" | while read addr; do
        log_debug "  - $addr"
    done
    
    # 测试 IPv6 连通性
    log_info "测试 IPv6 连通性..."
    local test_hosts=("google.com" "cloudflare.com" "github.com")
    local success_count=0
    
    for host in "${test_hosts[@]}"; do
        if timeout 10 ping6 -c 1 "$host" &> /dev/null; then
            log_debug "✅ $host IPv6 连通性正常"
            success_count=$((success_count + 1))
        else
            log_warn "❌ $host IPv6 连通性失败"
        fi
    done
    
    if [ $success_count -eq 0 ]; then
        log_error "所有 IPv6 连通性测试失败。请检查网络配置或防火墙。"
        exit 1
    elif [ $success_count -lt ${#test_hosts[@]} ]; then
        log_warn "部分 IPv6 连通性测试失败，但继续安装。这可能表明存在网络问题。"
    else
        log_info "IPv6 连通性测试全部通过"
    fi
}

# 检查端口占用
check_port() {
    log_info "检查端口 $PORT 是否被占用..."
    
    if netstat -tlnp | grep -q ":$PORT "; then
        local process=$(netstat -tlnp | grep ":$PORT " | awk '{print $7}' | cut -d/ -f2)
        log_warn "端口 $PORT 已被进程 '$process' 占用。"
        
        read -p "是否继续安装？这可能会导致服务冲突 (y/N): " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            log_info "安装已取消"
            exit 0
        fi
    else
        log_info "端口 $PORT 可用"
    fi
}

# 服务状态检查函数（增强版）
check_service_status() {
    local service_name="$1"
    local max_attempts=20
    local attempt=1
    
    log_info "检查服务 $service_name 状态..."
    while [ $attempt -le $max_attempts ]; do
        if systemctl is-active --quiet "$service_name"; then
            log_info "✅ $service_name 服务运行正常"
            
            # 额外的健康检查
            case "$service_name" in
                "hysteria-server")
                    if netstat -tlnp | grep -q ":$PORT "; then
                        log_info "✅ Hysteria2 端口监听正常"
                    else
                        log_warn "⚠️  Hysteria2 端口未监听。请检查Hysteria2配置或防火墙。"
                        return 1
                    fi
                    ;;
                "cloudflared")
                    # 检查是否有隧道连接
                    sleep 5 # 给一点时间建立连接
                    if journalctl -u cloudflared --since "1 minute ago" --no-pager | grep -q "Connection.*registered"; then
                        log_info "✅ Cloudflare Tunnel 连接已建立"
                    else
                        log_warn "⚠️  Cloudflare Tunnel 可能未完全建立连接。请检查Cloudflare日志或网络。"
                    fi
                    ;;
            esac
            return 0
        fi
        
        log_info "等待服务启动... ($attempt/$max_attempts)"
        sleep 3
        attempt=$((attempt + 1))
    done
    
    log_error "❌ $service_name 服务启动失败"
    log_error "请检查日志：journalctl -u $service_name --no-pager -n 30"
    return 1
}

# 备份配置文件
backup_configs() {
    log_info "备份现有配置..."
    mkdir -p "$BACKUP_DIR"
    
    local timestamp=$(date +%Y%m%d_%H%M%S)
    
    if [ -d "$HYSTERIA_CONFIG_DIR" ]; then
        cp -r "$HYSTERIA_CONFIG_DIR" "${BACKUP_DIR}/hysteria_config_$timestamp"
        log_info "Hysteria2 配置已备份到 ${BACKUP_DIR}/hysteria_config_$timestamp"
    fi
    
    if [ -d "$CF_CONFIG_DIR" ]; then
        cp -r "$CF_CONFIG_DIR" "${BACKUP_DIR}/cloudflared_config_$timestamp"
        log_info "Cloudflare 配置已备份到 ${BACKUP_DIR}/cloudflared_config_$timestamp"
    fi
    
    if [ -d "/root/.cloudflared" ]; then
        cp -r "/root/.cloudflared" "${BACKUP_DIR}/cloudflared_creds_$timestamp"
        log_info "Cloudflare 凭证已备份到 ${BACKUP_DIR}/cloudflared_creds_$timestamp"
    fi
    
    if [ -n "$(find "$BACKUP_DIR" -maxdepth 1 -type d -name "*_$(date +%Y%m%d)_*" 2>/dev/null)" ]; then
        log_info "✅ 备份完成！"
    else
        log_warn "未能找到任何可备份的配置，可能当前系统没有相关安装。"
    fi
}

# 恢复配置文件
restore_configs() {
    log_info "开始恢复配置..."
    
    if [ ! -d "$BACKUP_DIR" ] || [ -z "$(ls -A "$BACKUP_DIR" 2>/dev/null)" ]; then
        log_warn "未找到备份目录或备份目录为空。"
        return 1
    fi
    
    echo -e "\n${YELLOW}可用的备份目录 (位于 $BACKUP_DIR):${NC}"
    find "$BACKUP_DIR" -maxdepth 1 -type d -name "hysteria_config_*" -o -name "cloudflared_config_*" -printf "%f\n" | sort -r || echo "无可用备份"
    echo ""
    
    read -p "请输入要恢复的备份目录名（如 hysteria_config_YYYYMMDD_HHMMSS，或按回车取消）: " backup_name
    
    if [ -n "$backup_name" ]; then
        local full_backup_path="${BACKUP_DIR}/$backup_name"
        if [ -d "$full_backup_path" ]; then
            log_info "开始恢复 $full_backup_path ..."
            
            # 停止相关服务以避免文件冲突
            systemctl stop hysteria-server 2>/dev/null || true
            systemctl stop cloudflared 2>/dev/null || true
            
            # 删除现有配置
            rm -rf "$HYSTERIA_CONFIG_DIR" "$CF_CONFIG_DIR" "/root/.cloudflared"
            
            # 恢复备份
            if [[ "$backup_name" == hysteria_config_* ]]; then
                cp -r "$full_backup_path" "$HYSTERIA_CONFIG_DIR"
                log_info "Hysteria2 配置已恢复"
            elif [[ "$backup_name" == cloudflared_config_* ]]; then
                cp -r "$full_backup_path" "$CF_CONFIG_DIR"
                log_info "Cloudflare 配置已恢复"
                # 尝试恢复对应的凭证
                local creds_backup=$(find "$BACKUP_DIR" -maxdepth 1 -type d -name "cloudflared_creds_$(echo "$backup_name" | cut -d'_' -f3-)" 2>/dev/null)
                if [ -n "$creds_backup" ]; then
                    cp -r "$creds_backup" "/root/.cloudflared"
                    log_info "Cloudflare 凭证已恢复"
                else
                    log_warn "未找到对应的 Cloudflare 凭证备份，可能需要重新登录授权。"
                fi
            else
                log_warn "未知备份类型，跳过恢复。"
            fi
            
            systemctl daemon-reload
            log_info "配置恢复完成。请手动重启服务以应用更改：systemctl restart hysteria-server cloudflared"
        else
            log_error "指定的备份目录 '$backup_name' 不存在。"
        fi
    else
        log_info "恢复已取消"
    fi
}

# 完全卸载 Hysteria2（增强版）
uninstall_hysteria() {
    log_info "卸载 Hysteria2..."
    
    # 停止并禁用服务
    if systemctl list-units --full -all | grep -Fq "hysteria-server.service"; then
        systemctl stop hysteria-server 2>/dev/null || true
        systemctl disable hysteria-server 2>/dev/null || true
        log_info "Hysteria2 服务已停止并禁用"
    fi
    
    # 删除服务文件
    for service_file in /etc/systemd/system/hysteria*.service /lib/systemd/system/hysteria*.service; do
        if [ -f "$service_file" ]; then
            rm -f "$service_file"
            log_info "删除服务文件: $service_file"
        fi
    done
    
    # 删除二进制文件
    for binary in /usr/local/bin/hysteria* /usr/bin/hysteria* /opt/hysteria*/hysteria*; do
        if [ -f "$binary" ]; then
            rm -f "$binary"
            log_info "删除二进制文件: $binary"
        fi
    done
    
    # 删除配置目录
    if [ -d "$HYSTERIA_CONFIG_DIR" ]; then
        rm -rf "$HYSTERIA_CONFIG_DIR"
        log_info "删除 Hysteria2 配置目录"
    fi
    
    # 清理可能的残留进程
    pkill -f hysteria 2>/dev/null || true
    
    systemctl daemon-reload
    systemctl reset-failed 2>/dev/null || true
    log_info "Hysteria2 卸载完成"
}

# 完全卸载 Cloudflare Tunnel（增强版）
uninstall_cloudflared() {
    log_info "卸载 Cloudflare Tunnel..."
    
    # 停止并禁用所有可能的 cloudflared 服务
    for service in cloudflared cloudflared-tunnel@${TUNNEL_NAME} cloudflared@${TUNNEL_NAME}; do
        if systemctl list-units --full -all | grep -Fq "${service}.service"; then
            systemctl stop "$service" 2>/dev/null || true
            systemctl disable "$service" 2>/dev/null || true
            log_info "停止并禁用服务: $service"
        fi
    done
    
    # 删除所有可能的服务文件
    for service_file in /etc/systemd/system/cloudflared*.service /lib/systemd/system/cloudflared*.service; do
        if [ -f "$service_file" ]; then
            rm -f "$service_file"
            log_info "删除服务文件: $service_file"
        fi
    done
    
    # 使用 cloudflared service uninstall (如果可用)
    if command -v cloudflared &> /dev/null; then
        cloudflared service uninstall 2>/dev/null || true
        log_info "执行 cloudflared service uninstall"
        
        # 删除现有隧道（更安全的方式）
        local tunnel_list=$(cloudflared tunnel list --json 2>/dev/null)
        if [ -n "$tunnel_list" ]; then
            # 尝试删除所有在Cloudflare上注册的隧道
            echo "$tunnel_list" | jq -r '.[].id' 2>/dev/null | while read -r tunnel_id; do
                local tunnel_name_from_list=$(echo "$tunnel_list" | jq -r ".[] | select(.id==\"$tunnel_id\") | .name" 2>/dev/null)
                log_info "尝试删除隧道: $tunnel_name_from_list ($tunnel_id)"
                cloudflared tunnel delete "$tunnel_id" 2>/dev/null || true
            done
        fi
    fi
    
    # 删除 cloudflared 二进制文件和包
    if command -v cloudflared &> /dev/null; then
        if dpkg -l 2>/dev/null | grep -q cloudflared; then
            apt remove -y cloudflared 2>/dev/null || true
            apt autoremove -y 2>/dev/null || true
            log_info "卸载 cloudflared 软件包"
        fi
        
        # 删除可能残留的二进制文件
        for bin_path in /usr/local/bin/cloudflared /usr/bin/cloudflared /opt/cloudflared/cloudflared; do
            if [ -f "$bin_path" ]; then
                rm -f "$bin_path"
                log_info "删除二进制文件: $bin_path"
            fi
        done
    fi
    
    # 删除配置目录
    for config_dir in "$CF_CONFIG_DIR" "/root/.cloudflared"; do
        if [ -d "$config_dir" ]; then
            rm -rf "$config_dir"
            log_info "删除配置目录: $config_dir"
        fi
    done
    
    # 清理可能的残留进程
    pkill -f cloudflared 2>/dev/null || true
    
    systemctl daemon-reload
    systemctl reset-failed 2>/dev/null || true
    log_info "Cloudflare Tunnel 卸载完成"
}

# 完全卸载所有组件
uninstall_all() {
    log_info "开始完全卸载..."
    
    # 显示当前状态
    show_status_brief
    
    read -p "确认要完全卸载所有组件吗？此操作不可逆 (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        log_info "卸载已取消"
        return 0
    fi
    
    uninstall_hysteria
    uninstall_cloudflared
    
    # 清理备份目录（可选）
    if [ -d "$BACKUP_DIR" ]; then
        read -p "是否删除备份文件？(y/N): " del_backup
        if [[ "$del_backup" =~ ^[Yy]$ ]]; then
            rm -rf "$BACKUP_DIR"
            log_info "备份文件已删除"
        fi
    fi
    
    # 清理日志文件
    if [ -f "$SCRIPT_LOG" ]; then
        rm -f "$SCRIPT_LOG"
        log_info "安装日志文件已删除"
    fi
    
    log_info "✅ 完全卸载成功！"
}

# 检查组件安装状态（增强版）
check_installation_status() {
    local hysteria_status=0 # 0=未安装, 1=已安装并运行, 2=残留或停止
    local cloudflared_status=0
    
    # 检查 Hysteria2
    if systemctl is-active --quiet hysteria-server 2>/dev/null && systemctl is-enabled --quiet hysteria-server 2>/dev/null; then
        hysteria_status=1
        log_debug "✅ Hysteria2 完整安装并运行"
    elif [ -f "/usr/local/bin/hysteria2" ] || [ -d "$HYSTERIA_CONFIG_DIR" ] || systemctl list-unit-files | grep -q hysteria; then
        hysteria_status=2
        log_debug "⚠️  检测到 Hysteria2 残留文件或服务停止"
    else
        log_debug "ℹ️  Hysteria2 未安装"
    fi
    
    # 检查 Cloudflared
    if systemctl is-active --quiet cloudflared 2>/dev/null && systemctl is-enabled --quiet cloudflared 2>/dev/null; then
        cloudflared_status=1
        log_debug "✅ Cloudflared 完整安装并运行"
    elif command -v cloudflared &> /dev/null || [ -d "$CF_CONFIG_DIR" ] || systemctl list-unit-files | grep -q cloudflared; then
        cloudflared_status=2
        log_debug "⚠️  检测到 Cloudflared 残留文件或服务停止"
    else
        log_debug "ℹ️  Cloudflared 未安装"
    fi
    
    # 返回状态码
    if [ $hysteria_status -eq 1 ] && [ $cloudflared_status -eq 1 ]; then
        return 0 # 完整安装并运行
    elif [ $hysteria_status -gt 0 ] || [ $cloudflared_status -gt 0 ]; then
        return 1 # 部分安装、残留或停止
    else
        return 2 # 未安装
    fi
}

# 安全的 UUID 获取函数（增强版）
get_tunnel_uuid() {
    local uuid=""
    
    # 方法1: 从本地凭证文件获取 (最新的)
    if [ -d "/root/.cloudflared" ]; then
        local json_file=$(find /root/.cloudflared -name "*.json" -type f -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2-)
        
        if [ -n "$json_file" ] && [ -f "$json_file" ]; then
            uuid=$(basename "$json_file" .json)
            if [[ "$uuid" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
                log_debug "从本地文件获取 UUID: $uuid"
                echo "$uuid"
                return 0
            fi
        fi
    fi
    
    # 方法2: 从隧道列表获取 (通过 TUNNEL_NAME)
    if command -v cloudflared &> /dev/null; then
        local tunnel_list=$(cloudflared tunnel list --json 2>/dev/null)
        if [ -n "$tunnel_list" ]; then
            uuid=$(echo "$tunnel_list" | jq -r ".[] | select(.name==\"$TUNNEL_NAME\") | .id" 2>/dev/null | head -1)
            if [[ "$uuid" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
                log_debug "从隧道列表获取 UUID: $uuid"
                echo "$uuid"
                return 0
            fi
        fi
    fi
    
    # 方法3: 从配置目录的保存文件获取
    if [ -f "$CF_CONFIG_DIR/uuid.txt" ]; then
        uuid=$(cat "$CF_CONFIG_DIR/uuid.txt" | tr -d '\n\r')
        if [[ "$uuid" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
            log_debug "从保存文件获取 UUID: $uuid"
            echo "$uuid"
            return 0
        fi
    fi
    
    log_warn "无法获取有效的隧道 UUID"
    return 1
}

# 原子化安装 Hysteria2（增强版）
install_hysteria_atomic() {
    local temp_dir=$(mktemp -d)
    
    log_info "原子化安装 Hysteria2..."
    
    # 检查依赖
    if ! command -v openssl &> /dev/null; then
        log_error "openssl 未安装，请先安装"
        rm -rf "$temp_dir"
        return 1
    fi
    
    # 下载并安装 Hysteria2 - 支持网络协议回退
    log_info "下载 Hysteria2..."
    local hysteria_install_success=false
    
    # 尝试不同的网络协议下载 Hysteria2 安装脚本
    local install_methods=(
        "curl -6 -fsSL https://get.hy2.sh"  # IPv6
        "curl -4 -fsSL https://get.hy2.sh"  # IPv4
        "curl -fsSL https://get.hy2.sh"     # 默认协议
    )
    
    for method in "${install_methods[@]}"; do
        log_info "尝试使用: $method"
        if retry_with_backoff 3 5 "下载并执行 Hysteria2 安装脚本" bash <($method); then
            hysteria_install_success=true
            log_info "✅ Hysteria2 安装脚本执行成功"
            break
        else
            log_warn "使用 $method 失败，尝试下一种方法..."
        fi
    done
    
    if ! $hysteria_install_success; then
        log_error "所有下载方法都失败了，无法安装 Hysteria2"
        rm -rf "$temp_dir"
        return 1
    fi
    
    # 验证二进制文件
    if [ ! -f "/usr/local/bin/hysteria2" ]; then
        log_error "Hysteria2 二进制文件未找到，安装可能失败"
        rm -rf "$temp_dir"
        return 1
    fi
    
    # 测试二进制文件
    if ! /usr/local/bin/hysteria2 version &> /dev/null; then
        log_error "Hysteria2 二进制文件损坏或无法执行"
        rm -rf "$temp_dir"
        return 1
    fi
    
    # 创建配置目录
    mkdir -p "$HYSTERIA_CONFIG_DIR"
    
    # 生成增强的 Hysteria2 配置文件
    cat > "$HYSTERIA_CONFIG_DIR/config.yaml" <<EOF
# Hysteria2 服务器配置
listen: :$PORT

tls:
  insecure: true
  sni: $SNI

auth:
  type: password
  password: $PASSWORD

masq:
  type: wireguard

# 性能优化配置
obfs:
  type: salamander
  salamander:
    password: $PASSWORD

quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 20971520
  maxConnReceiveWindow: 20971520
  maxIdleTimeout: 30s
  maxIncomingStreams: 1024

# 带宽限制（可选，根据VPS配置调整）
bandwidth:
  up: 1 gbps
  down: 1 gbps
EOF
    
    chmod 600 "$HYSTERIA_CONFIG_DIR/config.yaml"
    
    # 创建增强的 Systemd 服务文件
    cat > /etc/systemd/system/hysteria-server.service <<EOF
[Unit]
Description=Hysteria2 Server
After=network.target nss-lookup.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria2 server -c $HYSTERIA_CONFIG_DIR/config.yaml
Restart=always
RestartSec=5
LimitNOFILE=1048576
User=nobody
Group=nogroup

# 安全设置
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$HYSTERIA_CONFIG_DIR
NoNewPrivileges=true

# 网络设置 (仅允许IPv6，如果需要IPv4，请删除或修改)
IPAddressAllow=::/0
# IPAddressDeny=any # 注释掉此行以允许 IPv4 出站，如果仅限 IPv6 则保留

[Install]
WantedBy=multi-user.target
EOF
    
    # 重载并启动服务
    systemctl daemon-reload
    systemctl enable hysteria-server
    
    if ! systemctl start hysteria-server; then
        log_error "Hysteria2 服务启动失败，查看错误信息："
        journalctl -u hysteria-server --no-pager -n 10
        uninstall_hysteria
        rm -rf "$temp_dir"
        return 1
    fi
    
    # 验证服务状态
    if ! check_service_status "hysteria-server"; then
        log_error "Hysteria2 服务验证失败，开始回滚"
        uninstall_hysteria
        rm -rf "$temp_dir"
        return 1
    fi
    
    rm -rf "$temp_dir"
    log_info "✅ Hysteria2 原子化安装成功"
    return 0
}

# Cloudflare 连接测试
test_cloudflare_connectivity() {
    log_info "测试 Cloudflare 服务连通性..."
    
    local cf_endpoints=("1.1.1.1" "cloudflare.com" "api.cloudflare.com")
    local success_count=0
    
    for endpoint in "${cf_endpoints[@]}"; do
        if timeout 10 ping6 -c 2 "$endpoint" &> /dev/null; then
            log_debug "✅ $endpoint 连通正常"
            success_count=$((success_count + 1))
        else
            log_warn "❌ $endpoint 连通失败"
        fi
    done
    
    if [ $success_count -eq 0 ]; then
        log_error "无法连接到 Cloudflare 服务，请检查网络或防火墙设置。"
        return 1
    elif [ $success_count -lt ${#cf_endpoints[@]} ]; then
        log_warn "部分 Cloudflare 服务连通失败，但这不一定会阻止安装。可能需要后续手动检查。"
    fi
    
    return 0
}

# 智能重试机制
retry_with_backoff() {
    local max_attempts="$1"
    local delay="$2"
    local description="$3"
    shift 3
    local command=("$@")
    
    local attempt=1
    while [ $attempt -le $max_attempts ]; do
        log_info "尝试 $description ($attempt/$max_attempts)..."
        
        if "${command[@]}"; then
            log_info "✅ $description 成功"
            return 0
        fi
        
        if [ $attempt -lt $max_attempts ]; then
            local wait_time=$((delay * attempt))
            log_warn "⚠️  $description 失败，${wait_time}秒后重试..."
            sleep $wait_time
        fi
        
        attempt=$((attempt + 1))
    done
    
    log_error "❌ $description 在 $max_attempts 次尝试后仍然失败"
    return 1
}

# 检查并修复 Cloudflare 环境
prepare_cloudflare_environment() {
    log_info "准备 Cloudflare 环境..."
    
    # 检查并清理可能的冲突
    if command -v cloudflared &> /dev/null; then
        local cf_version=$(cloudflared version 2>/dev/null | head -1)
        log_info "检测到现有 cloudflared: $cf_version"
        
        # 检查是否有运行中的隧道进程
        if pgrep -f cloudflared > /dev/null; then
            log_warn "检测到运行中的 cloudflared 进程。"
            read -p "是否终止现有进程以避免冲突？(Y/n): " confirm
            if [[ ! "$confirm" =~ ^[Nn]$ ]]; then
                pkill -f cloudflared || true
                sleep 2
            fi
        fi
    fi
    
    # 检查网络环境
    test_cloudflare_connectivity || return 1
    
    # 确保必要的目录存在
    mkdir -p /root/.cloudflared "$CF_CONFIG_DIR"
    
    return 0
}

# 安全的 Cloudflare 登录流程
cloudflare_login_safe() {
    local max_login_attempts=3
    local attempt=1
    
    while [ $attempt -le $max_login_attempts ]; do
        log_info "Cloudflare 登录尝试 $attempt/$max_login_attempts"
        
        echo -e "\n${YELLOW}=======================================================${NC}"
        echo -e "${YELLOW}🔐 Cloudflare 授权登录 (第 $attempt 次尝试)${NC}"
        echo -e "${YELLOW}请在浏览器中完成以下步骤：${NC}"
        echo -e "${CYAN}1. 复制即将显示的授权链接${NC}"
        echo -e "${CYAN}2. 在浏览器中打开链接${NC}"
        echo -e "${CYAN}3. 登录您的 Cloudflare 账户${NC}"
        echo -e "${CYAN}4. 选择要使用的域名（或使用默认域名）${NC}"
        echo -e "${CYAN}5. 点击 'Authorize' 完成授权${NC}"
        echo -e "${YELLOW}⏰ 超时时间: 10分钟${NC}"
        echo -e "${YELLOW}=======================================================${NC}\n"
        
        read -p "按回车键开始授权..." dummy
        
        # 使用超时机制
        if timeout 600 cloudflared tunnel login; then
            # 验证授权是否成功
            if [ -d "/root/.cloudflared" ] && [ -n "$(ls -A /root/.cloudflared 2>/dev/null)" ]; then
                log_info "✅ Cloudflare 授权成功"
                return 0
            else
                log_warn "授权过程完成但验证失败，/root/.cloudflared 目录为空。"
            fi
        else
            log_warn "❌ Cloudflare 授权失败或超时"
        fi
        
        if [ $attempt -lt $max_login_attempts ]; then
            echo -e "${YELLOW}是否重试授权？${NC}"
            read -p "继续尝试 (Y/n): " retry_confirm
            if [[ "$retry_confirm" =~ ^[Nn]$ ]]; then
                break
            fi
            
            # 清理可能的部分授权文件
            rm -rf /root/.cloudflared/* 2>/dev/null || true
        fi
        
        attempt=$((attempt + 1))
    done
    
    log_error "Cloudflare 授权在 $max_login_attempts 次尝试后失败"
    return 1
}

# 原子化安装 Cloudflare Tunnel（超级增强版）
install_cloudflared_atomic() {
    local temp_dir=$(mktemp -d)
    local rollback_needed=false
    local install_checkpoint="" # 用于记录安装进度，方便修复
    
    log_info "开始安装 Cloudflare Tunnel（增强容错版）..."
    
    # 准备环境
    if ! prepare_cloudflare_environment; then
        log_error "Cloudflare 环境准备失败"
        rm -rf "$temp_dir"
        return 1
    fi
    
    # 检测系统架构
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) CLOUDFLARED_ARCH="amd64" ;;
        aarch64|arm64) CLOUDFLARED_ARCH="arm64" ;;
        armv7l|armv6l) CLOUDFLARED_ARCH="arm" ;;
        i386|i686) CLOUDFLARED_ARCH="386" ;;
        *)
            log_error "不支持的系统架构: $ARCH"
            rm -rf "$temp_dir"
            return 1
            ;;
    esac
    
    log_info "检测到系统架构: $ARCH -> $CLOUDFLARED_ARCH"
    
    # 检查点1: 下载 cloudflared
    install_checkpoint="download"
    echo "$install_checkpoint" > "$CF_CONFIG_DIR/install_checkpoint.txt"
    log_info "📥 检查点1: 下载 cloudflared..."
    
    # 多源下载策略
    local download_urls=(
        "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${CLOUDFLARED_ARCH}.deb"
        "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${CLOUDFLARED_ARCH}"
    )
    
    local download_success=false
    for url in "${download_urls[@]}"; do
        local filename=$(basename "$url")
        log_info "尝试从源下载: $filename"
        # 尝试下载，优先使用 IPv6，失败则回退到 IPv4
        local download_cmd_success=false
        
        # 首先尝试 IPv6
        if timeout 300 wget -6 -q --show-progress "$url" -O "${temp_dir}/${filename}" 2>/dev/null; then
            download_cmd_success=true
            log_debug "使用 IPv6 下载成功: $filename"
        else
            log_warn "IPv6 下载失败，尝试 IPv4: $filename"
            # 回退到 IPv4
            if timeout 300 wget -4 -q --show-progress "$url" -O "${temp_dir}/${filename}" 2>/dev/null; then
                download_cmd_success=true
                log_debug "使用 IPv4 下载成功: $filename"
            else
                log_warn "IPv4 下载也失败，尝试不指定协议版本: $filename"
                # 最后尝试不指定协议版本
                if timeout 300 wget -q --show-progress "$url" -O "${temp_dir}/${filename}" 2>/dev/null; then
                    download_cmd_success=true
                    log_debug "使用默认协议下载成功: $filename"
                fi
            fi
        fi
        
        if $download_cmd_success; then
            if [ -s "${temp_dir}/${filename}" ]; then
                log_info "✅ 文件下载成功: ${temp_dir}/${filename}"
                
                if [[ "$filename" == *.deb ]]; then
                    # .deb 包安装
                    if retry_with_backoff 3 2 "安装 cloudflared deb 包" apt install -y "${temp_dir}/${filename}"; then
                        download_success=true
                        break
                    fi
                else
                    # 二进制文件安装
                    cp "${temp_dir}/${filename}" /usr/local/bin/cloudflared
                    chmod +x /usr/local/bin/cloudflared
                    download_success=true
                    break
                fi
            fi
        fi
        log_warn "从 $filename 下载或安装失败，尝试下一个源..."
    done
    
    if ! $download_success; then
        log_error "所有下载源都失败了，无法安装 cloudflared。"
        rm -rf "$temp_dir"
        return 1
    fi
    
    rollback_needed=true
    
    # 验证安装
    if ! command -v cloudflared &> /dev/null; then
        log_error "cloudflared 安装验证失败，未找到可执行文件。"
        if $rollback_needed; then uninstall_cloudflared; fi
        rm -rf "$temp_dir"
        return 1
    fi
    
    # 显示版本信息
    local cf_version=$(cloudflared version 2>/dev/null | head -1)
    log_info "✅ Cloudflared 安装成功，版本: $cf_version"
    
    # 检查点2: Cloudflare 授权
    install_checkpoint="login"
    echo "$install_checkpoint" > "$CF_CONFIG_DIR/install_checkpoint.txt"
    log_info "📝 检查点2: Cloudflare 授权..."
    
    # 使用安全的登录流程
    if ! cloudflare_login_safe; then
        log_error "Cloudflare 授权失败。"
        echo -e "\n${RED}🚨 授权失败处理选项：${NC}"
        echo -e "${CYAN}1. 稍后手动运行: cloudflared tunnel login${NC}"
        echo -e "${CYAN}2. 检查网络连接和防火墙设置${NC}"
        echo -e "${CYAN}3. 确保 Cloudflare 账户正常${NC}"
        echo -e "${CYAN}4. 可以保留当前安装，稍后手动配置${NC}"
        
        read -p "是否保留已安装的 cloudflared？(Y/n): " keep_install
        if [[ "$keep_install" =~ ^[Nn]$ ]]; then
            if $rollback_needed; then uninstall_cloudflared; fi
            rm -rf "$temp_dir"
            return 1
        else
            log_info "保留 cloudflared 安装，您可以稍后手动配置。"
            rm -rf "$temp_dir"
            echo "incomplete" > "$CF_CONFIG_DIR/install_status.txt"
            return 2  # 特殊返回码：部分成功
        fi
    fi
    
    # 检查点3: 创建隧道
    install_checkpoint="tunnel_create"
    echo "$install_checkpoint" > "$CF_CONFIG_DIR/install_checkpoint.txt"
    log_info "🚇 检查点3: 创建隧道..."
    
    # 确保 jq 已安装
    if ! command -v jq &> /dev/null; then
        log_info "安装 jq 工具..."
        retry_with_backoff 3 2 "安装 jq" apt install -y jq || {
            log_warn "jq 安装失败，部分功能可能受限，但尝试继续。"
        }
    fi
    
    local UUID=""
    local current_tunnel_name="$TUNNEL_NAME" # 使用全局变量作为默认目标名称
    
    # 检查是否存在同名隧道
    if command -v jq &> /dev/null; then
        local existing_tunnel_id=$(cloudflared tunnel list --json 2>/dev/null | jq -r ".[] | select(.name==\"$current_tunnel_name\") | .id" 2>/dev/null | head -1)
    fi
    
    if [ -n "$existing_tunnel_id" ] && [ "$existing_tunnel_id" != "null" ]; then
        log_warn "发现同名隧道: $current_tunnel_name ($existing_tunnel_id)"
        echo -e "${YELLOW}处理选项：${NC}"
        echo -e "${CYAN}1. 删除现有隧道并创建新的${NC}"
        echo -e "${CYAN}2. 使用现有隧道${NC}"
        read -p "请选择 (1/2): " tunnel_option
        
        case $tunnel_option in
            "1")
                log_info "删除现有隧道: $current_tunnel_name ($existing_tunnel_id)..."
                if ! retry_with_backoff 3 5 "删除现有隧道" cloudflared tunnel delete "$existing_tunnel_id"; then
                    log_error "删除现有隧道失败。请检查Cloudflare账户权限或手动删除。"
                    if $rollback_needed; then uninstall_cloudflared; fi
                    rm -rf "$temp_dir"
                    return 1
                fi
                UUID=""
                ;;
            "2")
                UUID="$existing_tunnel_id"
                log_info "使用现有隧道: $UUID"
                ;;
            *)
                log_error "无效选择，终止安装。"
                if $rollback_needed; then uninstall_cloudflared; fi
                rm -rf "$temp_dir"
                return 1
                ;;
        esac
    fi
    
    # 创建新隧道（如果需要）
    if [ -z "$UUID" ] || [ "$UUID" == "null" ]; then
        # 生成更安全的隧道名称
        local hostname_short=$(hostname 2>/dev/null | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]//g' | cut -c1-10)
        local timestamp=$(date +%m%d%H%M)
        local random_suffix=$(openssl rand -hex 2)
        local new_tunnel_name="hy2-${hostname_short:-vps}-${timestamp}-${random_suffix}"
        
        log_info "创建新隧道: $new_tunnel_name"
        if ! retry_with_backoff 3 5 "创建隧道" cloudflared tunnel create "$new_tunnel_name"; then
            log_error "创建隧道失败。"
            echo -e "\n${RED}🚨 隧道创建失败可能的原因：${NC}"
            echo -e "${CYAN}1. 网络连接问题${NC}"
            echo -e "${CYAN}2. Cloudflare API 限制${NC}"
            echo -e "${CYAN}3. 账户权限不足${NC}"
            echo -e "${CYAN}4. 隧道名称冲突（虽然已尝试动态生成）${NC}"
            if $rollback_needed; then uninstall_cloudflared; fi
            rm -rf "$temp_dir"
            return 1
        fi
        
        # 更新 TUNNEL_NAME 为新创建的名称
        TUNNEL_NAME="$new_tunnel_name"
        
        # 获取新创建的隧道 UUID
        sleep 3  # 等待隧道创建完成
        UUID=$(get_tunnel_uuid) # 再次尝试获取，这次应该能获取到新创建的
        if [ -z "$UUID" ]; then
            log_error "无法获取新创建的隧道 UUID，即使隧道创建成功。这可能是一个Cloudflare API的延迟问题。"
            # 尝试手动查找
            log_info "尝试手动查找隧道 ID..."
            local manual_uuid=$(cloudflared tunnel list 2>/dev/null | grep "$TUNNEL_NAME" | awk '{print $1}' | head -1)
            if [[ "$manual_uuid" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
                UUID="$manual_uuid"
                log_info "✅ 手动找到隧道 UUID: $UUID"
            else
                log_error "手动查找也失败。"
                if $rollback_needed; then uninstall_cloudflared; fi
                rm -rf "$temp_dir"
                return 1
            fi
        fi
    fi
    
    log_info "✅ 使用隧道 UUID: $UUID"
    
    # 检查点4: 配置文件处理
    install_checkpoint="config"
    echo "$install_checkpoint" > "$CF_CONFIG_DIR/install_checkpoint.txt"
    log_info "📄 检查点4: 处理配置文件..."
    
    # 复制凭证文件（带重试）
    CREDENTIALS_FILE="/root/.cloudflared/$UUID.json"
    if ! retry_with_backoff 5 2 "等待并复制凭证文件" test -f "$CREDENTIALS_FILE"; then
        log_error "隧道凭证文件不存在: $CREDENTIALS_FILE。请确认Cloudflare授权和隧道创建过程是否完全成功。"
        if $rollback_needed; then uninstall_cloudflared; fi
        rm -rf "$temp_dir"
        return 1
    fi
    
    # 安全复制凭证文件
    if ! cp "$CREDENTIALS_FILE" "$CF_CONFIG_DIR/"; then
        log_error "复制凭证文件失败。检查目录权限。"
        if $rollback_needed; then uninstall_cloudflared; fi
        rm -rf "$temp_dir"
        return 1
    fi
    chmod 600 "$CF_CONFIG_DIR/$UUID.json"
    log_info "✅ 隧道凭证文件处理成功"
    
    # 生成 Cloudflare Tunnel 域名
    CF_TUNNEL_DOMAIN="${TUNNEL_NAME}.cfargotunnel.com"
    
    # 生成配置文件（带验证）
    cat > "$CF_CONFIG_DIR/config.yml" <<EOF
# Cloudflare Tunnel 配置 - 生成时间: $(date)
tunnel: $UUID
credentials-file: $CF_CONFIG_DIR/$UUID.json

# 日志配置
loglevel: info # 可以设置为 debug, info, warn, error

# 协议配置
protocol: quic

# 重连配置
retries: 5
grace-period: 30s

# 入口规则
ingress:
  - hostname: $CF_TUNNEL_DOMAIN
    service: https://localhost:$PORT
    originRequest:
      noTLSVerify: true
      connectTimeout: 30s
      tlsTimeout: 30s
      keepAliveConnections: 10
      keepAliveTimeout: 30s
      httpHostHeader: $SNI
      # 添加重试配置
      disableChunkedEncoding: true
  - service: http_status:404 # 默认处理未匹配的请求
EOF
    
    chmod 600 "$CF_CONFIG_DIR/config.yml"
    
    # 验证配置文件语法
    if ! cloudflared tunnel --config "$CF_CONFIG_DIR/config.yml" validate 2>/dev/null; then
        log_warn "配置文件语法验证失败，但这不一定会阻止服务启动。请检查 $CF_CONFIG_DIR/config.yml 内容。"
    else
        log_info "✅ 配置文件语法验证通过"
    fi
    
    # 检查点5: DNS 配置
    install_checkpoint="dns"
    echo "$install_checkpoint" > "$CF_CONFIG_DIR/install_checkpoint.txt"
    log_info "🌐 检查点5: 配置 DNS 记录..."
    
    if ! retry_with_backoff 3 5 "配置 DNS 记录" cloudflared tunnel route dns "$TUNNEL_NAME" "$CF_TUNNEL_DOMAIN"; then
        log_warn "DNS 记录配置失败。您可能需要手动在Cloudflare面板中为 $CF_TUNNEL_DOMAIN 添加CNAME记录指向 $TUNNEL_NAME.cfargotunnel.com"
    else
        log_info "✅ DNS 记录配置成功"
    fi
    
    # 检查点6: 服务安装
    install_checkpoint="service"
    echo "$install_checkpoint" > "$CF_CONFIG_DIR/install_checkpoint.txt"
    log_info "⚙️  检查点6: 安装系统服务..."
    
    # 测试配置文件是否能正常启动（干运行）
    log_info "测试配置文件能否正常启动 (干运行)..."
    timeout 10 cloudflared tunnel --config "$CF_CONFIG_DIR/config.yml" run &
    local test_pid=$!
    sleep 5
    kill $test_pid 2>/dev/null || true
    wait $test_pid 2>/dev/null || true
    
    if ! retry_with_backoff 3 3 "安装 Cloudflare Tunnel 服务" cloudflared service install --config "$CF_CONFIG_DIR/config.yml"; then
        log_error "Cloudflare Tunnel 服务安装失败。"
        
        # 提供手动安装选项
        echo -e "\n${YELLOW}🔧 提供手动服务创建选项...${NC}"
        read -p "是否尝试创建自定义服务文件？(Y/n): " create_custom
        if [[ ! "$create_custom" =~ ^[Nn]$ ]]; then
            # 创建自定义服务文件
            cat > /etc/systemd/system/cloudflared.service <<EOF
[Unit]
Description=Cloudflare Tunnel
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/cloudflared tunnel --config $CF_CONFIG_DIR/config.yml run
Restart=always
RestartSec=10
User=root # 默认使用root运行，可以改为nobody

[Install]
WantedBy=multi-user.target
EOF
            systemctl daemon-reload
            log_info "✅ 自定义服务文件创建成功"
        else
            if $rollback_needed; then uninstall_cloudflared; fi
            rm -rf "$temp_dir"
            return 1
        fi
    fi
    
    # 检查点7: 服务启动
    install_checkpoint="start"
    echo "$install_checkpoint" > "$CF_CONFIG_DIR/install_checkpoint.txt"
    log_info "🚀 检查点7: 启动服务..."
    
    if ! retry_with_backoff 3 5 "启用 Cloudflare Tunnel 服务" systemctl enable cloudflared; then
        log_error "Cloudflare Tunnel 服务启用失败。"
        if $rollback_needed; then uninstall_cloudflared; fi
        rm -rf "$temp_dir"
        return 1
    fi
    
    if ! retry_with_backoff 3 10 "启动 Cloudflare Tunnel 服务" systemctl start cloudflared; then
        log_error "Cloudflare Tunnel 服务启动失败。"
        echo -e "\n${RED}🔍 服务启动失败，显示错误信息：${NC}"
        journalctl -u cloudflared --no-pager -n 20
        
        # 提供诊断信息
        echo -e "\n${YELLOW}🩺 诊断信息：${NC}"
        echo "配置文件路径: $CF_CONFIG_DIR/config.yml"
        echo "凭证文件路径: $CF_CONFIG_DIR/$UUID.json"
        echo "隧道名称: $TUNNEL_NAME"
        echo "隧道UUID: $UUID"
        
        # 提供修复选项
        read -p "是否尝试手动启动测试？(y/N): " manual_test
        if [[ "$manual_test" =~ ^[Yy]$ ]]; then
            log_info "手动测试启动..."
            timeout 30 cloudflared tunnel --config "$CF_CONFIG_DIR/config.yml" run &
            local manual_pid=$!
            sleep 10
            if kill -0 $manual_pid 2>/dev/null; then
                log_info "✅ 手动启动测试成功。请杀死此进程并手动尝试 'systemctl start cloudflared'"
                kill $manual_pid 2>/dev/null || true
            else
                log_error "❌ 手动启动测试也失败。问题可能更深层次。"
            fi
        fi
        
        if $rollback_needed; then uninstall_cloudflared; fi
        rm -rf "$temp_dir"
        return 1
    fi
    
    # 检查点8: 服务验证
    install_checkpoint="verify"
    echo "$install_checkpoint" > "$CF_CONFIG_DIR/install_checkpoint.txt"
    log_info "✅ 检查点8: 验证服务..."
    
    # 等待服务稳定
    sleep 15
    
    if ! check_service_status "cloudflared"; then
        log_error "Cloudflare Tunnel 服务验证失败。隧道可能未完全连接到Cloudflare网络。"
        
        # 详细诊断
        echo -e "\n${YELLOW}🔍 详细诊断信息：${NC}"
        echo "最近的服务日志："
        journalctl -u cloudflared --no-pager -n 30
        
        echo -e "\n当前隧道列表："
        cloudflared tunnel list 2>/dev/null || echo "获取隧道列表失败"
        
        echo -e "\n网络连接测试："
        netstat -tlnp | grep cloudflared || echo "未发现 cloudflared 监听端口"
        
        # 提供修复建议
        echo -e "\n${CYAN}💡 可能的解决方案：${NC}"
        echo -e "${CYAN}1. 检查防火墙设置，确保出站连接没有被阻止${NC}"
        echo -e "${CYAN}2. 验证 IPv6 网络配置是否稳定${NC}"
        echo -e "${CYAN}3. 检查 Cloudflare 账户权限或限制${NC}"
        echo -e "${CYAN}4. 稍后手动重启服务: systemctl restart cloudflared${NC}"
        
        read -p "是否保留当前配置以便手动调试？(Y/n): " keep_for_debug
        if [[ "$keep_for_debug" =~ ^[Nn]$ ]]; then
            if $rollback_needed; then uninstall_cloudflared; fi
            rm -rf "$temp_dir"
            return 1
        else
            log_warn "⚠️  保留配置以便调试，安装可能不完整。请手动解决问题并重启服务。"
            # 保存状态信息
            echo "incomplete" > "$CF_CONFIG_DIR/install_status.txt"
        fi
    fi
    
    # 保存关键信息到文件（检查点恢复用）
    echo "$CF_TUNNEL_DOMAIN" > "$CF_CONFIG_DIR/domain.txt"
    echo "$UUID" > "$CF_CONFIG_DIR/uuid.txt"
    echo "$TUNNEL_NAME" > "$CF_CONFIG_DIR/name.txt"
    echo "$install_checkpoint" > "$CF_CONFIG_DIR/install_checkpoint.txt"
    echo "complete" > "$CF_CONFIG_DIR/install_status.txt"
    
    rm -rf "$temp_dir"
    log_info "✅ Cloudflare Tunnel 原子化安装成功"
    return 0
}

# 故障恢复函数 (此函数由 check_and_repair_installation 调用，不直接 exposed)
recover_from_failure() {
    local checkpoint="$1"
    
    log_info "尝试从检查点恢复: $checkpoint"
    
    case "$checkpoint" in
        "download")
            log_info "从下载阶段恢复..."
            # 清理可能的部分下载文件和包
            apt autoremove -y cloudflared 2>/dev/null || true
            rm -rf /tmp/cloudflared-linux*.deb /tmp/cloudflared-linux* 2>/dev/null || true
            ;;
        "login")
            log_info "从登录阶段恢复..."
            # 清理授权文件
            rm -rf /root/.cloudflared/* 2>/dev/null || true
            ;;
        "tunnel_create")
            log_info "从隧道创建阶段恢复..."
            # 尝试清理可能创建的隧道
            if [ -n "$TUNNEL_NAME" ]; then
                cloudflared tunnel delete "$TUNNEL_NAME" 2>/dev/null || true
            fi
            ;;
        "config"|"dns"|"service"|"start"|"verify")
            log_info "从配置/服务阶段恢复..."
            # 保留 cloudflared 二进制，只清理配置
            systemctl stop cloudflared 2>/dev/null || true
            systemctl disable cloudflared 2>/dev/null || true
            rm -rf "$CF_CONFIG_DIR" /root/.cloudflared
            ;;
    esac
    log_info "检查点 '$checkpoint' 清理完成，可以尝试重新安装或修复。"
}


# 检查和修复不完整的安装
check_and_repair_installation() {
    log_info "检查是否存在不完整的安装..."
    if [ -f "$CF_CONFIG_DIR/install_status.txt" ]; then
        log_debug "找到安装状态文件，检查安装状态..."
=======
# 检查和修复不完整的安装
check_and_repair_installation() {
    log_info "检查是否存在不完整的安装..."
    if [ -f "$CF_CONFIG_DIR/install_status.txt" ]; then
        log_debug "找到安装状态文件，检查安装状态..."
        local status=$(cat "$CF_CONFIG_DIR/install_status.txt")
        if [ "$status" == "incomplete" ]; then
            log_warn "检测到不完整的 Cloudflare Tunnel 安装。"
            
            if [ -f "$CF_CONFIG_DIR/install_checkpoint.txt" ]; then
                local checkpoint=$(cat "$CF_CONFIG_DIR/install_checkpoint.txt")
                echo -e "${YELLOW}上次安装失败于: $checkpoint${NC}"
                
                read -p "是否尝试修复安装？(Y/n): " repair_confirm
                if [[ ! "$repair_confirm" =~ ^[Nn]$ ]]; then
                    log_info "开始修复安装..."
                    
                    # 尝试从失败的检查点继续
                    case "$checkpoint" in
                        "verify"|"start")
                            # 尝试重启服务
                            log_info "尝试重启 Cloudflare Tunnel 服务..."
                            if systemctl restart cloudflared 2>/dev/null; then
                                if check_service_status "cloudflared"; then
                                    echo "complete" > "$CF_CONFIG_DIR/install_status.txt"
                                    log_info "✅ Cloudflare Tunnel 修复成功"
                                    # 尝试重新获取并保存域名/UUID/名称
                                    local current_uuid=$(get_tunnel_uuid)
                                    local current_tunnel_name=$(cat "$CF_CONFIG_DIR/name.txt" 2>/dev/null || echo "$TUNNEL_NAME")
                                    local current_cf_domain="${current_tunnel_name}.cfargotunnel.com"
                                    echo "$current_cf_domain" > "$CF_CONFIG_DIR/domain.txt"
                                    echo "$current_uuid" > "$CF_CONFIG_DIR/uuid.txt"
                                    echo "$current_tunnel_name" > "$CF_CONFIG_DIR/name.txt"
                                    return 0
                                fi
                            fi
                            ;;
                        "service")
                            # 重新安装服务
                            log_info "尝试重新安装 Cloudflare Tunnel 服务..."
                            if cloudflared service install --config "$CF_CONFIG_DIR/config.yml" 2>/dev/null; then
                                systemctl enable cloudflared && systemctl start cloudflared
                                if check_service_status "cloudflared"; then
                                    echo "complete" > "$CF_CONFIG_DIR/install_status.txt"
                                    log_info "✅ Cloudflare Tunnel 修复成功"
                                    return 0
                                fi
                            fi
                            ;;
                        "dns")
                            # 重新配置 DNS
                            log_info "尝试重新配置 DNS 记录..."
                            local current_tunnel_name=$(cat "$CF_CONFIG_DIR/name.txt" 2>/dev/null || echo "$TUNNEL_NAME")
                            local current_cf_domain=$(cat "$CF_CONFIG_DIR/domain.txt" 2>/dev/null)
                            if [ -n "$current_tunnel_name" ] && [ -n "$current_cf_domain" ] && \
                                retry_with_backoff 3 5 "配置 DNS 记录" cloudflared tunnel route dns "$current_tunnel_name" "$current_cf_domain"; then
                                log_info "✅ DNS 记录修复成功"
                                # 尝试启动服务
                                systemctl enable cloudflared && systemctl start cloudflared
                                if check_service_status "cloudflared"; then
                                    echo "complete" > "$CF_CONFIG_DIR/install_status.txt"
                                    log_info "✅ Cloudflare Tunnel 修复成功"
                                    return 0
                                fi
                            fi
                            ;;
                        "config"|"tunnel_create"|"login"|"download")
                            # 对于这些早期阶段的失败，最好是进行清理后重新安装
                            log_warn "上次失败发生在早期阶段 ($checkpoint)，建议执行完全卸载后重新安装。"
                            return 1
                            ;;
                    esac
                    
                    log_warn "自动修复失败。建议执行 '$0 reinstall'。"
                fi
            fi
        fi
    else
        log_debug "未找到安装状态文件，表示这是全新安装"
    fi
    return 1
}

# 预检查函数
pre_install_check() {
    log_info "执行预安装检查..."
    
    # 检查网络连接 - 优先尝试 IPv6，失败则回退到 IPv4
    log_info "检查网络连接到 GitHub API..."
    local connection_success=false
    
    # 首先尝试 IPv6 连接
    if timeout 10 curl -s -6 https://api.github.com > /dev/null 2>&1; then
        log_info "✅ IPv6 连接到 GitHub API 成功"
        connection_success=true
    else
        log_warn "IPv6 连接到 GitHub API 失败，尝试 IPv4..."
        # 回退到 IPv4 连接
        if timeout 10 curl -s -4 https://api.github.com > /dev/null 2>&1; then
            log_info "✅ IPv4 连接到 GitHub API 成功"
            connection_success=true
        else
            log_warn "IPv4 连接也失败，尝试不指定协议版本..."
            # 最后尝试不指定协议版本
            if timeout 10 curl -s https://api.github.com > /dev/null 2>&1; then
                log_info "✅ 连接到 GitHub API 成功"
                connection_success=true
            fi
        fi
    fi
    
    if ! $connection_success; then
        log_error "无法连接到 GitHub API，这可能影响下载Hysteria2和Cloudflare Tunnel。请检查网络或防火墙。"
        log_info "提示：你可以尝试以下解决方案："
        log_info "1. 检查防火墙设置"
        log_info "2. 检查 IPv6 配置"
        log_info "3. 使用代理或更换网络环境"
        return 1
    fi
    
    # 检查磁盘空间 (至少需要2GB可用空间)
    local required_space_kb=2097152 # 2GB
    local available_space_kb=$(df -k / | awk 'NR==2 {print $4}')
    if [ "$available_space_kb" -lt "$required_space_kb" ]; then
        local available_space_gb=$(echo "scale=2; $available_space_kb / 1024 / 1024" | bc)
        log_warn "磁盘空间不足 (可用: ${available_space_gb}GB)，建议至少有 2GB 可用空间，可能影响安装或后续运行。"
    else
        log_debug "磁盘空间充足。"
    fi
    
    # 检查内存 (至少需要256MB可用内存)
    local required_memory_mb=256
    local available_memory_mb=$(free -m | awk 'NR==2{print $7}')
    if [ "$available_memory_mb" -lt "$required_memory_mb" ]; then
        log_warn "可用内存不足 (${available_memory_mb}MB)，建议至少有 256MB 可用内存，可能影响服务运行稳定性。"
    else
        log_debug "内存充足。"
    fi
    
    return 0
}

# 主安装函数（超级增强容错版）
install_all() {
    show_banner
    log_info "=== 开始安装 Hysteria2 + Cloudflare Tunnel (超级增强容错版) ==="
    
    # 前置检查
    check_root
    check_system
    pre_install_check || exit 1
    check_ipv6
    check_port
    
    # 检查并修复不完整的安装
    if check_and_repair_installation; then
        log_info "✅ 现有安装已成功修复！"
        show_config
        return 0
    fi
    
    # 如果没有不完整的安装需要修复，继续正常安装流程
    log_debug "没有检测到不完整的安装，继续正常安装流程..."
    
    # 检查现有安装
    check_installation_status
    local install_status=$?
    
    if [ $install_status -eq 0 ]; then
        log_warn "检测到完整安装且服务正在运行。"
        echo -e "${YELLOW}现有服务状态：${NC}"
        show_status_brief
        echo ""
        echo -e "${YELLOW}安装选项：${NC}"
        echo -e "${CYAN}1. 覆盖安装（推荐，将删除现有配置并重新安装）${NC}"
        echo -e "${CYAN}2. 保持现有配置（跳过安装）${NC}"
        echo -e "${CYAN}3. 备份后重新安装${NC}"
        read -p "请选择 (1-3): " install_choice
        
        case "$install_choice" in
            "1")
                log_info "执行覆盖安装..."
                uninstall_all
                ;;
            "2")
                log_info "保持现有配置，跳过安装。"
                show_config
                return 0
                ;;
            "3")
                log_info "备份后重新安装..."
                backup_configs
                uninstall_all
                ;;
            *)
                log_info "安装已取消"
                exit 0
                ;;
        esac
    elif [ $install_status -eq 1 ]; then
        log_warn "检测到部分安装或残留文件，建议清理后重新安装。"
        echo -e "${YELLOW}检测到的组件：${NC}"
        if [ -f "/usr/local/bin/hysteria2" ] || [ -d "$HYSTERIA_CONFIG_DIR" ]; then
            echo -e "  ${CYAN}• Hysteria2 相关文件/服务${NC}"
        fi
        if command -v cloudflared &> /dev/null || [ -d "$CF_CONFIG_DIR" ]; then
            echo -e "  ${CYAN}• Cloudflared 相关文件/服务${NC}"
        fi
        
        read -p "是否清理残留文件后重新安装？(Y/n): " confirm
        if [[ ! "$confirm" =~ ^[Nn]$ ]]; then
            backup_configs
            uninstall_all
            log_info "清理完成，3秒后继续安装..."
            sleep 3
        fi
    fi
    
    # 创建安装锁文件
    local install_lock="/tmp/hy2_install.lock"
    echo "$$" > "$install_lock" # 存储PID
    
    # 更新系统
    log_info "更新系统并安装依赖..."
    export DEBIAN_FRONTEND=noninteractive
    
    # 分步骤安装依赖，增强容错性
    local base_packages=(curl wget unzip socat net-tools iputils-ping dnsutils openssl bc)
    local optional_packages=(jq htop iotop) # jq现在是关键依赖，但为兼容旧系统先放可选
    
    if ! apt update -y; then
        log_warn "apt update 失败，尝试修复包管理器..."
        apt --fix-broken install -y || true
        dpkg --configure -a || true
        apt update -y || {
            log_error "系统包管理器故障，请手动修复 'apt update' 后再试。"
            cleanup_and_exit 1
        }
    fi
    
    # 安装基础包
    for package in "${base_packages[@]}"; do
        if ! dpkg -l | grep -q "^ii.*$package"; then
            log_info "安装必需包: $package"
            if ! retry_with_backoff 3 2 "安装 $package" apt install -y "$package"; then
                log_error "关键包 $package 安装失败。请手动安装此包并重试。"
                cleanup_and_exit 1
            fi
        fi
    done
    
    # 安装可选包（失败不影响主流程）
    for package in "${optional_packages[@]}"; do
        if ! dpkg -l | grep -q "^ii.*$package"; then
            apt install -y "$package" 2>/dev/null || log_warn "可选包 $package 安装失败，不影响核心功能。"
        fi
    done
    
    # 阶段1: 安装 Hysteria2
    log_info "🚀 阶段1: 安装 Hysteria2..."
    if ! install_hysteria_atomic; then
        log_error "Hysteria2 安装失败，回滚所有Hysteria2组件。"
        cleanup_and_exit 1
    fi
    log_info "✅ Hysteria2 安装完成"
    
    # 阶段2: 安装 Cloudflare Tunnel（超级增强版）
    log_info "🌐 阶段2: 安装 Cloudflare Tunnel..."
    local cf_install_result
    install_cloudflared_atomic
    cf_install_result=$?
    
    case $cf_install_result in
        0)
            log_info "✅ Cloudflare Tunnel 安装完成"
            ;;
        1)
            log_error "❌ Cloudflare Tunnel 安装失败。"
            echo -e "\n${RED}🚨 安装失败处理选项：${NC}"
            echo -e "${CYAN}1. 保留 Hysteria2，仅使用 IPv6 直连${NC}"
            echo -e "${CYAN}2. 稍后手动配置 Cloudflare Tunnel${NC}"
            echo -e "${CYAN}3. 完全回滚所有安装${NC}"
            
            read -p "请选择处理方式 (1-3): " failure_choice
            case "$failure_choice" in
                "1")
                    log_info "保留 Hysteria2 安装，Cloudflare Tunnel 已回滚。"
                    show_hysteria_only_config
                    cleanup_and_exit 0
                    ;;
                "2")
                    log_info "保留当前状态，提供手动配置指南。Cloudflare Tunnel 已回滚。"
                    show_manual_cloudflare_guide
                    cleanup_and_exit 0
                    ;;
                "3")
                    log_info "执行完全回滚所有安装。"
                    uninstall_hysteria
                    cleanup_and_exit 1
                    ;;
                *)
                    log_error "无效选择，执行回滚所有安装。"
                    uninstall_hysteria
                    cleanup_and_exit 1
                    ;;
            esac
            ;;
        2)
            log_warn "⚠️  Cloudflare Tunnel 部分安装成功，可能需要手动完成配置。"
            echo -e "${YELLOW}您可以稍后手动完成配置，详情请查看日志或使用 '$0 repair' 命令尝试修复。${NC}"
            show_partial_install_guide
            ;;
    esac
    
    # 等待服务完全启动
    log_info "等待所有服务完全启动并稳定..."
    sleep 15
    
    # 最终验证
    log_info "执行最终验证..."
    local final_check=true
    
    if ! systemctl is-active --quiet hysteria-server; then
        log_error "❌ Hysteria2 服务未运行。"
        final_check=false
    fi
    
    if [ "$cf_install_result" -eq 0 ] && ! systemctl is-active --quiet cloudflared; then
        log_error "❌ Cloudflare Tunnel 服务未运行。"
        final_check=false
    fi
    
    if ! $final_check; then
        log_error "服务验证失败。部分服务可能未正常启动。"
        show_status
        
        echo -e "\n${YELLOW}故障排除建议：${NC}"
        echo -e "${CYAN}1. 检查服务日志: journalctl -u hysteria-server -f${NC}"
        echo -e "${CYAN}2. 检查服务日志: journalctl -u cloudflared -f${NC}"
        echo -e "${CYAN}3. 尝试重启服务: systemctl restart hysteria-server cloudflared${NC}"
        echo -e "${CYAN}4. 查看完整状态: $0 status${NC}"
        
        cleanup_and_exit 1
    fi
    
    # 连接测试
    log_info "执行连接测试..."
    test_connection
    
    # 显示配置信息
    show_config
    
    # 保存安装信息
    local install_info="/root/hy2_install_$(date +%Y%m%d_%H%M%S).log"
    {
        echo "=== Hysteria2 + Cloudflare Tunnel 安装记录 ==="
        echo "安装时间: $(date)"
        echo "脚本版本: 超级增强容错版 v2.1"
        echo "系统信息: $(uname -a)"
        echo ""
        echo "安装状态: 成功"
        echo "Hysteria2 状态: $(systemctl is-active hysteria-server)"
        echo "Cloudflared 状态: $(systemctl is-active cloudflared)"
        echo ""
        if [ -f "$CF_CONFIG_DIR/domain.txt" ]; then
            echo "Tunnel 域名: $(cat $CF_CONFIG_DIR/domain.txt)"
        fi
        if [ -f "$CF_CONFIG_DIR/uuid.txt" ]; then
            echo "Tunnel UUID: $(cat $CF_CONFIG_DIR/uuid.txt)"
        fi
        echo "IPv6 地址: $(ip -6 addr show scope global | grep inet6 | awk '{print $2}' | cut -d/ -f1 | head -n 1)"
    } > "$install_info"
    
    # 清理安装锁
    rm -f "$install_lock"
    
    log_info "✅ 安装完成！请保存上述配置信息。"
    echo -e "\n${GREEN}🎉 超级增强容错版安装成功完成！${NC}"
    echo -e "${CYAN}📋 安装记录保存在: $install_info${NC}"
    echo -e "${CYAN}💡 提示: 使用 '$0 status' 检查服务状态${NC}"
    echo -e "${CYAN}💡 提示: 使用 '$0 config' 重新显示配置${NC}"
    echo -e "${CYAN}💡 提示: 使用 '$0 test' 测试连接${NC}"
}

# 安装错误处理函数
handle_install_error() {
    local exit_code=$1
    local lock_file=$2
    
    # 防止重复执行
    if [ -f "$lock_file" ]; then
        local lock_pid=$(cat "$lock_file")
        if [ "$lock_pid" != "$$" ]; then
            log_warn "另一个脚本实例可能正在处理错误，当前实例退出。"
            exit $exit_code
        fi
    fi

    log_error "安装过程中发生错误 (退出码: $exit_code)"
    
    # 清理安装锁
    rm -f "$lock_file"
    
    echo -e "\n${RED}🚨 安装失败处理${NC}"
    echo -e "${YELLOW}错误发生时间: $(date)${NC}"
    
    # 收集错误信息
    echo -e "\n${BLUE}📊 错误诊断信息:${NC}"
    echo "系统负载: $(uptime)"
    echo "磁盘空间: $(df -h / | tail -1)"
    echo "内存使用: $(free -m)"
    
    # 服务状态
    if systemctl list-units --full -all | grep -q hysteria-server.service; then
        echo "Hysteria2 服务状态: $(systemctl is-active hysteria-server 2>/dev/null || echo 'inactive')"
        log_info "Hysteria2 服务日志 (最近20行):"
        journalctl -u hysteria-server --no-pager -n 20 2>/dev/null || echo "无法获取Hysteria2日志"
    fi
    if systemctl list-units --full -all | grep -q cloudflared.service; then
        echo "Cloudflared 服务状态: $(systemctl is-active cloudflared 2>/dev/null || echo 'inactive')"
        log_info "Cloudflared 服务日志 (最近20行):"
        journalctl -u cloudflared --no-pager -n 20 2>/dev/null || echo "无法获取Cloudflared日志"
    fi
    
    # 最近的系统日志
    echo -e "\n${BLUE}📋 系统错误日志 (最近10行):${NC}"
    journalctl --no-pager -n 10 -p err 2>/dev/null || echo "无法获取系统日志"
    
    echo -e "\n${YELLOW}建议的处理步骤：${NC}"
    echo -e "${CYAN}1. 仔细查看上述日志和错误信息。${NC}"
    echo -e "${CYAN}2. 尝试修复后，使用 '$0 repair' 命令尝试修复安装。${NC}"
    echo -e "${CYAN}3. 如果修复无效，尝试 '$0 uninstall && $0 install' 进行完全清理和重新安装。${NC}"
    echo -e "${CYAN}4. 检查网络连接和系统资源是否充足。${NC}"
    echo -e "${CYAN}5. 如果Cloudflare Tunnel始终失败，可以尝试 '$0 hysteria-only' 仅安装Hysteria2。${NC}"
    
    # 退出前不进行额外的清理，保留现场以便诊断
    exit $exit_code
}

# 清理并退出函数 (用于正常退出或已知错误)
cleanup_and_exit() {
    local exit_code=$1
    
    # 清理临时文件
    rm -rf /tmp/cloudflared-linux*.deb /tmp/cloudflared-linux* 2>/dev/null || true
    
    # 清理安装锁
    rm -f /tmp/hy2_install.lock
    
    exit $exit_code
}

# 仅显示 Hysteria2 配置
show_hysteria_only_config() {
    local password=""
    if [ -f "$HYSTERIA_CONFIG_DIR/config.yaml" ]; then
        password=$(grep "password:" "$HYSTERIA_CONFIG_DIR/config.yaml" | awk '{print $2}' | tr -d '"')
    else
        log_error "Hysteria2 配置文件不存在，无法显示密码。"
    fi
    local ipv6=$(ip -6 addr show scope global | grep inet6 | awk '{print $2}' | cut -d/ -f1 | head -n 1)
    
    echo -e "\n${GREEN}📡 仅 Hysteria2 直连配置:${NC}"
    echo -e "${CYAN}服务器: [$ipv6]:$PORT${NC}"
    echo -e "${CYAN}密码: $password${NC}"
    echo -e "${CYAN}SNI: $SNI${NC}"
    
    echo -e "\n${GREEN}📎 Clash Meta (仅Hysteria2直连) 配置:${NC}"
    cat <<EOL
proxies:
  - name: 🌐 Hy2-Direct-IPv6
    type: hysteria2
    server: "$ipv6"
    port: $PORT
    password: "$password"
    sni: "$SNI"
    skip-cert-verify: true
EOL
    
    echo -e "\n${GREEN}📎 Sing-box (仅Hysteria2直连) 配置:${NC}"
    cat <<EOL
{
  "outbounds": [
    {
      "type": "hysteria2",
      "tag": "Hy2-Direct-IPv6",
      "server": "$ipv6",
      "server_port": $PORT,
      "password": "$password",
      "tls": {
        "enabled": true,
        "server_name": "$SNI",
        "insecure": true
      }
    }
  ]
}
EOL

    echo -e "\n${GREEN}📱 V2rayNG (仅Hysteria2直连) 配置:${NC}"
    cat <<EOL
服务器地址: [$ipv6]
端口: $PORT
密码: $PASSWORD
传输协议: hysteria2
伪装域名(SNI): $SNI
跳过证书验证: 是
EOL
    echo -e "${PURPLE}=======================================================${NC}"
}

# 显示手动配置 Cloudflare 指南
show_manual_cloudflare_guide() {
    echo -e "\n${BLUE}🔧 手动配置 Cloudflare Tunnel 指南:${NC}"
    echo -e "${CYAN}1. 登录授权 (如果未完成):${NC}"
    echo -e "   ${YELLOW}cloudflared tunnel login${NC}"
    echo -e "${CYAN}2. 创建隧道 (如果需要新隧道):${NC}"
    echo -e "   ${YELLOW}cloudflared tunnel create <您的隧道名称>${NC}"
    echo -e "${CYAN}3. 获取隧道UUID (如果已知隧道名称):${NC}"
    echo -e "   ${YELLOW}cloudflared tunnel list --json | jq -r '.[] | select(.name==\"<您的隧道名称>\") | .id'${NC}"
    echo -e "${CYAN}4. 生成配置文件:${NC}"
    echo -e "   在 '$CF_CONFIG_DIR/config.yml' 中创建或修改配置，参考以下模板：${NC}"
    echo -e "${YELLOW}--- (config.yml 模板) ---${NC}"
    echo "tunnel: <您的隧道UUID>"
    echo "credentials-file: $CF_CONFIG_DIR/<您的隧道UUID>.json"
    echo "ingress:"
    echo "  - hostname: <您的Cloudflare域名>"
    echo "    service: https://localhost:$PORT"
    echo "    originRequest:"
    echo "      noTLSVerify: true"
    echo "      httpHostHeader: $SNI"
    echo "  - service: http_status:404"
    echo -e "${YELLOW}--- (模板结束) ---${NC}"
    echo -e "${CYAN}5. 配置DNS记录 (可选):${NC}"
    echo -e "   ${YELLOW}cloudflared tunnel route dns <您的隧道名称> <您的Cloudflare域名>${NC}"
    echo -e "${CYAN}6. 安装并启动服务:${NC}"
    echo -e "   ${YELLOW}cloudflared service install --config $CF_CONFIG_DIR/config.yml${NC}"
    echo -e "   ${YELLOW}systemctl enable --now cloudflared${NC}"
    echo -e "${PURPLE}=======================================================${NC}"
}

# 显示部分安装指南
show_partial_install_guide() {
    echo -e "\n${YELLOW}⚠️  部分安装完成指南:${NC}"
    echo -e "${CYAN}cloudflared 已安装，但可能未完全配置或启动。${NC}"
    echo -e "${CYAN}请检查以下文件和服务：${NC}"
    echo -e "  • Cloudflare Tunnel 配置文件: $CF_CONFIG_DIR/config.yml"
    echo -e "  • Cloudflare Tunnel 凭证文件: $CF_CONFIG_DIR/*.json"
    echo -e "  • Cloudflare Tunnel 服务状态: systemctl status cloudflared"
    echo -e "${CYAN}您可以尝试运行 '$0 repair' 命令来自动修复安装。${NC}"
    echo -e "${CYAN}如果需要重新开始，请运行 '$0 reinstall'。${NC}"
    echo -e "${PURPLE}=======================================================${NC}"
}

# 简要状态显示
show_status_brief() {
    local hysteria_status="❌ 未运行"
    local cloudflared_status="❌ 未运行"
    
    if systemctl is-active --quiet hysteria-server 2>/dev/null; then
        hysteria_status="✅ 运行中"
    fi
    
    if systemctl is-active --quiet cloudflared 2>/dev/null; then
        cloudflared_status="✅ 运行中"
    fi
    
    echo -e "Hysteria2: $hysteria_status"
    echo -e "Cloudflare Tunnel: $cloudflared_status"
}

# 显示服务状态（增强版）
show_status() {
    show_banner
    log_info "=== 详细服务状态 ==="
    
    echo -e "\n${BLUE}📊 服务运行状态:${NC}"
    show_status_brief
    
    echo -e "\n${BLUE}🔧 Hysteria2 服务详情:${NC}"
    if systemctl list-units --full -all | grep -Fq "hysteria-server.service"; then
        systemctl status hysteria-server --no-pager -l
        echo ""
        echo -e "${BLUE}📋 Hysteria2 最近日志 (最近15行，过去10分钟内):${NC}"
        journalctl -u hysteria-server --no-pager -n 15 --since "10 minutes ago" || echo "无Hysteria2日志"
    else
        echo "Hysteria2 服务未安装"
    fi
    
    echo -e "\n${BLUE}🔧 Cloudflare Tunnel 服务详情:${NC}"
    if systemctl list-units --full -all | grep -Fq "cloudflared.service"; then
        systemctl status cloudflared --no-pager -l
        echo ""
        echo -e "${BLUE}📋 Cloudflared 最近日志 (最近15行，过去10分钟内):${NC}"
        journalctl -u cloudflared --no-pager -n 15 --since "10 minutes ago" || echo "无Cloudflared日志"
    else
        echo "Cloudflare Tunnel 服务未安装"
    fi
    
    # 显示网络信息
    echo -e "\n${BLUE}🌐 网络信息:${NC}"
    local ipv6=$(ip -6 addr show scope global | grep inet6 | awk '{print $2}' | cut -d/ -f1 | head -n 1)
    echo "VPS IPv6 地址: ${ipv6:-未找到}"
    
    if [ -f "$CF_CONFIG_DIR/domain.txt" ]; then
        local cf_domain=$(cat "$CF_CONFIG_DIR/domain.txt" | tr -d '\n\r')
        echo "Cloudflare Tunnel 域名: $cf_domain"
        
        # 测试隧道连通性 - 支持网络协议回退
        log_info "测试 Cloudflare Tunnel 域名连通性..."
        local connectivity_test_success=false
        local test_methods=(
            "curl -6 -s -o /dev/null -w %{http_code}"  # IPv6
            "curl -4 -s -o /dev/null -w %{http_code}"  # IPv4
            "curl -s -o /dev/null -w %{http_code}"     # 默认协议
        )
        
        for method in "${test_methods[@]}"; do
            if timeout 10 $method "https://$cf_domain" | grep -q "404"; then
                log_info "✅ Cloudflare Tunnel 域名连通性正常 (收到404响应，表明隧道已连接并转发请求)"
                connectivity_test_success=true
                break
            fi
        done
        
        if ! $connectivity_test_success; then
            log_warn "⚠️  Cloudflare Tunnel 域名连通性测试失败。请检查DNS设置或隧道配置。"
        fi
    else
        log_warn "未找到 Cloudflare Tunnel 域名信息。"
    fi
    echo -e "${PURPLE}=======================================================${NC}"
}

# 显示客户端配置（增强版）
show_config() {
    # 获取信息
    if [ -f "$HYSTERIA_CONFIG_DIR/config.yaml" ]; then
        PASSWORD=$(grep "password:" "$HYSTERIA_CONFIG_DIR/config.yaml" | awk '{print $2}' | tr -d '"')
    else
        log_error "Hysteria2 配置文件不存在，无法显示密码。"
        PASSWORD="N/A"
    fi
    
    if [ -f "$CF_CONFIG_DIR/domain.txt" ]; then
        CF_TUNNEL_DOMAIN=$(cat "$CF_CONFIG_DIR/domain.txt" | tr -d '\n\r')
    else
        log_warn "Cloudflare Tunnel 域名文件不存在，尝试从配置获取。"
        CF_TUNNEL_DOMAIN="N/A"
        local tunnel_name_from_file=$(cat "$CF_CONFIG_DIR/name.txt" 2>/dev/null | tr -d '\n\r')
        if [ -n "$tunnel_name_from_file" ]; then
             CF_TUNNEL_DOMAIN="${tunnel_name_from_file}.cfargotunnel.com"
             log_info "从隧道名称推断域名: $CF_TUNNEL_DOMAIN"
        fi
    fi
    
    IPV6=$(ip -6 addr show scope global | grep inet6 | awk '{print $2}' | cut -d/ -f1 | head -n 1)
    if [ -z "$IPV6" ]; then
        IPV6="未找到IPv6地址"
        log_warn "未找到全局 IPv6 地址，直连配置可能不可用。"
    fi
    
    echo -e "\n${PURPLE}=======================================================${NC}"
    echo -e "${PURPLE}🎉 Hysteria2 + Cloudflare Tunnel 配置信息${NC}"
    echo -e "${PURPLE}=======================================================${NC}"
    echo -e "${CYAN}📌 VPS IPv6 地址: [$IPV6]:$PORT${NC}"
    echo -e "${CYAN}🔐 Hysteria2 密码: $PASSWORD${NC}"
    echo -e "${CYAN}🌐 Cloudflare Tunnel 域名: $CF_TUNNEL_DOMAIN${NC}"
    echo -e "${CYAN}🔧 SNI: $SNI${NC}"
    echo -e "${PURPLE}------------------------------------------------------${NC}"
    
    echo -e "\n${GREEN}📎 Clash Meta 配置:${NC}"
    cat <<EOL
proxies:
  - name: 🌐 Hy2-CF-Tunnel
    type: hysteria2
    server: $CF_TUNNEL_DOMAIN
    port: 443
    password: "$PASSWORD"
    sni: "$SNI"
    skip-cert-verify: true
    
  - name: 🌐 Hy2-Direct-IPv6
    type: hysteria2
    server: "$IPV6"
    port: $PORT
    password: "$PASSWORD"
    sni: "$SNI"
    skip-cert-verify: true
EOL
    
    echo -e "\n${GREEN}📎 Sing-box 配置:${NC}"
    cat <<EOL
{
  "outbounds": [
    {
      "type": "hysteria2",
      "tag": "Hy2-CF-Tunnel",
      "server": "$CF_TUNNEL_DOMAIN",
      "server_port": 443,
      "password": "$PASSWORD",
      "tls": {
        "enabled": true,
        "server_name": "$SNI",
        "insecure": true
      }
    },
    {
      "type": "hysteria2",
      "tag": "Hy2-Direct-IPv6",
      "server": "$IPV6",
      "server_port": $PORT,
      "password": "$PASSWORD",
      "tls": {
        "enabled": true,
        "server_name": "$SNI",
        "insecure": true
      }
    }
  ]
}
EOL

    echo -e "\n${GREEN}📱 V2rayNG 配置:${NC}"
    cat <<EOL
服务器地址: $CF_TUNNEL_DOMAIN
端口: 443
密码: $PASSWORD
传输协议: hysteria2
伪装域名(SNI): $SNI
跳过证书验证: 是
EOL
    
    echo -e "\n${BLUE}🔧 管理命令:${NC}"
    echo -e "查看服务状态: ${CYAN}$0 status${NC}"
    echo -e "显示配置: ${CYAN}$0 config${NC}"
    echo -e "重新安装: ${CYAN}$0 reinstall${NC}"
    echo -e "完全卸载: ${CYAN}$0 uninstall${NC}"
    echo -e "备份配置: ${CYAN}$0 backup${NC}"
    echo -e "恢复配置: ${CYAN}$0 restore${NC}"
    echo -e "尝试修复: ${CYAN}$0 repair${NC}"
    echo -e "仅安装Hysteria2: ${CYAN}$0 hysteria-only${NC}"
    echo -e "测试连接: ${CYAN}$0 test${NC}"
    echo -e "${PURPLE}=======================================================${NC}"
    
    # 保存配置到文件
    local config_file="/root/hysteria2_config_$(date +%Y%m%d_%H%M%S).txt"
    {
        echo "=== Hysteria2 + Cloudflare Tunnel 配置信息 ==="
        echo "生成时间: $(date)"
        echo "VPS IPv6: [$IPV6]:$PORT"
        echo "密码: $PASSWORD"
        echo "Tunnel域名: $CF_TUNNEL_DOMAIN"
        echo "SNI: $SNI"
        echo ""
        echo "=== Clash Meta 配置 ==="
        cat <<EOL2
proxies:
  - name: 🌐 Hy2-CF-Tunnel
    type: hysteria2
    server: $CF_TUNNEL_DOMAIN
    port: 443
    password: "$PASSWORD"
    sni: "$SNI"
    skip-cert-verify: true
    
  - name: 🌐 Hy2-Direct-IPv6
    type: hysteria2
    server: "$IPV6"
    port: $PORT
    password: "$PASSWORD"
    sni: "$SNI"
    skip-cert-verify: true
EOL2
    } > "$config_file"
    
    log_info "配置信息已保存到: $config_file"
}

# 测试连接函数
test_connection() {
    log_info "执行连接测试..."
    
    local test_succeeded=true
    
    # 测试 Hysteria2 服务
    if systemctl is-active --quiet hysteria-server 2>/dev/null && [ -f "$HYSTERIA_CONFIG_DIR/config.yaml" ]; then
        local current_ipv6=$(ip -6 addr show scope global | grep inet6 | awk '{print $2}' | cut -d/ -f1 | head -n 1)
        local current_password=$(grep "password:" "$HYSTERIA_CONFIG_DIR/config.yaml" | awk '{print $2}' | tr -d '"')
        if [ -n "$current_ipv6" ] && [ -n "$current_password" ]; then
            log_info "测试 Hysteria2 本地直连..."
            if timeout 5 /usr/local/bin/hysteria2 client -s "[$current_ipv6]:$PORT" -a "$current_password" --sni "$SNI" --insecure -t 3 2>/dev/null; then
                log_info "✅ Hysteria2 直连测试成功。"
            else
                log_warn "⚠️  Hysteria2 直连测试失败。请检查Hysteria2服务日志和端口是否开放。"
                test_succeeded=false
            fi
        else
            log_warn "Hysteria2 直连测试信息不完整，跳过测试。"
        fi
    else
        log_warn "Hysteria2 服务未运行或配置不存在，跳过直连测试。"
    fi
    
    # 测试 Cloudflare Tunnel
    if systemctl is-active --quiet cloudflared 2>/dev/null && [ -f "$CF_CONFIG_DIR/domain.txt" ]; then
        local cf_domain=$(cat "$CF_CONFIG_DIR/domain.txt" | tr -d '\n\r')
        if [ "$cf_domain" != "N/A" ]; then
            log_info "测试 Cloudflare Tunnel 域名连通性..."
            local cf_connectivity_success=false
            local cf_test_methods=(
                "curl -6 -s -o /dev/null -w %{http_code}"  # IPv6
                "curl -4 -s -o /dev/null -w %{http_code}"  # IPv4
                "curl -s -o /dev/null -w %{http_code}"     # 默认协议
            )
            
            for method in "${cf_test_methods[@]}"; do
                if timeout 10 $method "https://$cf_domain" | grep -q "404"; then
                    log_info "✅ Cloudflare Tunnel 域名连通性正常 (收到404响应)。"
                    cf_connectivity_success=true
                    break
                fi
            done
            
            if ! $cf_connectivity_success; then
                log_warn "⚠️  Cloudflare Tunnel 域名连通性测试失败。请检查Cloudflare DNS设置或隧道服务日志。"
                test_succeeded=false
            fi
        else
            log_warn "Cloudflare Tunnel 域名信息不可用，跳过测试。"
        fi
    else
        log_warn "Cloudflare Tunnel 服务未运行或配置不存在，跳过隧道连通性测试。"
    fi
    
    if $test_succeeded; then
        log_info "✅ 所有选定的连接测试均成功。"
        return 0
    else
        log_error "❌ 部分连接测试失败。"
        return 1
    fi
}

# 主函数（超级增强容错版）
main() {
    # 确保日志目录存在
    mkdir -p "$(dirname "$SCRIPT_LOG")"
    touch "$SCRIPT_LOG"
    
    # 捕获中断信号和错误
    trap 'handle_install_error $? /tmp/hy2_install.lock' ERR
    trap 'log_error "脚本被用户中断 (Ctrl+C)"; cleanup_and_exit 130' INT TERM
    
    case "${1:-install}" in
        "install")
            install_all
            ;;
        "uninstall")
            show_banner
            uninstall_all
            ;;
        "reinstall")
            show_banner
            log_info "执行重新安装..."
            backup_configs
            uninstall_all
            sleep 3
            install_all
            ;;
        "status")
            show_status
            ;;
        "config")
            show_banner
            show_config
            ;;
        "backup")
            backup_configs
            log_info "✅ 配置备份完成"
            ;;
        "restore")
            restore_configs
            ;;
        "test")
            show_banner
            test_connection
            ;;
        "repair")
            show_banner
            log_info "尝试修复安装..."
            if check_and_repair_installation; then
                log_info "✅ 修复成功"
                show_config
            else
                log_error "修复失败，建议尝试 '$0 reinstall'。"
            fi
            ;;
        "hysteria-only")
            show_banner
            log_info "仅安装 Hysteria2..."
            check_root
            check_system
            check_ipv6
            check_port
            
            # 确保Cloudflare Tunnel被清理，避免干扰
            log_info "确保 Cloudflare Tunnel 组件被清理以进行 Hysteria2 独立安装..."
            uninstall_cloudflared
            
            if install_hysteria_atomic; then
                show_hysteria_only_config
                log_info "✅ Hysteria2 独立安装完成"
            else
                log_error "Hysteria2 安装失败"
                exit 1
            fi
            ;;
        "-h"|"--help"|"help")
            show_help
            ;;
        *)
            log_error "未知选项: $1"
            echo ""
            show_help
            cleanup_and_exit 1
            ;;
    esac
    cleanup_and_exit 0 # 正常退出
}

# 运行主函数
main "$@"
