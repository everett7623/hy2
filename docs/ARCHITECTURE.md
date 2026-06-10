# 脚本架构说明

## 设计原则

1. **零依赖运行**：每个 .sh 文件完全独立，无 `source`/`include`，无共享库
2. **curl | bash 部署**：必须支持管道执行（需含 TTY fix + bash 自举 + CRLF guard）
3. **busybox 兼容**：不用 `grep -oP`，不用 `${var,,}`，不用 `head -c`
4. **全发行版覆盖**：Debian/Ubuntu/CentOS/Alpine/Arch，systemd + openrc

## 脚本模板

添加新协议（如 Tuic、Reality 等）时，复制以下骨架：

```bash
#!/bin/bash
#========================================================================
# 项目：XXX Management Script
# 版本：v1.0.0
# 更新日期: YYYY-MM-DD
#========================================================================

# --- bash 自举 ---
[ -z "$BASH_VERSION" ] && exec bash "$0" "$@"

# --- TTY fix ---
[ ! -t 0 ] && [ -c /dev/tty ] && exec < /dev/tty

# --- CRLF guard ---
[ -f "$0" ] && grep -q $'\r' "$0" 2>/dev/null && { sed -i 's/\r$//' "$0"; exec bash "$0" "$@"; }

# ---- 颜色 ----
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; PLAIN='\033[0m'

# ---- 路径常量 ----
BIN="/usr/local/bin/xxx"
CONFIG="/etc/xxx/config.yaml"
META="/etc/xxx/meta"
SERVICE="/etc/systemd/system/xxx-server.service"

# ---- 全局状态 ----
INIT_SYS=""; NAT_MODE=0; IPV6_ONLY=0
HAS_IPV4=0; HAS_IPV6=0
PUBLIC_IP=""; PUBLIC_IPV6=""
LISTEN_PORT=""

# ---- 必须实现的核心函数 ----
# check_root()          — 检查 root
# detect_init()         — 检测 init 系统
# detect_network()      — IPv4/IPv6/NAT 检测（含 WARP 过滤）
# install_dependencies()— 安装依赖（按发行版分支）
# get_latest_version()  — 获取最新版本号
# download_xxx()        — 下载二进制（双源 fallback，return 1 不用 exit）
# install_xxx()         — 完整安装流程
# upgrade_xxx()         — 升级（含备份回滚）
# uninstall_xxx()       — 卸载
# service_start/stop/restart — 按 $INIT_SYS 分发
# show_config()         — 展示配置/分享链接
# gen_password()        — 密码生成
# main_menu()           — 主菜单循环

# ---- 可选功能 ----
# change_password()     — 修改密码（awk 块检测 + 备份回滚）
# change_bandwidth()    — 修改带宽
# change_port()         — 修改端口
# open_firewall_port()  — 防火墙单端口
# open_firewall_range() — 防火墙端口范围
# enable_bbr()          — BBR 调优
# setup_autoupdate()    — 自动更新 cron
# server_tools_menu()   — 服务工具子菜单
```

## 关键约束

| 规则 | 说明 |
|------|------|
| `return 1` 不用 `exit 1` | 下载函数失败应 return，让调用方决定是否退出 |
| 升级必须备份 | `cp "$BIN" "${BIN}.bak"` 在删除旧二进制前执行 |
| trap 不覆盖 | 设置 trap 前需考虑已存在的 trap（特别是 DNS restore） |
| awk 块检测 | 修改 YAML 配置必须用块检测（`/^auth:/` → `in_auth=1`）而非裸 sed |
| 防火墙范围 | 端口跳跃场景用 `open_firewall_range()` 而非单端口 |
| mktemp -d | 下载解压用临时目录而非临时文件，避免空文件回退 |
| IPv6 过滤 | EUserv 场景需 `_get_real_ipv6()` 排除 WARP/tunnel 网卡 |

## 文件结构

```
hy2/
├── install.sh          # 启动器（唯一入口）
├── hy2.sh              # Hysteria 2 管理
├── ss.sh               # Shadowsocks 管理
├── euservhy2.sh        # EUserv IPv6 Hysteria 2
├── CHANGELOG.md        # 更新日志
├── README.md           # 项目说明
├── CLAUDE.md           # Claude Code 指引
├── AGENTS.md           # AI Agent 指引
└── docs/
    └── ARCHITECTURE.md # 本文档
```
