# 脚本架构说明

## 设计原则

1. **零依赖运行**：每个 .sh 文件完全独立，无 `source`/`include`，无共享库
2. **远程交互部署**：面向 `bash <(curl -fsSL URL)` 运行方式，需保留 TTY fix、bash 自举与 CRLF guard
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

## 执行与发布模型

```text
用户运行 install.sh
        │
        ├── 写入 /usr/local/bin/sb 快捷命令（远程主入口优先，本地缓存兜底）
        ├── 选择 Hysteria 2 ──────> 下载 main/hy2.sh ──────> 按动作参数执行
        ├── 选择 Shadowsocks ─────> 下载 main/ss.sh ───────> 按动作参数执行
        ├── 选择 AnyTLS ──────────> 下载 main/anytls.sh ───> 按动作参数执行
        └── 选择 EUserv IPv6 HY2 ─> 下载 main/euservhy2.sh > 按动作参数执行
```

- `install.sh` 是统一远程入口，会向子脚本传入 `install`、`info`、`manage`、`upgrade`、`uninstall` 等动作参数；四个子脚本也可独立运行，不带参数时显示原菜单。
- 首次运行 `install.sh` 会写入 `/usr/local/bin/sb` 快捷命令；`sb` 会优先拉取 GitHub `main` 的最新主入口，远程失败时使用本地缓存。
- 启动器不读取仓库中的本地子脚本；未推送到 GitHub `main` 的修改不会通过启动器生效。
- 项目没有预发布分支。静态检查由 `tests/validate_scripts.sh` 和 GitHub Actions 执行；运行时行为仍需在一次性 VPS 上端到端验证。
- 五个脚本的项目版本目前保持一致，但版本文本分散在文件头、菜单和变量中，发布时必须人工同步。
- `anytls.sh` 使用 sing-box >= 1.12.0 原生 AnyTLS 入站；Shell 生成 JSON、自签证书及 `anytls-server` wrapper，不依赖 Python。

## 本地验证清单

```bash
bash tests/validate_scripts.sh
```

语法检查通过后，至少手动覆盖以下路径：

1. 全新安装与重复运行。
2. systemd 和 OpenRC 服务启停、重启与日志。
3. 标准 IPv4、NAT、双栈及纯 IPv6 网络检测。
4. 防火墙单端口与 Hysteria 2 端口跳跃范围。
5. 升级成功、下载失败及备份回滚。
6. 自动更新 cron 的创建、执行日志与移除。
7. 卸载后服务、配置和定时任务清理。

## 文件结构

```
sing-box-multi-protocol-tools/  # 仓库 slug 仍为 hy2，raw URL 不变
├── install.sh          # 统一远程入口（子脚本也可独立运行）
├── hy2.sh              # Hysteria 2 管理
├── ss.sh               # Shadowsocks 管理
├── anytls.sh           # sing-box 原生 AnyTLS 管理
├── euservhy2.sh        # EUserv IPv6 Hysteria 2
├── CHANGELOG.md        # 更新日志
├── CONTRIBUTING.md     # 贡献与开发流程
├── README.md           # 项目说明
├── CLAUDE.md           # Claude Code 指引
├── AGENTS.md           # AI Agent 指引
├── tests/
│   ├── validate_scripts.sh # 总验证入口
│   └── validate_anytls.sh  # AnyTLS 行为测试
├── .github/workflows/
│   └── shell-checks.yml # GitHub Actions
└── docs/
    ├── ARCHITECTURE.md # 本文档
    ├── TESTING.md      # VPS 测试矩阵
    ├── RELEASE.md      # 发布与回滚流程
    └── MAINTENANCE.md  # 维护、安全与外部依赖
```
