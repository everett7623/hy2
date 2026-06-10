# CHANGELOG

格式遵循 [语义化版本](https://semver.org/lang/zh-CN/)：`MAJOR.MINOR.PATCH`

---

## 2026-06-11

### hy2.sh — v2.4.0
**新增**
- 端口跳跃 (Port Hopping)：服务器监听端口范围，防火墙自动放行
- dev 版本功能合并：BBR 调优、自动更新 cron、防火墙、修改带宽、QR 二维码、服务工具

**修复**
- change_bandwidth() 写入失败后缺少 return，元数据不一致
- download_hy2() 删除旧二进制前无备份，升级失败无法回滚
- change_password() 缺少 trap 清理临时文件
- get_latest_version() 错误信息增加 GitHub API 限频提示

### ss.sh — v3.3.0
**新增**
- IPv4/IPv6 切换（双栈可选查看），默认 IPv6 优先
- WARP/隧道 IPv4 过滤（纯 IPv6 + WARP 场景仅输出真实 IPv6）
- 架构支持：armv7 / s390x / loongarch64
- dev 版本功能合并：升级、BBR、自动更新、QR、修改配置、连接测试

**修复**
- download_ss() fallback mv 安装空文件 → 改用 `mktemp -d`
- download_ss() 删除旧二进制前无备份，升级失败无法回滚
- service_restart() 改用 systemd/openrc 原生 restart
- Clash YAML 输出统一单引号格式
- cron 安装 CentOS 7 兼容（dnf 失败回落 yum）

### euservhy2.sh — v2.0.4
**修复**
- 新增 bash 自举 / CRLF guard / TTY fix（与 hy2/ss 对齐）
- `_get_real_ipv6()` 排除 WARP/tunnel 虚拟网卡
- do_upgrade() trap 被 enable_nat64_dns() 覆盖
- `__upgrade_recover` guard 改用 `-s`（非空检查）替代 `-f`（存在检查）
- 所有 `grep -oP` → awk/grep -oE（busybox 兼容）
- 所有 `${var,,}` → tr/双条件（bash 3.x 兼容）

### install.sh — v2.0.1
**变更**
- URL 指向 hy2.sh / ss.sh（不再指向 dev 版本）
- IPv6 提取排除 WARP 网卡

### 项目结构
- hy2dev.sh / ssdev.sh 删除，功能合入 hy2.sh / ss.sh
- 新增 CHANGELOG.md、docs/ARCHITECTURE.md
- 更新 CLAUDE.md / AGENTS.md / README.md

---

## 2026-06-10

### hy2.sh — v2.3.6
- 下载 URL 使用完整 tag（含 `app/` 前缀），版本对比使用剥离后格式
- gen_password() 改用 dd 替代 head -c（POSIX 兼容）
- change_bandwidth() 用 awk 重写 bandwidth 块（块检测替换）
- 分享链接 insecure=1（自签证书场景）
- NAT 检测增加 `command -v ip` 守卫

### ss.sh — v3.1.2
- service_restart() 改用原生 restart
- NAT 检测增加 `command -v ip` 守卫
- cron 安装 CentOS 7 兼容（dnf 失败回落 yum）

---

## 2026-05-21

### hy2.sh / hy2dev.sh — v2.3.4
- 防火墙自动放行端口（ufw / firewalld / iptables）
- 一键开启 BBR 拥塞控制（支持 BBRv3 检测）
- 定时自动更新（cron 每天 03:00）
- 服务工具子菜单（BBR / 自动更新 / 防火墙 / 系统信息）
- 管理菜单增加修改带宽选项、订阅增加二维码、日志提升至 50 行

---

## 2026-05-14

### ssdev.sh — v3.2.0
- 合并升级功能（保留配置，仅替换二进制）
- 服务工具子菜单（BBR / 自动更新 / 系统信息）
- 终端二维码渲染（qrencode -t ANSIUTF8）
- 修改配置（端口 / 密码 / 加密方式）
- 连接测试（服务器本机端口监听验证）
- uri_encode() 优先 python3，降级纯 bash

### euservhy2.sh — v2.0.1
- 初始版本（EUserv IPv6-only VPS 一键部署 Hysteria2）
