# CHANGELOG

所有脚本统一版本号，同步更新。

---

## v1.0.2 (2026-06-30)

**新增 AnyTLS 协议支持**

- 新增 `anytls.sh` 管理脚本，支持 AnyTLS 协议一键部署
- AnyTLS 使用 TCP 传输，适合 UDP 受限网络环境
- 支持自签证书、SNI 伪装、配置修改、升级卸载
- 集成 BBR 加速、自动更新、系统信息展示
- 集成到 `install.sh` 统一启动器（选项 4）
- 更新 `tests/validate_scripts.sh` 支持 anytls.sh 验证
- 完整的输入验证（端口、密码、域名）
- 支持 NAT 模式、IPv4/IPv6 双栈
- systemd 和 OpenRC 服务管理

---

## v1.0.1 (2026-06-11)

**兼容性与可靠性修复**

- 修复 `install.sh` 在 Debian/RHEL 系统缺少 Bash 时使用错误包管理器参数的问题
- 启动器兼容 systemd、OpenRC 和无 init 环境的服务状态检测
- 下载二进制改为临时文件校验后原子替换，失败时保留当前可用版本
- 自动更新增加架构补全、二进制校验、服务验证和失败回滚
- 修复运行中但未启用开机启动的服务不会被自动更新器重启的问题
- 增加 Hysteria 2 / Shadowsocks 端口、带宽和密码输入校验
- Shadowsocks 与 EUserv 配置修改增加服务验证和失败回滚
- 防火墙规则改为幂等写入，并补充 IPv6 与 EUserv firewalld 支持
- 修复纯 Bash URI 编码对非 ASCII 内容的错误处理
- Python URI 编码不可用时自动回退到纯 Bash 实现
- 补充多发行版所需的 CA、iproute2 和进程工具依赖
- 调整极简系统的依赖安装顺序，将可选二维码组件与核心依赖拆分
- Bash 自举在 Debian 系列先刷新 apt 索引，提升最小化镜像成功率
- 安装自动更新时主动启用 cron/crond，并验证 `crontab` 可用
- EUserv 下载使用唯一临时文件，移除会直接改写目标二进制的远程安装脚本路径
- EUserv 增加伪装域名与 SNI 校验，并支持在修改配置时更新 SNI
- EUserv 明确校验 systemd 环境，并避免重复插入 iptables 规则
- 修正 Hysteria 2 官方 ARMv7 二进制文件名映射（`arm`）
- 新增 `tests/validate_scripts.sh` 与 GitHub Actions 静态验证
- 新增贡献指南、VPS 测试矩阵、发布流程及维护/AI 接手文档
- 修复 EUserv 卸载遗漏 BBR 配置文件的问题

---

## v1.0.0 (2026-06-11)

**首次统一发布**

### hy2.sh
- 端口跳跃 (Port Hopping) 支持，防火墙范围放行
- BBR 调优、自动更新 cron、防火墙自动放行
- QR 二维码 (qrencode)、修改带宽、服务工具子菜单
- awk 块检测修改密码/带宽，备份回滚机制
- download_hy2() 双源 fallback (GitHub + 官方镜像)

### ss.sh
- IPv6 优先检测 + WARP 虚拟网卡过滤
- 双栈 VPS 支持 IPv4/IPv6 切换
- 架构支持: amd64 / arm64 / armv7 / s390x / loongarch64
- 升级功能 (备份回滚)、BBR、自动更新、QR 二维码
- 修改配置 (端口/密码/加密)、连接测试
- Shadowsocks 2022 协议支持 (blake3-aes-256-gcm)
- Clash/Surge/Loon/Quantumult X 全客户端配置输出

### euservhy2.sh
- EUserv IPv6-only VPS 一键部署 Hysteria2
- NAT64 DNS 临时切换、多级下载 fallback
- WARP/tunnel 虚拟网卡 IPv6 过滤
- bash 自举 / CRLF guard / TTY fix
- busybox 兼容 (无 grep -oP, 无 ${var,,})

### install.sh
- 统一启动器，支持 hy2 / ss / euserv 三种脚本
- 实时状态检测 (运行中/已停止/未安装 + 版本号)

### 项目结构
- dev 版本合并，hy2dev.sh / ssdev.sh 删除
- CLAUDE.md / AGENTS.md / docs/ARCHITECTURE.md
- 脚本模板骨架 (docs/ARCHITECTURE.md)
- 完善 README 快速入口、日常管理、选型、故障排查与安全说明
- 统一开发文档中的版本策略、远程启动器行为和本地验证流程
