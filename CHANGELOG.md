# CHANGELOG

所有脚本统一版本号，同步更新。

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
