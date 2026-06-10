# CHANGELOG

## 2026-06-11

### hy2.sh v2.3.7
- **合并**: dev 版本合并入主版本，删除 hy2dev.sh
- **新增**: 端口跳跃 (Port Hopping) 支持，防火墙自动放行范围端口
- **新增**: WARP/隧道 IPv4 过滤（纯 IPv6 + WARP 场景不误识别）
- **修复**: change_bandwidth() 写入失败后缺少 return 导致元数据不一致
- **修复**: download_hy2() 删除旧二进制前无备份，升级失败无法回滚
- **修复**: change_password() 缺少 trap 临时文件清理
- **修复**: get_latest_version() 错误信息增加 GitHub API 限频提示
- **已有**: BBR 调优 / 自动更新 cron / 防火墙 / 修改带宽 / QR 二维码 / 服务工具

### ss.sh v3.2.3
- **合并**: dev 版本合并入主版本，删除 ssdev.sh
- **新增**: IPv4/IPv6 切换（双栈时可选查看）默认 IPv6 优先
- **新增**: WARP/隧道 IPv4 过滤（纯 IPv6 + WARP 场景仅输出 IPv6）
- **新增**: 检测顺序改为 IPv6 优先
- **新增**: 架构支持 armv7 / s390x / loongarch64
- **修复**: download_ss() fallback mv 安装空文件 → 改用 mktemp -d
- **修复**: download_ss() 删除旧二进制前无备份，升级失败无法回滚
- **修复**: service_restart() 改用 systemd/openrc 原生 restart
- **修复**: Clash YAML 输出单引号统一
- **修复**: cron 安装 CentOS 7 兼容（dnf 失败回落 yum）
- **已有**: BBR / 自动更新 / QR / 修改配置 / 连接测试 / 服务工具 / upgrade

### euservhy2.sh v2.0.3
- **修复**: 新增 bash 自举/CRLF guard/TTY fix（之前缺失）
- **修复**: _get_real_ipv6() 排除 WARP/tunnel 虚拟网卡
- **修复**: do_upgrade() trap 被 enable_nat64_dns() 覆盖
- **修复**: __upgrade_recover guard 改用 -s（非空）替代 -f（存在）
- **修复**: 所有 grep -oP 替换为 awk/grep -oE（busybox 兼容）
- **修复**: 所有 ${var,,} 替换为 tr/双条件（bash 3.x 兼容）

### install.sh
- **更新**: URL 指向 hy2.sh / ss.sh（不再指向 dev 版本）
- **修复**: IPv6 提取排除 WARP 网卡

### 项目结构
- **合并**: hy2dev.sh / ssdev.sh 删除，dev 功能全部合入主版本
- **文档**: 更新 CLAUDE.md / AGENTS.md / README.md
- **新增**: CHANGELOG.md

---

## 历史版本

### v2.3.6 (2026-06-10)
- hy2.sh: 下载 URL 修复（完整 tag 含 app/ 前缀），升级对比用剥离版本号
- hy2dev.sh: 密码自动生成改用 dd 替代 head -c（POSIX 兼容）
- hy2dev.sh: change_bandwidth() 用 awk 重写 bandwidth 块
- 分享链接 insecure=1（自签证书场景）

### v2.3.4 (2026-05-21)
- hy2.sh / hy2dev.sh: 稳定版与 dev 版同步修复
- 防火墙自动放行端口（ufw / firewalld / iptables）
- 一键开启 BBR 拥塞控制
- 定时自动更新（cron 每天凌晨 3 点）
- 服务工具子菜单（BBR / 自动更新 / 防火墙 / 系统信息）

### v3.2.0 (2026-05-14)
- ssdev.sh: 合并升级功能（保留配置，仅替换二进制）
- ssdev.sh: 合并服务工具子菜单
- ssdev.sh: 二维码终端内直接渲染（qrencode -t ANSIUTF8）
- ssdev.sh: 修改配置（端口 / 密码 / 加密方式）
- ssdev.sh: 连接测试（服务器本机端口监听验证）
- ssdev.sh: uri_encode() 优先 python3，降级纯 bash

### v3.1.2 (2026-06-10)
- ss.sh: service_restart() 改用原生 restart
- ss.sh: NAT 检测增加 command -v ip 守卫
- ss.sh: cron 安装 CentOS 7 兼容

### v2.0.1 (2026-05-14)
- euservhy2.sh: 初始版本（EUserv IPv6-only 支持）
