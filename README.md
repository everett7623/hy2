# 🚀 Hysteria 2 & Shadowsocks 一键管理脚本

> 功能闭环 · 极低占用 · 全系统兼容 · 交互友好
> 无需域名，无需复杂配置，一键开启高速且安全的网络体验。

![GitHub release (latest by date)](https://img.shields.io/github/v/release/everett7623/hy2?color=blue&label=Latest%20Version)
![Shell Script](https://img.shields.io/badge/Language-Shell-green)
![License](https://img.shields.io/badge/License-MIT-orange)

---

## 📖 项目简介

这是一个专为 **Hysteria 2** 与 **Shadowsocks** 协议设计的 Linux 一键部署管理脚本集合，旨在将繁琐的服务器配置流程压缩到 1 分钟以内，即使没有 Linux 基础的新手也能轻松完成部署。

| 协议 | 核心优势 | 适用场景 |
| --- | --- | --- |
| **Hysteria 2** | UDP 超速 · 自签证书 · 无需域名 | 主力节点，绝大多数网络环境 |
| **Shadowsocks** | 支持 SS-2022 · musl 静态编译 · 全平台兼容 | 备用节点，IPv6 / 双栈环境尤佳 |

---

## ✨ 核心特性

- **⚡️ 一键部署**：支持 `curl | bash` 极速安装，自动识别系统包管理器，全自动穿透系统防火墙（兼容 firewalld / ufw / iptables）。
- **🪶 轻量无依赖**：彻底移除 `jq` 等外部依赖，纯 Bash 实现 URI 转义，极低配置 VPS 也能稳定运行。
- **🛠️ 终极系统兼容**：Shadowsocks 端强制采用 `musl` 静态编译，彻底免疫 CentOS 8 / Rocky 8 等老旧系统的 GLIBC 报错问题。
- **🌐 NAT 与双栈支持**：自动检测 IPv4 / IPv6 网络状态，完美支持 NAT 机器（内外端口映射）及纯 IPv6 环境。
- **🔐 Hysteria 2 免域名**：采用自签证书 + SNI 伪装 `amd.com`，自动配置 `skip-cert-verify`，零门槛开箱即用。
- **🔐 SS 双协议自由选**：安装时可选择 100% 连通率的经典 `aes-256-gcm`，或强抗主动探测的 `2022-blake3-aes-256-gcm`（自动生成 32 字节规范密钥并尝试同步系统时间）。
- **🔧 服务器工具内置**：一键开启 BBR 加速、定时自动更新（每天 03:00）、系统信息总览，开箱即用。
- **📱 全客户端节点输出**：自动生成适配 Loon / Surge / Clash Meta / Stash / Shadowrocket / v2rayN / Quantumult X 等主流客户端的完整配置代码与二维码链接。

---

## 🚀 快速开始

### Hysteria 2（主推）

适用于绝大多数网络环境，UDP 协议极速占满带宽，抗封锁能力强。

```bash
# 稳定版
bash <(curl -fsSL https://raw.githubusercontent.com/everett7623/hy2/main/hy2.sh)

# DEV 测试版（含最新功能）
bash <(curl -fsSL https://raw.githubusercontent.com/everett7623/hy2/main/hy2dev.sh)
```

- 默认端口：`18888`（支持 NAT 自定义外网端口）
- 免域名机制：SNI 伪装 `amd.com` + 自动配置 `skip-cert-verify`

### Shadowsocks（保底备用）

建议在 **IPv6 单栈**或**双栈**网络环境下使用。纯 IPv4 极易被封锁，脚本内附风险提示拦截。

```bash
# 稳定版
bash <(curl -fsSL https://raw.githubusercontent.com/everett7623/hy2/main/ss.sh)

# DEV 测试版（含升级 / 服务器工具菜单）
bash <(curl -fsSL https://raw.githubusercontent.com/everett7623/hy2/main/ssdev.sh)
```

- 默认端口：`28888`（支持 NAT 自定义外网端口）
- 加密选项：`aes-256-gcm`（经典高兼容）或 `2022-blake3-aes-256-gcm`（SS-2022 高安全）

> **⚠️ SS-2022 特别提醒**：SS-2022 协议具有严格的时间防重放机制。若配置无误但仍提示超时，请务必确保手机 / 电脑本地时间与世界标准时间分秒一致。

---

## 📋 功能菜单对照

### Hysteria 2 菜单

```
 1. 安装 Hysteria2
 2. 管理 Hysteria2    → 查看配置 / 启动 / 停止 / 重启 / 日志 / 改密码 / 改带宽
 3. 升级 Hysteria2
 4. 卸载 Hysteria2
 5. 服务器工具        → BBR / 自动更新 / 系统信息
```

### Shadowsocks 菜单

```
 1. 安装 Shadowsocks 服务
 2. 管理 Shadowsocks 配置  → 查看配置 / 启动 / 停止 / 重启 / 日志
 3. 升级 Shadowsocks 服务  （DEV 版）
 4. 卸载 Shadowsocks 服务
 5. 服务器工具              → BBR / 自动更新 / 系统信息（DEV 版）
```

---

## 📱 客户端兼容性

| 平台 | 推荐客户端 | Hysteria 2 | Shadowsocks |
| --- | --- | :---: | :---: |
| iOS | Shadowrocket / Loon / Stash | ✅ | ✅ |
| iOS | Quantumult X | ❌ 暂不支持 | ✅ |
| Android | v2rayNG / NekoBox / Surfboard | ✅ | ✅ |
| macOS / Windows | Clash Verge (Meta) / Clash Nyanpasu | ✅ | ✅ |
| Windows | v2rayN | ✅ | ✅ |

---

## 🖥️ 支持系统

| 发行版 | 版本 |
| --- | --- |
| Debian | 10 / 11 / 12+ |
| Ubuntu | 20.04 / 22.04 / 24.04+ |
| CentOS / RHEL | 7 / 8 / 9 |
| Rocky / AlmaLinux | 8 / 9 |
| Fedora | 38+ |
| Arch Linux / Manjaro | 最新滚动版 |
| Alpine Linux | 3.x |

> 支持 标准 VPS · NAT 机器 · IPv6 单栈 / 双栈 · 低配 VPS（≥ 128MB RAM）

---

## 📸 运行截图

#### Hysteria 2 安装示例
<img width="1187" height="1365" alt="hy2" src="https://github.com/user-attachments/assets/1c798220-b59e-4e1f-81ce-2052d45820b9" />

#### Shadowsocks 安装示例
<img width="1186" height="1367" alt="ssdev" src="https://github.com/user-attachments/assets/f4440535-4880-48ab-bf5e-3c163817bee7" />
---

## 🔗 关于作者

| | |
| --- | --- |
| **Author** | Jensfrank |
| **Blog** | [Seedloc 博客](https://seedloc.com) — 分享技术与生活 |
| **Website** | [VPSknow](https://vpsknow.com) — VPS 测评与推荐 |
| **Forum** | [Nodeloc 论坛](https://nodeloc.com) — 主机爱好者社区 |

---

## ⚠️ 免责声明

- 本项目仅供学习、技术研究和网络底层协议交流使用。
- 请勿将本项目用于任何违反当地法律法规的用途。
- 使用本项目产生的任何后果（包括但不限于 IP 被封锁、机器被服务商收回等）由使用者自行承担。

---

**觉得脚本好用？请点击右上角 ⭐️ Star 支持一下，这是对作者最大的鼓励！**
