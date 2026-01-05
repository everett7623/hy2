# 🚀 Hysteria2 Management Script | Hysteria2 一键管理脚本

> **功能闭环、兼容广泛、交互友好、稳定可靠**
> 无需域名、无需复杂的配置，一键开启 Hysteria 2 高速网络体验。

![GitHub release (latest by date)](https://img.shields.io/github/v/release/everett7623/hy2?color=blue&label=Latest%20Version)
![Shell Script](https://img.shields.io/badge/Language-Shell-green)
![License](https://img.shields.io/badge/License-MIT-orange)

## 📖 项目简介

这是一个专为 **Hysteria 2** 协议设计的 Linux 一键部署管理脚本。它旨在简化繁琐的服务器配置流程，即使是没有 Linux 基础的新手也能在 1 分钟内完成部署。

**核心亮点：** 采用**自签证书**模式（Self-signed），**无需购买域名**，无需进行复杂的 DNS 解析。脚本自动配置客户端所需的 `insecure` / `skip-cert-verify` 参数，开箱即用。

---

## ✨ 功能特性

* **⚡️ 极速部署**：支持 `curl | bash` 一键安装，自动处理依赖。
* **🆔 无需域名**：使用自签证书 + SNI 伪装（默认伪装 `amd.com`），降低使用门槛。
* **🛡️ 智能修复**：
    * 自动检测并修复 Windows 换行符（CRLF）导致的脚本运行错误。
    * 完美解决 `curl` 管道安装时的输入流冲突（死循环/刷屏）问题。
* **📱 全客户端兼容**：自动生成适配于 **Loon / Surge / Clash Meta / Stash / Sing-box / Shadowrocket / v2rayN** 等主流客户端的配置格式。
* **🔄 完整生命周期管理**：支持安装、服务重启、停止、查看日志、彻底卸载。
* **📦 附带 Shadowsocks 脚本**：同仓库提供高兼容性的 SS-Rust 管理脚本（支持 IPv6 检测）。

---

## 🛠️ 安装指南

### 1. Hysteria 2 (推荐)

适用于大多数网络环境，速度快，抗封锁能力强。

```bash
# 快速安装/管理
curl -sSL [https://raw.githubusercontent.com/everett7623/hy2/main/hy2.sh](https://raw.githubusercontent.com/everett7623/hy2/main/hy2.sh) | sudo bash

```

* **默认端口**：`18888`
* **默认协议**：UDP (Hysteria 2)

### 2. Shadowsocks-Rust (可选)

建议在 **IPv6** 或 **双栈** 网络环境下使用。脚本内置 IPv4 环境风险提示，防止 IP 被封。

```bash
# 安装 Shadowsocks-Rust
curl -sSL [https://raw.githubusercontent.com/everett7623/hy2/main/ss.sh](https://raw.githubusercontent.com/everett7623/hy2/main/ss.sh) | sudo bash

```

* **默认端口**：`28888`
* **默认加密**：`aes-256-gcm`

---

## 📱 客户端配置输出示例

脚本安装完成后，会自动输出适配以下软件的配置代码，直接复制即可使用：

| 平台 | 推荐客户端 | 兼容性 |
| --- | --- | --- |
| **iOS** | **Shadowrocket** / **Loon** / **Stash** / **Sing-box** | ✅ 完美支持 |
| **Android** | **v2rayNG** / **NekoBox** / **Surfboard** / **Sing-box** | ✅ 完美支持 |
| **macOS** | **Surge Mac** / **Clash Verge** / **Sing-box** | ✅ 完美支持 |
| **Windows** | **v2rayN** / **Clash Verge (Meta核心)** | ✅ 完美支持 |

> **注意**：由于使用自签证书，所有客户端配置均已默认开启 `允许不安全连接` (Allow Insecure / Skip Cert Verify)。

---

## 📸 运行截图

![ScreenShot_2026-01-05_161441_728.png](https://img.y8o.de/i/2026/01/05/695b72e8e30fc.png)

---

## 🔗 关于作者 & 友情链接

* **Author**: Jensfrank
* **Blog**: [Seeloc 博客](https://seedloc.com) - 分享技术与生活
* **Website**: [VPSknow](https://vpsknow.com) - VPS 测评与推荐
* **Forum**: [Nodeloc 论坛](https://nodeloc.com) - 主机爱好者社区

---

## ⚠️ 免责声明

* 本项目仅供学习、技术研究和交流使用。
* 请勿将本项目用于任何违反当地法律法规的用途。
* 使用本项目产生的任何后果由使用者自行承担。

---

**如果觉得脚本好用，请点击右上角的 ⭐️ Star 支持一下！**
