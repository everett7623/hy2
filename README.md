# 🚀 Hysteria 2 & Shadowsocks 一键管理脚本

> **功能闭环、极低占用、全系统兼容、交互友好**
> 无需域名、无需复杂的配置，一键开启高速且安全的网络体验。

![GitHub release (latest by date)](https://img.shields.io/github/v/release/everett7623/hy2?color=blue&label=Latest%20Version)
![Shell Script](https://img.shields.io/badge/Language-Shell-green)
![License](https://img.shields.io/badge/License-MIT-orange)

## 📖 项目简介

这是一个专为 **Hysteria 2** 与 **Shadowsocks** 协议设计的 Linux 一键部署管理脚本集合。它旨在简化繁琐的服务器配置流程，即使是没有 Linux 基础的新手也能在 1 分钟内完成极速部署。

**核心亮点：** 
- **Hy2 端**：采用**自签证书**模式，**无需购买域名**与解析，自动配置 `insecure` 参数，零门槛开箱即用。
- **SS 端**：支持经典协议与强抗封锁的 **Shadowsocks 2022** 协议切换，内置全自动防火墙穿透与终极系统兼容机制。

---

## ✨ 核心特性

* **⚡️ 极速部署与智能防护**：支持 `curl | bash` 一键安装，智能探测系统包管理器，并**全自动砸开系统防火墙**（完美兼容 firewalld / ufw / iptables）。
* **🪶 极低资源占用**：彻底移除 `jq` 等臃肿的外部依赖包，采用纯 Bash 实现复杂的 URI 转义，再老的低配 VPS 也能丝滑运行。
* **🛠️ 终极系统兼容 (SS 端)**：强制采用 `musl` 静态编译核心，彻底免疫 CentOS 8 / Rocky 8 等老旧系统上烦人的 `GLIBC` 版本过低报错问题。
* **🌐 NAT 与双栈支持**：自动检测本机 IPv4 / IPv6 状态。完美支持 NAT 服务器（内外端口映射）以及纯 IPv6 (IPv6 Only) 环境。
* **🔐 SS 双协议自由选**：安装时可自由选择 100% 连通率的经典 `aes-256-gcm`，或强抗主动探测的 `2022-blake3-aes-256-gcm`（脚本全自动生成 32 字节规范密钥并尝试同步系统时间）。
* **📱 全客户端节点输出**：自动生成适配于 **Loon / Surge / Clash Meta / Stash / Sing-box / Shadowrocket / v2rayN / Quantumult X** 等主流客户端的完整配置代码与二维码。

---

## 🚀 安装指南

### 1. Hysteria 2 (主推协议)

适用于绝大多数网络环境，UDP 协议极速抢占带宽，抗封锁能力强。

#### 快速安装/管理 Hysteria 2
```bash
# 快速安装/管理 Hysteria 2
bash <(curl -fsSL https://raw.githubusercontent.com/everett7623/hy2/main/hy2.sh)
````

  * **默认端口**：`18888` (支持 NAT 自定义外网端口)
  * **免域名机制**：默认 SNI 伪装 `amd.com` + 自动配置 `skip-cert-verify` 参数。

### 2\. Shadowsocks 2022 / 经典版 (保底推荐)

建议在 **IPv6 单栈** 或 **双栈** 网络环境下使用作为强力备用节点。纯 IPv4 极易被墙，脚本内附强制风险拦截。

#### 快速安装/管理 Shadowsocks 
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/everett7623/hy2/main/ss.sh)
```

  * **默认端口**：`28888` (支持 NAT 自定义外网端口)
  * **加密选项**：支持自选 `aes-256-gcm` (经典高兼容) 或 `2022-blake3-aes-256-gcm` (SS-2022 高安全)。

> **⚠️ 关于 SS-2022 的特别提醒**：SS-2022 协议拥有极其严格的“时间防重放”机制。如果配置全对却提示“超时连不上”，请务必确保您的**手机/电脑本地时间**与**世界标准时间**分秒不差！

-----

## 📱 客户端配置输出示例

脚本安装完成后，会自动在终端输出适配以下软件的配置代码，直接复制或扫码即可使用：

| 平台 | 推荐客户端 | Hysteria 2 支持 | Shadowsocks 支持 |
| --- | --- | :---: | :---: |
| **iOS** | **Shadowrocket / Loon / Stash** | ✅ 完美支持 | ✅ 完美支持 |
| **iOS** | **Quantumult X** | ❌ 暂不支持 | ✅ 完美支持 |
| **Android** | **v2rayNG / NekoBox / Surfboard** | ✅ 完美支持 | ✅ 完美支持 |
| **mac/PC** | **Clash Verge (Meta) / Sing-box** | ✅ 完美支持 | ✅ 完美支持 |
| **Windows** | **v2rayN** | ✅ 完美支持 | ✅ 完美支持 |

-----

## 📸 运行截图

<img width="1521" height="1405" alt="hy2" src="https://github.com/user-attachments/assets/9ee30ebb-9ce4-4596-823a-2270b1d49d29" />
<img width="1486" height="1482" alt="ss2022" src="https://github.com/user-attachments/assets/3ea42eb9-d920-473b-bd20-ccc1f43218f4" />

-----

## 🔗 关于作者 & 友情链接

  * **Author**: Jensfrank
  * **Blog**: [Seedloc 博客](https://seedloc.com) - 分享技术与生活
  * **Website**: [VPSknow](https://vpsknow.com) - VPS 测评与推荐
  * **Forum**: [Nodeloc 论坛](https://nodeloc.com) - 主机爱好者社区

-----

## ⚠️ 免责声明

  * 本项目仅供学习、技术研究和网络底层协议交流使用。
  * 请勿将本项目用于任何违反当地法律法规的用途。
  * 使用本项目产生的任何后果（包括但不限于 IP 被封锁、机器被服务商收回等）由使用者自行承担。

-----

**如果觉得脚本好用，帮到了您，请点击右上角的 ⭐️ Star 支持一下！**
