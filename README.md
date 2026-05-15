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
| **EUserv Hysteria 2** | IPv6-only 专属 · 自动适配 · Warp 集成 | EUserv 免费德鸡专用 |

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

### EUserv 免费德鸡专用（IPv6-only）

专为 **EUserv 免费 IPv6-only VPS** 深度定制，自动处理纯 IPv6 环境下的证书、防火墙、节点生成等所有细节，并集成 Warp 一键添加 IPv4 出口。

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/everett7623/hy2/main/euservhy2.sh)
```

### EUserv 专属特性

| 特性 | 说明 |
| --- | --- |
| **NAT64 DNS 自动切换** | 安装时临时启用 NAT64 DNS 拉取 IPv4 资源，完成后自动恢复原始配置 |
| **多下载源自动降级** | 官方 CDN → 官方安装脚本 → IPv6 直连 GitHub → NAT64+GitHub → ghproxy 镜像，逐级兜底 |
| **ELF 格式预检** | 下载完成后校验二进制有效性，防止损坏文件执行导致 Segfault |
| **WARP 状态实时检测** | 主菜单每次刷新均实时探测 IPv4 可达性，装完 WARP 立即反映 |
| **节点名动态读取** | 节点名称取自服务器 `hostname`，多机管理时一目了然 |
| **ip6tables 优先** | 防火墙配置优先使用 ip6tables，确保 UDP 端口在纯 IPv6 环境下正确放行 |
| **旧版 OpenSSL 兼容** | 自签证书生成自动检测 OpenSSL 版本，Debian 10 等老系统无 `-addext` 问题 |

### 使用前提

| 条件 | 要求 |
| --- | --- |
| 系统 | Debian 10/11/12（EUserv 默认镜像） |
| 权限 | root |
| 网络 | EUserv IPv6-only VPS（全局 IPv6 地址可达） |
| 客户端访问 | 需本地支持 IPv6（国内宽带开启 IPv6 / 手机 4G·5G 可直连；无 IPv6 须先在客户端侧安装 WARP） |

> **⚠️ 纯 IPv4 客户端用户**：若本地网络无 IPv6，可在脚本中选择选项 **8** 为服务器安装 WARP 后，将节点转换为通过 WARP IPv4 中转访问——但此方案延迟较高，建议优先解决客户端 IPv6 连接问题。

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

### EUserv Hysteria 2 菜单

```
━━━ Hysteria2 管理 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  1. 安装 / 重装 Hysteria2
  2. 查看节点信息 / 链接
  3. 修改配置（端口 / 密码 / 伪装域名）
  4. 升级 Hysteria2
  5. 服务管理（启动 / 停止 / 重启）
  6. 查看运行日志
  7. 卸载 Hysteria2

  ━━━ 网络增强 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  8. WARP（F大 fscarmen 脚本）— IPv6-only 补全 IPv4
  9. 系统工具（BBR / 系统信息 / 网络测试）
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
>
> EUserv 专用脚本额外支持：纯 IPv6-only 环境 · Debian 系统优先适配

---

## 📸 运行截图

#### Hysteria 2 安装示例
<img width="1187" height="1365" alt="hy2" src="https://github.com/user-attachments/assets/1c798220-b59e-4e1f-81ce-2052d45820b9" />

#### Shadowsocks 安装示例
<img width="1186" height="1367" alt="ssdev" src="https://github.com/user-attachments/assets/f4440535-4880-48ab-bf5e-3c163817bee7" />

#### Euserv ipv6 only Hysteria 2 安装示例

<img width="701" height="625" alt="euserv hy2-install 1" src="https://github.com/user-attachments/assets/59bc7560-b09f-4aab-84fb-d32a56ce4659" />
<img width="1186" height="1735" alt="euserv hy2-install 2" src="https://github.com/user-attachments/assets/78492236-d611-4b29-8e92-29ab73ab10f6" />

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
