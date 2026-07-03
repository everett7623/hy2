# 🚀 Sing-box Multi-Protocol Tools

> 功能闭环 · 极低占用 · 全系统兼容 · 交互友好
> 无需域名，无需复杂配置，一键开启高速且安全的网络体验。

![GitHub release (latest by date)](https://img.shields.io/github/v/release/everett7623/hy2?color=blue&label=Latest%20Version)
![Shell Script](https://img.shields.io/badge/Language-Shell-green)
![License](https://img.shields.io/badge/License-MIT-orange)

> 当前版本：v2.0.1（2026-07-03）
> 本次更新：优化四协议 Sing-box / SFA TUN JSON 导出，日志级别调整为 info，并启用 DNS 缓存以降低重复解析和日志写入造成的速度损耗。

---

## 📖 项目简介

这是一个基于 **sing-box** 和主流代理协议的 Linux VPS 一键安装、管理、导出、二维码、诊断、备份与恢复工具集。

| 协议 | 核心优势 | 适用场景 |
| --- | --- | --- |
| **Hysteria 2** | UDP 超速 · 自签证书 · 无需域名 | 主力节点，绝大多数网络环境 |
| **Shadowsocks** | 支持 SS-2022 · musl 静态编译 · 全平台兼容 | 备用节点，IPv6 / 双栈环境尤佳 |
| **AnyTLS** | sing-box 原生入站 · TCP/TLS · 自签证书 | 需要 TCP/TLS 传输的轻量节点 |
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
- **📱 全客户端节点输出**：自动生成适配 Loon / Surfboard / Clash Meta / Stash / Shadowrocket / v2rayN / Quantumult X 等主流客户端的完整配置代码与二维码链接。

---

## 🚀 快速开始

### 统一入口（推荐）

统一入口会检测当前网络和服务状态，并提供 AnyTLS、Hysteria 2、Shadowsocks 与 EUserv IPv6 专用脚本的分层管理菜单：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/everett7623/hy2/main/install.sh)
```

> `install.sh` 是远程启动器。选择菜单项后，它会再次从 GitHub `main` 分支下载对应脚本，因此需要 VPS 能访问 `raw.githubusercontent.com`。

### Hysteria 2（主推）

适用于绝大多数网络环境，UDP 协议极速占满带宽，抗封锁能力强。

```bash
# 稳定版
bash <(curl -fsSL https://raw.githubusercontent.com/everett7623/hy2/main/hy2.sh)
```

- 默认端口：`18888`（支持 NAT 自定义外网端口）
- 免域名机制：SNI 伪装 `amd.com` + 自动配置 `skip-cert-verify`

### Shadowsocks（保底备用）

建议在 **IPv6 单栈**或**双栈**网络环境下使用。纯 IPv4 极易被封锁，脚本内附风险提示拦截。

```bash
# 稳定版
bash <(curl -fsSL https://raw.githubusercontent.com/everett7623/hy2/main/ss.sh)
```

- 默认端口：`28888`（支持 NAT 自定义外网端口）
- 加密选项：`aes-256-gcm`（经典高兼容）或 `2022-blake3-aes-256-gcm`（SS-2022 高安全）

> **⚠️ SS-2022 特别提醒**：SS-2022 协议具有严格的时间防重放机制。若配置无误但仍提示超时，请务必确保手机 / 电脑本地时间与世界标准时间分秒一致。

### AnyTLS（sing-box 原生入站）

脚本下载 sing-box 稳定版，通过原生 AnyTLS inbound 提供服务；Shell 负责生成 JSON、自签证书、服务 wrapper 和分享链接，运行时不依赖 Python。

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/everett7623/hy2/main/anytls.sh)
```

- 默认端口：`38888`
- 支持架构：Linux `amd64` / `arm64` / `armv7` / `386` / `s390x`
- 支持环境：systemd、OpenRC、无 init；IPv4、IPv6、双栈
- 内置配置/证书/监听诊断，重装和升级失败自动回滚，并安全保留共享 sing-box 配置
- 输出 URI、Throne、Mihomo/Clash、Loon、Surfboard、Shadowrocket/Quantumult X、完整 Sing-box/SFA TUN JSON 配置与二维码

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

## 🔄 日常管理

重新运行对应脚本即可进入管理菜单，不会自动覆盖现有配置：

```bash
# Hysteria 2
bash <(curl -fsSL https://raw.githubusercontent.com/everett7623/hy2/main/hy2.sh)

# Shadowsocks
bash <(curl -fsSL https://raw.githubusercontent.com/everett7623/hy2/main/ss.sh)

# AnyTLS
bash <(curl -fsSL https://raw.githubusercontent.com/everett7623/hy2/main/anytls.sh)

# EUserv IPv6 专用 Hysteria 2
bash <(curl -fsSL https://raw.githubusercontent.com/everett7623/hy2/main/euservhy2.sh)
```

管理菜单提供升级、修改配置、服务启停、查看日志和卸载等功能。升级二进制时脚本会备份旧版本，启动失败则尝试回滚。

自动更新默认不会开启，需要在“服务器工具”中手动启用；启用后由 cron 每天 `03:00` 检查上游版本。

---

## 📋 功能菜单对照

### Hysteria 2 菜单

```
 1. 安装 Hysteria2
 2. 管理 Hysteria2
 3. 升级 Hysteria2
 4. 卸载 Hysteria2
 5. 服务器工具  (BBR / 自动更新 / 系统信息)
```

### Shadowsocks 菜单

```
 1. 安装 Shadowsocks
 2. 管理 Shadowsocks
 3. 升级 Shadowsocks
 4. 卸载 Shadowsocks
 5. 服务器工具  (BBR / 自动更新 / 系统信息)
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

| 平台 | 推荐客户端 | Hysteria 2 | Shadowsocks | AnyTLS |
| --- | --- | :---: | :---: | :---: |
| iOS | Shadowrocket / Loon / Stash | ✅ | ✅ | ✅ |
| iOS | Quantumult X | ❌ 暂不支持 | ✅ | ❌ 暂不支持 |
| Android | v2rayNG / NekoBox / Surfboard | ✅ | ✅ | ✅ |
| Android / 桌面 | Sing-box / SFA / SFM / SFI | ✅ | ✅ | ✅ |
| macOS / Windows | Clash Verge (Meta) / Clash Nyanpasu | ✅ | ✅ | ✅ |
| Windows | v2rayN | ✅ | ✅ | 视客户端版本 |

### Sing-box 输出说明

脚本输出的 Sing-box 内容是完整 TUN 客户端配置，可保存为 `config.json` 或直接导入 Sing-box / SFA / SFM / SFI 等兼容客户端。

配置内置 TUN 入站、DNS 代理解析、DNS 劫持、私网直连和 UDP 443/853 拒绝规则；Sing-box 内部出站 `tag`、DNS `detour` 与 `route.final` 使用固定 ASCII 名称（`hysteria2` / `shadowsocks` / `anytls`），避免节点展示名里的 emoji、隐藏字符或复制编码问题破坏 JSON。

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

## 🧭 如何选择

| 场景 | 建议 |
| --- | --- |
| 普通 IPv4 / 双栈 VPS | 优先使用 Hysteria 2 |
| NAT VPS | 使用 Hysteria 2 或 Shadowsocks，并按提示填写外网映射端口 |
| 纯 IPv6 VPS | Hysteria 2 与 Shadowsocks 均可，客户端必须具备 IPv6 可达性 |
| EUserv 免费 IPv6-only VPS | 使用 `euservhy2.sh` |
| UDP 被限制的网络 | 尝试 Shadowsocks；Hysteria 2 依赖 UDP |
| 需要 SS-2022 | 使用 `ss.sh`，并确保服务端和客户端时间准确 |

---

## 🛠️ 常见问题

### 执行后无法输入

请使用文档中的 `bash <(curl ...)` 命令，不要使用 `curl ... | sh`。脚本包含 TTY 修复，但交互式菜单仍要求系统存在 `/dev/tty`。

### 下载失败或 GitHub API 限频

确认 VPS 的 DNS、系统时间及 GitHub 连通性：

```bash
curl -I https://raw.githubusercontent.com
curl -I https://api.github.com
date
```

EUserv 脚本会自动尝试 IPv6、NAT64 和镜像等多级下载方式；普通脚本下载失败时，请先解决 VPS 到 GitHub 的网络问题。

### 服务已安装但无法连接

1. 检查云服务商安全组是否放行对应 UDP 端口。
2. 检查脚本菜单中的服务状态和运行日志。
3. NAT VPS 需确认外网端口映射到脚本配置的内网端口。
4. Hysteria 2 端口跳跃需要放行整个 UDP 端口范围。
5. SS-2022 超时优先检查服务端与客户端时钟。

### 本地修改为什么没有生效

`install.sh` 始终下载 GitHub `main` 分支的远程脚本，不会调用当前目录中的 `hy2.sh`、`ss.sh`、`anytls.sh` 或 `euservhy2.sh`。开发调试时应直接运行本地文件：

```bash
bash hy2.sh
```

---

## 🔒 安全说明

- 建议先下载并审阅脚本，再以 root 权限运行。
- 节点链接和二维码包含连接凭据，请勿公开分享。
- 卸载前请自行备份需要保留的配置；卸载功能会删除对应服务、配置和自动更新任务。
- 本项目安装的是上游最新版本，未使用锁文件固定 Hysteria 2、Shadowsocks-Rust 或 sing-box 版本。

---

## 📂 项目结构

| 文件 | 用途 |
| --- | --- |
| `install.sh` | 远程统一入口，从 GitHub `main` 下载并执行子脚本 |
| `hy2.sh` | Hysteria 2 安装与管理 |
| `ss.sh` | Shadowsocks-Rust 安装与管理 |
| `anytls.sh` | 基于 sing-box 原生入站的 AnyTLS 安装与管理 |
| `euservhy2.sh` | EUserv IPv6-only 专用 Hysteria 2 脚本 |
| `tests/validate_scripts.sh` | Bash 语法、版本、换行、兼容规则及自动更新脚本检查 |
| `tests/validate_anytls.sh` | AnyTLS 输入、下载 URL、配置、URI、服务文件与 ELF 行为测试 |
| `docs/ARCHITECTURE.md` | 代码结构、兼容性约束和开发注意事项 |
| `CHANGELOG.md` | 项目版本变更记录 |

---

## 📚 开发文档

| 文档 | 适用对象 |
| --- | --- |
| [CONTRIBUTING.md](CONTRIBUTING.md) | 贡献者的开发流程、修改原则和 PR 清单 |
| [AGENTS.md](AGENTS.md) | Codex 等通用 AI Agent 的仓库约束 |
| [CLAUDE.md](CLAUDE.md) | Claude Code 的项目上下文和维护约束 |
| [架构说明](docs/ARCHITECTURE.md) | 脚本边界、执行模型和代码模板 |
| [测试指南](docs/TESTING.md) | 静态验证、VPS 矩阵和故障注入 |
| [发布流程](docs/RELEASE.md) | 版本同步、验收、发布和紧急回滚 |
| [维护说明](docs/MAINTENANCE.md) | 外部依赖、安全边界、已知限制和 AI 接手协议 |

新开发者或 AI 工具建议按以下顺序阅读：

```text
AGENTS.md / CLAUDE.md
        ↓
docs/ARCHITECTURE.md
        ↓
CONTRIBUTING.md
        ↓
docs/TESTING.md
        ↓
docs/RELEASE.md
```

---

## 📸 运行截图

#### Hysteria 2 安装示例
<img width="1187" height="1365" alt="hysteria2 install" src="https://github.com/user-attachments/assets/1c798220-b59e-4e1f-81ce-2052d45820b9" />

#### Shadowsocks 安装示例
<img width="1186" height="1367" alt="ssdev" src="https://github.com/user-attachments/assets/f4440535-4880-48ab-bf5e-3c163817bee7" />

#### Euserv ipv6 only Hysteria 2 安装示例

<img width="701" height="625" alt="euserv hysteria2 install 1" src="https://github.com/user-attachments/assets/59bc7560-b09f-4aab-84fb-d32a56ce4659" />
<img width="1186" height="1735" alt="euserv hysteria2 install 2" src="https://github.com/user-attachments/assets/78492236-d611-4b29-8e92-29ab73ab10f6" />

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
