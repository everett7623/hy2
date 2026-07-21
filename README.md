# Sing-box Multi-Protocol Tools

面向 Linux VPS 的多协议部署与管理脚本，统一管理 VLESS + REALITY + Vision、AnyTLS、Hysteria 2、Shadowsocks-Rust 和 EUserv IPv6-only Hysteria 2。

[![GitHub release](https://img.shields.io/github/v/release/everett7623/hy2?color=blue&label=Latest%20Version)](https://github.com/everett7623/hy2/releases)
[![Shell Script](https://img.shields.io/badge/Language-Shell-green)](https://github.com/everett7623/hy2)
[![License](https://img.shields.io/badge/License-MIT-orange)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/everett7623/hy2?style=flat&color=yellow)](https://github.com/everett7623/hy2/stargazers)
[![Last commit](https://img.shields.io/github/last-commit/everett7623/hy2?color=purple)](https://github.com/everett7623/hy2/commits/main)

> 当前版本：v2.0.21（2026-07-21） · 本次更新：将 VLESS 恢复到上一稳定行为基线，并重构 README 信息架构。

## 目录

- [核心能力](#核心能力)
- [快速开始](#快速开始)
- [协议选择](#协议选择)
- [客户端导出](#客户端导出)
- [系统与网络支持](#系统与网络支持)
- [管理与升级](#管理与升级)
- [常见问题](#常见问题)
- [开发与维护](#开发与维护)

## 核心能力

| 能力 | 说明 |
| --- | --- |
| 统一入口 | 一个 `install.sh` 管理五种协议方案，首次运行后可使用 `sb` 快捷命令 |
| 自动检测 | 识别发行版、CPU 架构、systemd/OpenRC、IPv4/IPv6、NAT 与防火墙环境 |
| 安全部署 | 下载校验、临时文件、原子替换、配置备份、服务失败回滚 |
| 节点导出 | 按协议输出 URI、Mihomo、Surfboard、Shadowrocket、Loon、Quantumult X 与二维码 |
| 服务管理 | 安装、重装、查看状态、启停、重启、日志、修改配置、升级和卸载 |
| 共享核心 | AnyTLS 与 VLESS 安全共用 sing-box，升级前检查全部现存配置 |
| 系统工具 | 网络诊断、手动备份/恢复，以及按需启用标准 `bbr + fq` |

## 快速开始

### 安装前确认

- 脚本需要 `root` 权限，会写入 `/etc`、systemd/OpenRC、防火墙、cron 和系统网络配置。
- 建议先在可销毁 VPS 上测试，并在云服务商控制台放行对应端口。
- 交互运行请使用 `bash <(curl ...)`，不要使用 `curl ... | sh`。
- VPS 需要能够访问 `raw.githubusercontent.com` 和 `api.github.com`。

如需先审阅入口脚本：

```bash
curl -fsSL https://raw.githubusercontent.com/everett7623/hy2/main/install.sh -o install.sh
less install.sh
bash install.sh
```

### 推荐安装命令

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/everett7623/hy2/main/install.sh)
```

首次运行会安装统一快捷命令，之后直接执行：

```bash
sb
```

统一入口提供两组功能：

| 分组 | 功能 |
| --- | --- |
| 部署与分享 | 安装/重装、节点信息、客户端配置、二维码 |
| 运维与安全 | 服务管理、系统检测/BBR、备份/恢复、更新/升级、卸载/清理 |

<details>
<summary>独立运行协议脚本</summary>

```bash
# VLESS + REALITY + Vision
bash <(curl -fsSL https://raw.githubusercontent.com/everett7623/hy2/main/vless.sh)

# AnyTLS
bash <(curl -fsSL https://raw.githubusercontent.com/everett7623/hy2/main/anytls.sh)

# Hysteria 2
bash <(curl -fsSL https://raw.githubusercontent.com/everett7623/hy2/main/hy2.sh)

# Shadowsocks-Rust
bash <(curl -fsSL https://raw.githubusercontent.com/everett7623/hy2/main/ss.sh)

# EUserv IPv6-only Hysteria 2
bash <(curl -fsSL https://raw.githubusercontent.com/everett7623/hy2/main/euservhy2.sh)
```

</details>

## 协议选择

| 协议 | 适合场景 | 默认端口 | 关键说明 |
| --- | --- | --- | --- |
| VLESS REALITY | 需要 TCP、REALITY 与 XTLS Vision | 随机 `10000-65535/TCP` | 自动生成 UUID、REALITY 密钥与 short ID |
| AnyTLS | 需要轻量 TCP/TLS 传输 | 随机 `10000-65535/TCP` | 支持自签、已有域名证书和 sing-box 1.14+ ACME |
| Hysteria 2 | 大多数 IPv4/双栈 VPS，偏重 UDP 性能 | 随机 `10000-65535/UDP` | 支持单端口、端口跳跃和 NAT 外部端口 |
| Shadowsocks | 备用节点、IPv6/双栈环境 | 随机 `10000-65535/TCP+UDP` | 支持经典 AEAD 与 SS-2022；SS-2022 要求准确系统时间 |
| EUserv HY2 | EUserv IPv6-only VPS | 自定义 | 独立处理 NAT64 DNS、WARP 与纯 IPv6 下载回退 |

安装时生成的端口只是交互默认值，用户输入和 NAT 服务商的外部端口映射始终优先。

### VLESS REALITY 目标策略

脚本会从 Microsoft、Apple、Amazon、AMD、Mozilla、NVIDIA、Samsung 和 Cloudflare 中随机选择首选目标，再从当前 VPS 并行验证 HTTPS/TLS 可达性并使用首个可用目标。

REALITY 目标只参与握手伪装，不承载客户端后续下载流量。用户可以在安装或配置修改时手动指定其他有效域名与端口。

## 客户端导出

| 客户端/平台 | Hysteria 2 | Shadowsocks | AnyTLS | VLESS REALITY |
| --- | :---: | :---: | :---: | :---: |
| Mihomo / Clash Meta | ✅ | ✅ | ✅ | ✅ |
| Shadowrocket | ✅ | ✅ | ✅ | ✅ URI |
| Loon | ✅ | ✅ | ✅ | ✅ |
| Surfboard | ✅ | ✅ | ✅ | 暂无已确认格式 |
| Quantumult X | 暂不推荐 | ✅ | 暂不推荐 | ✅ |
| v2rayN / NekoBox | ✅ | ✅ | 视客户端支持 | ✅ URI |
| Stash | ✅ | ✅ | 视客户端支持 | 视客户端版本 |

“✅”表示脚本提供对应格式或兼容 URI，不代表所有历史客户端版本均支持。升级客户端后仍无法导入时，优先使用 URI 或 Mihomo 配置，并核对协议、UUID/密码、SNI、公钥、short ID、端口和传输类型。

当前保留的导出入口包括 URI、Mihomo/Clash、Surfboard、Shadowrocket、Loon、Quantumult X 和二维码；具体可用格式取决于协议。Throne 与 Sing-box/SFA 客户端 JSON 导出暂未提供。

## 系统与网络支持

| 系统 | 支持范围 |
| --- | --- |
| Debian | 10 / 11 / 12+ |
| Ubuntu | 20.04 / 22.04 / 24.04+ |
| CentOS / RHEL | 7 / 8 / 9 |
| Rocky / AlmaLinux | 8 / 9 |
| Fedora | 38+ |
| Arch / Manjaro | 滚动版本 |
| Alpine Linux | 3.x，使用 OpenRC |

支持标准 IPv4、双栈、IPv6-only 和 NAT VPS。常见上游架构包括 `amd64`、`arm64`、`armv7`、`386` 与 `s390x`；实际可用性取决于对应协议上游是否发布该架构的二进制文件。

## 管理与升级

### 常用动作

统一入口会向协议脚本传递 `install`、`info`、`manage`、`upgrade`、`uninstall` 等动作。VLESS 还提供只读诊断入口：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/everett7623/hy2/main/vless.sh) diagnose
```

### 重要边界

- 安装、升级和卸载不会自动创建 VPS 配置归档；如有需要，请先在“备份/恢复”中手动备份。
- BBR 默认只显示状态，不会随协议安装自动开启；启用标准 `bbr + fq` 属于用户主动操作。
- AnyTLS 与 VLESS 共用 `/usr/local/bin/sing-box`，替换核心前会检查 `/etc/sing-box/*.json`。
- `sb` 优先获取 GitHub `main` 的最新入口，远端失败时才尝试使用本地缓存。
- 本地修改不会被远程 `install.sh` 使用；开发测试应直接运行本地子脚本。

## 常见问题

### 运行后无法输入

使用 `bash <(curl -fsSL URL)`。交互菜单依赖 `/dev/tty`，`curl URL | sh` 不能保证正确工作。

### GitHub 下载失败或仍显示旧版本

先检查网络、DNS 和系统时间：

```bash
curl -I https://raw.githubusercontent.com
curl -I https://api.github.com
date
```

刚发布后可临时绕过 GitHub raw 边缘缓存：

```bash
bash <(curl -fsSL -H 'Cache-Control: no-cache' "https://raw.githubusercontent.com/everett7623/hy2/main/install.sh?nocache=$(date +%s)")
```

### 服务已安装但客户端无法连接

按以下顺序检查：

1. 脚本菜单中的服务状态、日志和监听端口。
2. 云安全组以及 VPS 本机防火墙是否放行正确的 TCP/UDP 端口。
3. NAT 外部端口是否映射到脚本监听端口。
4. 节点地址是否误用了 WARP 出口或不可达 IPv6。
5. SS-2022 客户端与服务端时间是否准确。
6. VLESS 的 UUID、SNI、REALITY 公钥、short ID 和 `xtls-rprx-vision` 是否一致。
7. REALITY 目标是否能从 VPS 正常访问。

### VLESS 能连接但速度慢

VLESS 诊断会检查 REALITY 目标、Cloudflare 下载探针和当前 TCP 拥塞控制。下载探针只是 VPS 当次网络状态的参考，不等价于客户端经代理的端到端测速。

- REALITY 目标失败：修改配置，选择当前 VPS 可达的目标。
- VPS 下载探针也慢：检查 VPS 带宽、负载、线路和服务商限速。
- VPS 下载探针正常但客户端慢：继续检查客户端分流、MTU、运营商路由和云安全组。
- 只有 Speedtest 失败：测速站可能限制数据中心 IP 或代理流量，请用普通 HTTPS 下载交叉验证。

<details>
<summary>运行截图</summary>

### 首页总览

![首页总览](docs/assets/screenshots/01-main-menu.png)

### AnyTLS 安装与节点导出

![AnyTLS 安装与节点导出](docs/assets/screenshots/02-anytls-install-export.png)

### 系统检测

![系统检测](docs/assets/screenshots/03-system-detect.png)

### 更新/升级中心

![更新/升级中心](docs/assets/screenshots/04-upgrade-center.png)

### 卸载/清理中心

![卸载/清理中心](docs/assets/screenshots/05-uninstall-center.png)

</details>

## 开发与维护

| 文件 | 用途 |
| --- | --- |
| `install.sh` | 统一入口、菜单、缓存和跨协议调度 |
| `hy2.sh` / `ss.sh` | Hysteria 2 与 Shadowsocks-Rust 管理 |
| `anytls.sh` / `vless.sh` | sing-box 原生 AnyTLS 与 VLESS 管理 |
| `euservhy2.sh` | EUserv IPv6-only 独立脚本 |
| `tests/validate_scripts.sh` | Bash 语法、版本、换行和行为验证总入口 |
| `docs/` | 架构、测试、发布和维护边界 |

开发前请阅读：

- [贡献指南](CONTRIBUTING.md)
- [架构说明](docs/ARCHITECTURE.md)
- [测试指南](docs/TESTING.md)
- [发布流程](docs/RELEASE.md)
- [维护与安全边界](docs/MAINTENANCE.md)
- [变更日志](CHANGELOG.md)

本地修改后运行：

```bash
bash tests/validate_scripts.sh
git diff --check
```

运行时安装、升级、防火墙和卸载仍需在一次性 VPS 上验证。项目要求每次提交一组修改时同步提升统一版本、日期、README、测试期望和 CHANGELOG。

## 项目信息

| 项目 | 地址 |
| --- | --- |
| Author | everettlabs |
| GitHub | [everett7623/hy2](https://github.com/everett7623/hy2) |
| Blog | [seedloc.com](https://seedloc.com) |
| Review | [vpsknow.com](https://vpsknow.com) |
| Forum | [nodeloc.com](https://nodeloc.com) |
| License | [MIT](LICENSE) |

## 免责声明

- 本项目仅供学习、技术研究和网络协议交流使用。
- 请遵守所在地法律法规和云服务商使用条款。
- 使用本项目产生的风险和后果由使用者自行承担。

如果项目对你有帮助，欢迎 Star 支持。
