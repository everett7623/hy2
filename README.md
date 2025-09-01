# Hysteria2 & Shadowsocks (IPv6-Only) 二合一管理脚本

![版本](https://img.shields.io/badge/版本-6.5.0-blue.svg) ![语言](https://img.shields.io/badge/语言-Bash-green.svg) ![许可](https://img.shields.io/badge/许可-MIT-brightgreen.svg)

这是一个功能强大且极度精简的 Shell 脚本，专为在 **IPv6-Only** 或 **双栈 (IPv4/IPv6)** 服务器上快速部署和管理 Hysteria2 和 Shadowsocks 服务而设计。

此版本经过多次迭代优化，移除了非核心功能（如备份），并将所有服务管理操作整合，提供了最简洁高效的使用体验。

## ✨ 核心特点

-   **二合一管理**: 在单个脚本中轻松管理 Hysteria2 和 Shadowsocks 两个服务。
-   **Hysteria2 极简部署**:
    -   采用 **自签名证书** 模式，**无需购买域名**，也无需任何第三方 API。
    -   安装流程自动化，只需输入一个用于伪装的域名（任意即可）和密码即可完成。
-   **专注 IPv6 的 Shadowsocks**:
    -   Shadowsocks 服务仅监听服务器的 **IPv6 地址**，非常适合纯 IPv6 小鸡或希望将服务与 IPv4 分离的场景。
    -   自动安装 `shadowsocks-libev` 并生成随机端口和密码。
-   **高度整合的管理中心**:
    -   将**启动、停止、重启、查看日志、显示配置、卸载**等所有操作聚合到统一的管理菜单中，逻辑清晰，操作便捷。
-   **用户友好**:
    -   清晰的菜单界面，所有操作一目了然。
    -   自动检测操作系统 (Ubuntu, Debian, CentOS, Fedora 等) 和 CPU 架构。
    -   关键步骤提供人性化的提示和确认。

## 🖥️ 系统要求

-   一台拥有 `root` 权限的 Linux 服务器。
-   支持的操作系统: **Ubuntu**, **Debian**, **CentOS**, **Rocky Linux**, **AlmaLinux**, **Fedora** 等主流发行版。
-   若要安装 Shadowsocks，服务器必须拥有至少一个**公网 IPv6 地址**。

## 🚀 快速开始

使用以下任一命令即可下载并运行此脚本：

**cURL 方式 (推荐)**
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/everett7623/hy2ipv6/main/hy2.sh)
```

**Wget 方式**
```bash
bash <(wget -qO- https://raw.githubusercontent.com/everett7623/hy2ipv6/main/hy2.sh)
```

脚本运行后，您将看到主菜单，根据提示选择相应的数字即可执行操作。

## 📜 菜单功能详解

-   **1. 安装 Hysteria2 (自签名证书模式)**
    -   安装 Hysteria2 服务。您只需要提供一个用于 SNI 伪装的域名（如 `www.bing.com`）和连接密码。客户端连接时**必须**勾选“允许不安全连接”。
-   **2. 安装 Shadowsocks (仅 IPv6)**
    -   在服务器的 IPv6 地址上安装 Shadowsocks-libev 服务，并自动生成配置。
-   **3. 管理服务 (启停/日志/配置/卸载)**
    -   进入统一的服务管理中心。您可以先选择要管理的 Hysteria2 或 Shadowsocks，然后对其进行**启动、停止、重启、查看实时日志、显示连接信息、以及卸载**等所有相关操作。
-   **4. 系统诊断**
    -   显示当前系统信息、IP 地址、端口占用和防火墙状态，帮助快速定位问题。
-   **0. 退出脚本**
    -   安全退出脚本。

## ⚠️ 重要提示

-   **Hysteria2 自签名证书**: 由于使用的是自签名证书，所有客户端在配置连接时，**必须** 找到并启用 **“允许不安全连接”**、**“跳过证书验证”** 或类似的选项 (英文通常是 `insecure` 或 `skip-cert-verify`)，否则无法连接。
-   **Shadowsocks IPv6**: 此脚本安装的 Shadowsocks **仅适用于 IPv6 网络环境**。请确保您的客户端设备和网络支持 IPv6 才能连接。连接地址请使用 `[IPv6 地址]` 的格式。

## 📄 许可

本项目采用 [MIT License](https://opensource.org/licenses/MIT) 许可。
