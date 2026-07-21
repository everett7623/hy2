# 测试与验收指南

## sing-box 协议自动化验证

`bash tests/validate_scripts.sh` 会执行 `tests/validate_anytls.sh`。该测试会 source `anytls.sh`，验证输入校验、sing-box 下载 URL、架构映射、IPv6 URI、JSON/元数据往返、wrapper、systemd 单元和 ELF 魔数。

同一入口还会执行 `tests/validate_vless.sh`。该测试会 source `vless.sh`，验证 UUID、REALITY 密钥与 short ID 校验、REALITY 握手地址族、IPv6 URI、Mihomo/Loon/Quantumult X 输出、JSON/元数据往返、本机网络诊断、BBR 回滚、wrapper、systemd/OpenRC 单元、共享核心配置预检和卸载所有权。

静态验证会阻止 Throne 与 Sing-box/SFA 客户端导出回归。修改节点输出时，应优先保证 URI、Mihomo/Clash、Surfboard、Shadowrocket、Loon、Quantumult X 与二维码格式不受影响。

发布前仍需在一次性 VPS 覆盖 systemd、OpenRC 以及 IPv4、IPv6、双栈环境。当前脚本支持上游 Linux `amd64`、`arm64`、`armv7`、`386` 和 `s390x` 发布包，其他架构应明确拒绝。

## 测试层级

### 1. 静态验证

每次修改都必须运行：

```bash
bash tests/validate_scripts.sh
```

该脚本检查 Bash 语法、项目版本、LF 换行、兼容性禁用语法、自动更新脚本生成内容，以及客户端输出格式边界。

安装默认端口测试应确认随机值位于 `10000-65535`、不占用当前监听端口，且用户显式输入仍会覆盖随机值。

### 2. 一次性 VPS 验证

以下行为会修改系统服务、防火墙、cron、sysctl 和 `/etc`，必须在可销毁 VPS 上测试：

- 全新安装和重复安装
- 服务启动、停止、重启和开机启动
- 升级成功、下载失败、服务失败和回滚
- 配置修改成功和失败回滚
- 自动更新创建、手动执行、日志和移除
- 防火墙规则写入及重复执行
- 卸载后的文件、服务和 cron 清理
- `/etc/sing-box` 存在其他配置时，卸载 AnyTLS 或 VLESS 不得删除共享文件和核心
- AnyTLS/VLESS 任一入口升级 sing-box 前，必须用候选二进制校验所有 `/etc/sing-box/*.json`
- AnyTLS 三种证书模式均需验证：自签输出兼容参数；已有证书校验 SAN、有效期、root 私钥权限和密钥配对；ACME 仅在 sing-box >= 1.14.0 使用 `certificate_provider`，并验证 TCP 80/443 防火墙所有权、回滚和卸载清理
- 核心替换后必须重启替换前正在运行的 AnyTLS/VLESS；任一服务恢复失败时回滚核心和原服务状态
- 最后一个项目管理的 sing-box 协议卸载时，只有存在 `.singbox-tools-managed` 或协议元数据确认所有权后才可删除核心

### 3. 用户侧连接验证

服务器监听正常不等于客户端可连接。至少使用一个真实客户端验证分享链接、IPv4/IPv6 地址、端口及认证参数。VLESS 还需核对 UUID、SNI、REALITY 公钥、short ID 与 `xtls-rprx-vision`，并确认 VPS 可访问 REALITY 握手目标。

## 推荐测试矩阵

| 场景 | 推荐系统 | init | 重点 |
| --- | --- | --- | --- |
| Debian 主路径 | Debian 12 | systemd | apt、ufw、cron、Hysteria 2 |
| Ubuntu 主路径 | Ubuntu 24.04 | systemd | ufw、云安全组、双栈 |
| RHEL 系 | Rocky Linux 9 | systemd | dnf、firewalld、SELinux |
| Alpine | Alpine 3.x | OpenRC | apk、musl、OpenRC、dcron |
| NAT VPS | Debian 12 | systemd | 内外端口、UDP 映射 |
| 纯 IPv6 | Debian 12 | systemd | ip6tables、客户端 IPv6 |
| EUserv | EUserv Debian | systemd | NAT64 DNS、WARP、DNS 恢复 |

架构改动还应覆盖受影响的平台：`amd64`、`arm64`，以及可获得环境时的 `armv7`、`s390x`、`loongarch64`。

## 每个脚本的最小验收

### `install.sh`

- 无 Bash 或 curl 时能安装依赖或给出明确错误。
- 状态检测兼容 systemd、OpenRC 和未安装状态。
- 下载的子脚本为空、HTML 或语法错误时拒绝执行。
- 安装、节点信息、二维码、升级和卸载入口应向子脚本传入对应动作参数，避免先进入子脚本主菜单。
- 首次运行后应生成 `/usr/local/bin/sb`，`sb` 能打开主菜单，并在远程失败时回退到本地缓存。
- 临时文件在成功和失败后均被清理。

### `hy2.sh`

- 单端口、端口跳跃、NAT 和 IPv6-only 配置正确。
- 自签证书和分享链接可用。
- 二进制升级失败不会丢失旧版本。
- 密码和带宽修改失败时配置可恢复。

### `ss.sh`

- 经典加密和 SS-2022 均可启动。
- 双栈节点能正确选择 IPv4/IPv6。
- TCP/UDP 监听和连接测试结果合理。
- 配置与自动更新失败可回滚。

### `vless.sh`

- 全新安装生成有效 UUID、REALITY X25519 密钥对和 16 位十六进制 short ID，节点输出不得包含服务端私钥。
- sing-box JSON 使用原生 `vless` 入站、TCP、REALITY 和 `xtls-rprx-vision`，并通过 `sing-box check`。
- REALITY `handshake.domain_resolver` 使用本地 resolver，并按 IPv4 节点写入 `ipv4_only`、按纯 IPv6 节点写入 `ipv6_only`；目标筛选必须使用相同地址族。
- URI、Mihomo、Shadowrocket、Loon 与 Quantumult X 输出包含一致的公钥、short ID、SNI 和 flow；Surfboard 输出明确兼容性提示。
- NAT、IPv4、IPv6 与双栈节点地址和端口正确；REALITY 目标域名及端口可达。
- REALITY 目标固定优先 Microsoft → Apple → Samsung，Amazon / Bing / Intel / AMD / Adobe 作为随机后备；候选不使用 `.cn` 或 GitHub，安装探测和运行诊断应从 VPS 实际执行，目标不可达时明确告警。
- 运行诊断分别报告 REALITY 目标可达性、握手地址族、外部测速源到 VPS 的入站下载、本机 TCP/IP 累计计数、网卡及活动队列；不得把该探针描述为 VPS 到客户端方向，也不把 Speedtest 单站失败直接判定为 VLESS 故障。
- `vless.sh diagnose` 与服务管理菜单中的诊断入口应产生相同检查结果，且不修改配置、服务或防火墙。
- 独立 VLESS 工具箱手动启用标准 `bbr + fq` 时应原子写入共享 sysctl 文件；任一实时参数未生效时恢复旧文件与修改前参数。
- 配置修改、重装、升级或服务启动失败时恢复旧配置、核心和服务状态。
- 与 AnyTLS 共存时，升级会预检双方 JSON；不同卸载顺序都不会误删共享配置或遗留项目独占核心。

### `euservhy2.sh`

- 非 systemd 或无全局 IPv6 时明确拒绝。
- NAT64 DNS 在成功、失败和中断后恢复。
- 下载文件经过 ELF 和执行验证。
- 修改端口、密码、伪装域名和 SNI 后服务可用。

## 故障注入

建议主动模拟：

- 将下载 URL 临时改为不存在地址。
- 下载 HTML 文本代替二进制。
- 写入无效配置后触发服务重启失败。
- 在升级期间按 `Ctrl+C`。
- 禁用 GitHub API，只保留备用下载源。
- 重复执行防火墙和 cron 配置。

## 测试记录模板

```text
日期:
提交:
VPS/系统:
架构:
网络: IPv4 / 双栈 / IPv6-only / NAT
脚本:
测试路径:
结果:
未测试项:
日志或截图:
```
