# 测试与验收指南

## AnyTLS 自动化验证

`bash tests/validate_scripts.sh` 会执行 `tests/validate_anytls.sh`。该测试会 source `anytls.sh`，验证输入校验、sing-box 下载 URL、架构映射、IPv6 URI、JSON/元数据往返、wrapper、systemd 单元和 ELF 魔数。

`tests/validate_singbox_exports.sh` 会调用 Hysteria2、Shadowsocks、AnyTLS 与 EUserv HY2 的真实输出函数，并使用 JSON 解析器逐字段校验完整 TUN 配置。修改 Sing-box 输出时只改对应 JSON 生成块，不得顺带调整 URI、Mihomo、Loon、Surfboard、Shadowrocket 或二维码格式。

发布前仍需在一次性 VPS 覆盖 systemd、OpenRC 以及 IPv4、IPv6、双栈环境。当前脚本支持上游 Linux `amd64`、`arm64`、`armv7`、`386` 和 `s390x` 发布包，其他架构应明确拒绝。

## 测试层级

### 1. 静态验证

每次修改都必须运行：

```bash
bash tests/validate_scripts.sh
```

该脚本检查 Bash 语法、项目版本、LF 换行、兼容性禁用语法，以及两个自动更新脚本的生成内容。

### 2. 一次性 VPS 验证

以下行为会修改系统服务、防火墙、cron、sysctl 和 `/etc`，必须在可销毁 VPS 上测试：

- 全新安装和重复安装
- 服务启动、停止、重启和开机启动
- 升级成功、下载失败、服务失败和回滚
- 配置修改成功和失败回滚
- 自动更新创建、手动执行、日志和移除
- 防火墙规则写入及重复执行
- 卸载后的文件、服务和 cron 清理
- `/etc/sing-box` 存在其他配置时，卸载 AnyTLS 不得删除共享文件和核心

### 3. 用户侧连接验证

服务器监听正常不等于客户端可连接。至少使用一个真实客户端验证分享链接、IPv4/IPv6 地址、端口、密码、SNI 和证书跳过选项。

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
