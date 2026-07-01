# 维护与故障边界

## AnyTLS 上游边界

- 唯一二进制上游是 `https://github.com/anytls/anytls-go`，使用 `anytls-server`，不切换到 sing-box。
- 发布包格式为 `anytls_<version>_linux_<amd64|arm64>.zip`；上游命名变化时必须同步行为测试。
- 配置位于 `/etc/anytls/config.env`，写入值必须先通过脚本校验。
- 自动测试不替代真实 VPS 的服务启动、防火墙和客户端连通性验证。

## 维护重点

本项目的高风险边界依次为：

1. root 权限下的文件删除和系统配置写入
2. 二进制下载、升级和自动更新
3. systemd/OpenRC 服务生命周期
4. IPv4、IPv6、NAT 和 WARP 网络识别
5. ufw、firewalld、iptables 和云安全组
6. YAML/JSON 配置与分享链接编码

修改这些区域时必须同时检查成功路径、失败路径和中断恢复。

## 外部依赖

| 依赖 | 用途 | 变化风险 |
| --- | --- | --- |
| `apernet/hysteria` GitHub Releases | Hysteria 2 版本与二进制 | tag、文件名、架构名 |
| `shadowsocks/shadowsocks-rust` Releases | SS 版本与 musl 二进制 | tag、压缩包、架构名 |
| `download.hysteria.network` | Hysteria 备用下载 | URL 或可达性 |
| GitHub API | 获取最新版本 | 限频、网络阻断 |
| `raw.githubusercontent.com` | 分发项目脚本 | DNS、网络阻断 |
| fscarmen WARP 脚本 | EUserv IPv4 出口 | 交互参数和 URL |

上游接口变化时，先验证解析结果和下载文件，再修改生产路径。不要在下载验证前覆盖现有二进制。

## 安装产物

维护或卸载逻辑变更时，对照 `AGENTS.md` 中的安装路径，并额外检查：

- `/usr/local/bin/hy2-autoupdate.sh`
- `/usr/local/bin/ss-autoupdate.sh`
- `/var/log/hy2-autoupdate.log`
- `/var/log/ss-autoupdate.log`
- `/etc/sysctl.d/99-hysteria-bbr.conf`
- `/etc/sysctl.d/99-ss-bbr.conf`
- `/etc/sysctl.d/99-euserv-bbr.conf`
- root 用户的 crontab

## 安全规则

- 不记录或提交密码、私钥和完整节点链接。
- 远程脚本必须使用 HTTPS，并对下载结果做语法或二进制验证。
- 不使用 `eval` 执行用户输入。
- 不直接 `source` 可被用户修改的元数据文件。
- `rm -rf` 目标必须是固定项目路径，不能由未经验证的输入拼接。
- 配置修改使用临时文件和备份，不做无范围的文本替换。

## 已知限制

- 云服务商安全组无法由脚本统一管理。
- NAT 外网端口映射依赖宿主商面板。
- IPv6-only 节点要求客户端具备 IPv6 可达性。
- EUserv 专用脚本只支持 systemd，且主要面向 Debian/RHEL 类系统。
- 上游最新版本在运行时获取，没有锁文件或固定版本。
- 静态 CI 无法证明真实 VPS 的服务、防火墙和网络行为。

## AI 接手协议

其他 AI 工具开始工作前应：

1. 读取 `AGENTS.md`、`CLAUDE.md` 和 `docs/ARCHITECTURE.md`。
2. 检查 `git status`，不得覆盖已有未提交修改。
3. 对照脚本实际实现，不盲信 README 或历史变更日志。
4. 将改动限制在受影响脚本和相应文档。
5. 运行 `bash tests/validate_scripts.sh`。
6. 明确区分“静态验证通过”和“VPS 实机验证通过”。
7. 修改版本时遵循 `docs/RELEASE.md`。
