# 贡献与开发指南

感谢参与 Sing-box Multi-Protocol Tools 项目。此仓库直接向 VPS 用户分发 root 权限 Shell 脚本，改动应优先保证可恢复性、跨发行版兼容和远程执行安全。

## 反馈问题

请用 `.github/ISSUE_TEMPLATE/` 里的 Issue 表单，不要开空白 issue：

- **故障报告**：脚本、脚本版本、发行版和版本、CPU 架构、网络类型、安装命令、复现步骤、期望与实际结果、打码后的日志
- **功能建议**：希望增加的能力（例如家宽 / 落地中转支持新的落地协议）
- **使用提问**：先看 [README 常见问题](README.md#常见问题)
- **文档问题**：README、本文件或 `docs/` 有误或过时

提交前打码公网 IP、域名、密码、UUID、密钥、节点链接和 SSH 信息。表单会带上 `bug`、`enhancement`、`question` 或 `documentation`。维护者再按脚本补标签：`hy2.sh` 与 `euservhy2.sh` 用 `script: hy2`，其余为 `script: anytls`、`script: vless`、`script: ss`、`script: landing`、`script: proxy`、`script: install`。信息不够时加 `needs-info`，复现后加 `confirmed`。

## 开发前必读

1. 阅读 `CLAUDE.md`（统一 AI 开发指南），了解不可移除的兼容约束。
2. 阅读 `docs/ARCHITECTURE.md`，确认脚本边界和执行模型。
3. 阅读 `docs/TESTING.md`，根据改动范围选择 VPS 测试场景。
4. 不要通过 `install.sh` 测试未推送的本地子脚本；它始终下载 GitHub `main`。

## 修改原则

- 保持 `install.sh`、`hy2.sh`、`ss.sh`、`anytls.sh`、`vless.sh`、`proxy.sh`、`landing.sh`、`euservhy2.sh` 可独立执行。
- 不引入共享 `source` 文件；远程启动器只下载单个脚本。
- 保留 Bash 自举、TTY 修复和 CRLF guard。
- 不使用 `grep -oP`、`${var,,}`、`${var^^}` 或 `head -c`。
- 下载二进制时先写入唯一临时文件，校验后再原子替换目标。
- 升级和配置修改必须备份；服务验证失败时必须回滚。
- 防火墙规则应幂等，兼顾 IPv4、IPv6、ufw、firewalld 和 iptables。
- 用户输入写入 YAML/JSON/服务文件前必须校验或正确转义。
- 可选依赖失败不能阻断核心安装流程。

## 开发流程

```bash
git status --short
bash tests/validate_scripts.sh
```

完成静态验证后，按 `docs/TESTING.md` 在一次性 VPS 上验证受影响流程。不要在开发机或生产节点测试安装、卸载、防火墙和 BBR 修改。

## 版本与变更日志
### 版本递增策略

按用户可见变更范围选择下一版本：补丁修复、兼容性修复、排版/测试/文档更新使用 `PATCH`（`v2.0.x+1`）；向后兼容的新功能、新协议或新导出格式使用 `MINOR`（`v2.x+1.0`）；命令、配置、导出兼容性或已支持行为发生破坏性变化使用 `MAJOR`（`v3.0.0`）。同一批改动跨越多个级别时取最高级别。每次发布提交都必须同步脚本、入口、测试、README、CHANGELOG 和日期，不能把版本更新留到之后。

项目没有共享版本文件。每次准备提交一组代码、测试或文档修改时，都必须提升统一项目版本并同步以下位置；不能等到创建 GitHub Release 时再补版本：

- 八个脚本的文件头版本和日期
- `install.sh`、`hy2.sh`、`ss.sh`、`anytls.sh`、`vless.sh`、`proxy.sh`、`landing.sh` 的菜单显示版本
- `install.sh` 写入备份元数据的 `script_version`
- `euservhy2.sh` 的 `SCRIPT_VERSION`
- `tests/validate_scripts.sh` 的 `EXPECTED_VERSION`
- `README.md` 的当前版本、日期和本次更新摘要
- AnyTLS 变更需同步 `tests/validate_anytls.sh`；保持 sing-box 原生 AnyTLS 入站、JSON 配置、证书与 wrapper 的测试覆盖。
- VLESS 变更需同步 `tests/validate_vless.sh`；保持 UUID、REALITY 密钥/short ID、JSON、客户端输出、共享核心和 wrapper/service 的测试覆盖。
- HTTP/SOCKS 变更需同步 `tests/validate_proxy.sh`；保持 mixed 入站、用户凭据、`bind_interface`、wrapper/service 的测试覆盖。
- 家宽中转变更需同步 `tests/validate_landing.sh`；保持 WireGuard 密钥校验、线路机/落地机 JSON、远程结果解析、两阶段提交回滚、SSH 安全选项和卸载所有权的测试覆盖。
- `CHANGELOG.md` 顶部对应版本、日期和用户可见变更

完整发布步骤见 `docs/RELEASE.md`。

## 提交建议

- 一个提交只解决一类问题。
- 提交信息说明用户可见影响，例如 `fix: 保留旧二进制直到下载校验通过`。
- 不提交节点密码、IP 地址、VPS 日志、私钥或真实配置。
- 文档与行为变更应在同一个提交中同步。

## Pull Request 清单

- [ ] 已运行 `bash tests/validate_scripts.sh`
- [ ] 已说明改动影响的脚本和发行版
- [ ] 已完成相应 VPS 场景测试，或明确标记未测试项
- [ ] 安装、升级、回滚和卸载没有破坏现有配置
- [ ] 版本与 `CHANGELOG.md` 已按发布策略同步
- [ ] 未包含凭据、私钥、节点链接或用户数据
