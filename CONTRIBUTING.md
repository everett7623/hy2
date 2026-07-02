# 贡献与开发指南

感谢参与 Sing-box Multi-Protocol Tools 项目。此仓库直接向 VPS 用户分发 root 权限 Shell 脚本，改动应优先保证可恢复性、跨发行版兼容和远程执行安全。

## 开发前必读

1. 阅读 `AGENTS.md` 或 `CLAUDE.md`，了解不可移除的兼容约束。
2. 阅读 `docs/ARCHITECTURE.md`，确认脚本边界和执行模型。
3. 阅读 `docs/TESTING.md`，根据改动范围选择 VPS 测试场景。
4. 不要通过 `install.sh` 测试未推送的本地子脚本；它始终下载 GitHub `main`。

## 修改原则

- 保持 `install.sh`、`hy2.sh`、`ss.sh`、`anytls.sh`、`euservhy2.sh` 可独立执行。
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

项目没有共享版本文件。发布时同步修改：

- 五个脚本的文件头版本和日期
- `install.sh`、`hy2.sh`、`ss.sh`、`anytls.sh` 的菜单显示版本
- `euservhy2.sh` 的 `SCRIPT_VERSION`
- `tests/validate_scripts.sh` 的 `EXPECTED_VERSION`
- AnyTLS 变更需同步 `tests/validate_anytls.sh`；保持 sing-box 原生 AnyTLS 入站、JSON 配置、证书与 wrapper 的测试覆盖。
- `CHANGELOG.md`

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
