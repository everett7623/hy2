# GitHub Copilot Instructions for Sing-box Multi-Protocol Tools

参考 `CLAUDE.md` 获取完整的 AI 开发指南。

## 项目概述

Bash 脚本集合，用于在 Linux VPS 上一键部署和管理 VLESS、AnyTLS、Hysteria 2、Shadowsocks-Rust。脚本通过 `curl | bash` 从 GitHub `main` 分支远程执行。

当前版本：v2.0.22 (2026-07-21)

## 关键约束

### 兼容性要求（绝不可移除）

1. **Bash bootstrap**: `exec bash "$0" "$@"` 确保在 Alpine 等系统运行
2. **CRLF guard**: 运行时自动修复 Windows 换行符
3. **TTY fix**: `exec < /dev/tty` 支持 `curl | bash` 交互
4. **busybox 兼容**: 不用 `grep -oP`，改用 `awk`/`cut`
5. **bash 3.x 兼容**: 不用 `${var,,}`，改用 `tr '[:upper:]' '[:lower:]'`

### 开发模式

- 测试本地修改：直接运行脚本（如 `bash hy2.sh`）
- **不要用 `install.sh` 测试**：它始终下载 GitHub `main` 的远程版本
- VPS 测试：在可销毁实例上验证安装/升级/卸载

### 版本管理（强制）

每次提交必须同步更新：
- 6 个脚本的文件头版本和日期
- `install.sh`、`hy2.sh`、`ss.sh`、`anytls.sh`、`vless.sh` 的菜单版本
- `euservhy2.sh` 的 `SCRIPT_VERSION`
- `tests/validate_scripts.sh` 的 `EXPECTED_VERSION`
- `README.md` 的版本、日期和更新摘要
- `CHANGELOG.md` 顶部条目

## 测试命令

```bash
# 必须：静态验证
bash tests/validate_scripts.sh
git diff --check

# 可选：协议特定验证（需要有效配置）
bash tests/validate_anytls.sh
bash tests/validate_vless.sh
```

## 提交规范

- 主体用简体中文，前缀（`feat:`、`fix:`）用英文
- 禁止添加 AI 署名
- 不提交敏感信息

完整文档：`CLAUDE.md`、`CONTRIBUTING.md`、`docs/`
