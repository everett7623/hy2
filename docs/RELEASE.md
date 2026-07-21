# 发布流程

## 版本更新原则

项目采用“每次提交一组修改即提升统一版本”的策略。代码、测试或文档发生可提交变化时，必须在同一提交中同步版本、日期、README 和 CHANGELOG；不得先提交功能，等创建 GitHub Release 时再补版本。多个尚未提交且属于同一变更集的编辑可共用一次版本提升。

## 发布前

1. 确认工作区只包含本次发布内容。
2. 确认本次变更集已按语义化版本提升版本，例如 `v1.0.3`。
3. 同步六个脚本的文件头版本和更新日期。
4. 同步五个菜单版本和 EUserv `SCRIPT_VERSION`。
5. 更新 `tests/validate_scripts.sh` 中的 `EXPECTED_VERSION`。
6. AnyTLS 或 VLESS 变更需确认行为测试覆盖官方下载 URL、配置和服务文件生成；共享 sing-box 升级还需验证所有现存配置。
7. 同步 `README.md` 的当前版本、日期和本次更新摘要。
8. 在 `CHANGELOG.md` 顶部增加版本、日期和用户可见变化。

## 静态验证

```bash
bash tests/validate_scripts.sh
git diff --check
git diff
```

## VPS 验收

按 `docs/TESTING.md` 选择覆盖本次改动的测试矩阵。至少验证一个 systemd 环境；涉及 Alpine/OpenRC、NAT、IPv6 或 EUserv 时必须增加对应环境。

记录未测试的平台和架构，不得用静态检查替代实机结论。

## 发布顺序

1. 合并或推送代码到 GitHub `main`。
2. 确认 GitHub Actions `Shell checks` 通过。
3. 从 `raw.githubusercontent.com` 下载脚本，确认远端内容和版本正确。
4. 在一次性 VPS 上通过远程命令执行最终冒烟测试。
5. 创建与脚本版本一致的 Git tag 和 GitHub Release。

> `install.sh` 始终读取 `main`。代码推送后即可能被用户执行，因此不要先推送未完成代码、再等待后续修复。

## 发布后检查

```bash
curl -fsSL https://raw.githubusercontent.com/everett7623/hy2/main/install.sh | head
curl -fsSL https://raw.githubusercontent.com/everett7623/hy2/main/hy2.sh | head
curl -fsSL https://raw.githubusercontent.com/everett7623/hy2/main/ss.sh | head
curl -fsSL https://raw.githubusercontent.com/everett7623/hy2/main/anytls.sh | head
curl -fsSL https://raw.githubusercontent.com/everett7623/hy2/main/vless.sh | head
curl -fsSL https://raw.githubusercontent.com/everett7623/hy2/main/euservhy2.sh | head
```

确认：

- 文件头版本和日期正确
- GitHub Release 徽章显示预期版本
- 启动器能下载当前 `main` 的子脚本
- 没有提交凭据、节点链接或测试 VPS 信息

## 紧急回滚

若 `main` 已发布严重故障：

1. 立即回滚引入故障的提交或提交最小修复。
2. 重新运行静态验证与受影响 VPS 冒烟测试。
3. 更新 `CHANGELOG.md`，发布补丁版本。
4. 不要只删除 GitHub Release；`install.sh` 使用的是 `main`，必须修复分支内容。
