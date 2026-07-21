# VLESS 回退任务

日期：2026-07-21

## 目标

将 `vless.sh` 的运行行为和对应行为测试恢复到已验证可用的 `v2.0.19` 基线（提交 `7da4d86`），并以统一项目版本 `v2.0.21` 发布该回退。

## 边界

- 保留工作区中正在进行的 README 重构和其他脚本版本同步修改。
- 不回退 `v2.0.20` 对非 VLESS 脚本的改动。
- 同步修正当前文档中仅由 `v2.0.20` VLESS 实现提供的行为说明。
- 静态验证不能替代一次性 VPS 上的实际连通性测试。

## TODO

- [x] 阅读架构、贡献、测试、发布与维护文档。
- [x] 确认上一可用版本为 `v2.0.19`（`7da4d86`）。
- [x] 回退 `vless.sh` 和 `tests/validate_vless.sh`。
- [x] 同步 `v2.0.21` 版本、README、CHANGELOG 与开发文档。
- [x] 运行 `bash tests/validate_scripts.sh` 和 `git diff --check`。
- [x] 复核最终差异并记录未执行的 VPS 验证。

## 验证结果

- `bash tests/validate_scripts.sh`：通过。
- `git diff --check`：通过。
- `vless.sh` 相对 `7da4d86` 仅保留 `v2.0.21` 版本、日期和菜单版本差异。
- `tests/validate_vless.sh` 与 `7da4d86` 的 blob 哈希一致。
- 未执行一次性 VPS 上的安装、服务启动与客户端连通性验证。

## 版本字段审计

- [x] 六个脚本头部版本统一为 `v2.0.21`。
- [x] 五个菜单显示版本和 EUserv 动态显示版本统一为 `v2.0.21`。
- [x] `install.sh` 备份元数据、README、CHANGELOG 和测试期望版本统一为 `v2.0.21`。
- [x] 版本测试从单一 `EXPECTED_VERSION` 派生 EUserv 数字版本，并覆盖 README 与备份元数据。

## 后续更正

`v2.0.22` 全项目复核确认：`7da4d86` 只是 `v2.0.19` 发布提交，之后还有五个未同步版本号但已验证的 VLESS 修复提交；最后可用基线应为 `bad8ded`。本任务选择了错误回退点，因此撤掉了死 IPv6、健康轮询、地址族解析、诊断和 Mihomo 字段引用修复，已在后续任务中纠正。
