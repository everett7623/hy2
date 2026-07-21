# REALITY 目标域名优先级调整

- [x] 核对现有候选列表、选择逻辑和规范约束
- [x] 设置 Microsoft → Apple → Samsung 固定优先级
- [x] 设置 Amazon / Bing / Intel / AMD / Adobe 随机后备
- [x] 同步架构与测试文档
- [x] 同步 README 与 CHANGELOG
- [x] 升级统一版本至 `v2.0.20`（2026-07-21）
- [x] 将“每次提交修改都必须提升版本”写入开发文档
- [x] 补充选择顺序测试并运行完整验证

## 验证结果

- `tests/validate_vless.sh` 通过。
- `tests/validate_scripts.sh` 全部通过。
- `git diff --check` 通过。
- 当前版本位置无 `v2.0.19` 或 `2026-07-17` 残留。

## 边界

- 只修改 VLESS REALITY 目标候选及选择策略。
- 保留按节点 IPv4/IPv6 地址族并行探测和用户手动覆盖行为。
- 不修改 AnyTLS 的证书域名选择逻辑。
