# v2.0.19 版本同步

- 日期：2026-07-17
- 状态：版本同步完成，待 VPS 实机验收、Git tag 与 GitHub Release
- 目标：将当前 `main` 已包含的 VLESS、AnyTLS 证书模式、随机端口和诊断能力统一标记为 `v2.0.19`。

## 发布面

- [x] 六个脚本文件头版本与日期统一为 `v2.0.19` / `2026-07-17`。
- [x] `install.sh`、HY2、SS、AnyTLS、VLESS 菜单版本同步。
- [x] EUserv `SCRIPT_VERSION` 与安装备份元数据版本同步。
- [x] `tests/validate_scripts.sh` 期望版本同步。
- [x] README 当前版本与更新摘要同步。
- [x] CHANGELOG 将现有 Unreleased 内容归档为 `v2.0.19 (2026-07-17)`。

## 验证

- [x] `bash tests/validate_scripts.sh` 通过。
- [x] `git diff --check` 通过。
- [x] 确认没有误改历史版本记录。
- [x] 明确记录未执行 VPS 实机验收、Git tag 和 GitHub Release。

## 验证结果

- AnyTLS、VLESS、Hysteria 2 网络和 Shadowsocks 网络行为验证：通过。
- 静态脚本、版本一致性、LF、兼容性与生成脚本验证：通过。
- `git diff --check`：通过。
- 未执行：一次性 VPS 实机验收、Git tag、GitHub Release、远程 Raw 版本检查。
