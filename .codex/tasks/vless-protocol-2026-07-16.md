# VLESS 协议支持

- 日期：2026-07-16
- 状态：已完成
- 目标：为统一工具集新增独立的 VLESS + TCP + REALITY + XTLS Vision 管理能力。

## 范围

- [x] 新增 `vless.sh`，支持安装、配置、升级、卸载、服务管理、自动更新、防火墙与节点导出。
- [x] 使用 sing-box 原生 VLESS 入站，生成 UUID、REALITY 密钥对和 short ID。
- [x] 使用 VLESS 专属配置、元数据、wrapper、service、cron 与日志路径，不覆盖 AnyTLS 产物。
- [x] 将 VLESS 接入 `install.sh` 的安装、信息、导出、二维码、服务、升级和卸载入口。
- [x] 新增 VLESS 行为验证并接入 `tests/validate_scripts.sh`。
- [x] 更新 README、架构、测试、维护和协作文档中的协议矩阵与路径说明。
- [x] 运行 `bash tests/validate_scripts.sh`。

## 边界与风险

- 默认安全形态为 VLESS + TCP + REALITY + `xtls-rprx-vision`，不提供明文 VLESS。
- REALITY 目标域名与 443 端口由用户配置，写入前校验；私钥只保存于服务器专属元数据/配置，不输出到节点信息。
- `/etc/sing-box` 与 `/usr/local/bin/sing-box` 可能被多个协议共享，卸载只删除 VLESS 专属产物；目录非空时保留共享核心。
- 本次不进行版本发布或推送，因此保持当前项目版本 `v2.0.18`，在变更日志中记录未发布功能。
- 静态验证不等价于 VPS 实机验证；安装、REALITY 握手、防火墙、systemd/OpenRC 与回滚仍需一次性 VPS 验证。

## 验收

- [x] Bash 语法、LF、兼容性和版本一致性检查通过。
- [x] VLESS JSON、元数据往返、URI/客户端导出、wrapper/service、升级回滚与共享目录卸载行为有自动化覆盖。
- [x] 不包含私钥、真实节点地址或完整真实分享链接。

## 验证结果

- `bash tests/validate_scripts.sh`：通过。
- `tests/validate_vless.sh` 与 `tests/validate_anytls.sh`：通过。
- 官方 sing-box v1.13.14 对 `vless.sh` 实际生成的 REALITY/Vision JSON 执行 `check`：通过。
- `git diff --check`：通过。
- 未在本机执行安装、卸载、防火墙或服务变更；真实 VPS 连通性保留为发布前手工验收。
