# 强化 HY2/SS 网络检测与升级回滚

- [x] 将 WARP 原生公网 IPv4 检测扩展到 Hysteria 2 和 Shadowsocks
- [x] 修复旧元数据中的已确认 WARP 出口地址
- [x] 为重装流程增加二进制、配置、元数据、证书和服务文件回滚
- [x] 为升级流程保留原服务停止状态并校验目标版本
- [x] 通过同目录临时文件原子写入 HY2/SS 配置
- [x] 增加 HY2/SS 网络检测与回滚测试
- [x] 同步五个脚本、菜单、README、测试断言和 CHANGELOG 至 v2.0.16
- [x] 运行 `bash tests/validate_scripts.sh`
- [ ] 在一次性 VPS 验证 systemd/OpenRC、WARP 和升级失败回滚

## 验证结果

- AnyTLS behavior validation passed.
- Hysteria 2 network validation passed.
- Shadowsocks network validation passed.
- Static script validation passed.

## 实机验证边界

- Windows 开发机仅完成静态和模拟行为验证。
- 安装、服务启停、防火墙、真实 WARP 路由及失败回滚仍需在可销毁 Linux VPS 执行。
