# 客户端输出格式规范化

- [x] 阅读 `docs/ARCHITECTURE.md`、`CONTRIBUTING.md`、`docs/TESTING.md`
- [x] 盘点各协议、各客户端的分享链接与配置输出
- [x] 修正 UUID、password 及相关字符串字段的格式与转义
- [x] 更新或补充输出格式测试
- [x] 运行 `bash tests/validate_scripts.sh`

## 验证结果

- Git Bash：`bash tests/validate_scripts.sh` 全部通过。
- `git diff --check` 通过。

## 边界

- 只调整用户可复制的客户端输出和对应测试，不改服务端协议配置。
- 按 URI、YAML、JSON、Loon、Quantumult X 等各自语法处理，不强制跨格式使用相同引号。
- 保留 IPv4、IPv6、NAT 及现有客户端兼容行为。
