# Requirements Document

## Introduction

本需求文档描述 hy2 项目 v1.1.0 版本的全面优化升级，涵盖四大方向：
1. 对 hy2.sh 和 ss.sh 脚本进行代码质量、健壮性和用户体验全面优化
2. 修复已知 bug（包括边界条件、异常处理和兼容性问题）
3. 版本号和更新时间统一递增至 v1.1.0
4. 新增 AnyTLS 协议支持（独立管理脚本 + install.sh 启动器集成）

## Glossary

- **Script_Manager**: hy2 项目的 bash 脚本集合，包含 hy2.sh、ss.sh、euservhy2.sh 和 install.sh
- **AnyTLS_Script**: 新增的 AnyTLS 协议管理脚本 (anytls.sh)
- **Launcher**: install.sh 统一远程入口脚本
- **AnyTLS_Server**: anytls-rs 项目提供的 AnyTLS 服务端二进制 (anytls-server)
- **AnyTLS_Client**: anytls-rs 项目提供的 AnyTLS 客户端二进制 (anytls-client)
- **Service_Manager**: systemd 或 OpenRC 服务管理层
- **Validator**: tests/validate_scripts.sh 静态检查脚本
- **Meta_Store**: 配置元数据存储目录（/etc/anytls/meta 等）
- **Firewall_Manager**: 脚本内置的防火墙规则管理功能（兼容 ufw/firewalld/iptables）
- **Version_Header**: 每个脚本文件头部的版本号和日期声明

## Requirements

### Requirement 1: AnyTLS 管理脚本核心功能

**User Story:** As a VPS 管理员, I want 一个独立的 AnyTLS 一键管理脚本, so that 我可以像管理 Hysteria2 和 Shadowsocks 一样方便地部署和管理 AnyTLS 代理节点。

#### Acceptance Criteria

1. THE AnyTLS_Script SHALL provide install, upgrade, uninstall, service management (start/stop/restart), configuration display, and configuration modification functions through an interactive menu
2. WHEN a user selects install, THE AnyTLS_Script SHALL check for root permission, detect the init system (systemd/openrc), install dependencies, and download the latest anytls-server binary from GitHub releases for the detected CPU architecture (amd64/arm64/armv7)
3. WHEN installation completes, THE AnyTLS_Script SHALL generate a self-signed TLS certificate, write the server configuration, create a systemd or OpenRC service, enable and start the service, and verify the service is active within 5 seconds of startup
4. WHEN a user provides a custom port, THE AnyTLS_Script SHALL validate the port is an integer between 1 and 65535; IF no port is provided, THEN THE AnyTLS_Script SHALL use the default port 443
5. WHEN a user provides a custom password, THE AnyTLS_Script SHALL validate the password does not contain double quotes, backslashes, or control characters and does not exceed 128 characters; IF no password is provided, THEN THE AnyTLS_Script SHALL generate a random password using openssl rand -base64 16
6. THE AnyTLS_Script SHALL store installation metadata (port, password, SNI, public IP, NAT mode) in the Meta_Store directory /etc/anytls/meta
7. WHEN displaying configuration, THE AnyTLS_Script SHALL output the server address, port, password, SNI, and generate client connection commands and compatible client configurations (Clash Meta, Surfboard, Loon)
8. IF a download fails, THEN THE AnyTLS_Script SHALL return exit code 1 without terminating the entire script, allowing the caller to decide next steps
9. WHEN upgrading, THE AnyTLS_Script SHALL backup the current binary before downloading, and IF the new binary fails to start the service within 5 seconds, THEN THE AnyTLS_Script SHALL restore the backed-up binary and restart the service
10. WHEN installation or configuration modification succeeds, THE AnyTLS_Script SHALL open the configured port in the active Linux firewall (firewalld, ufw, or iptables) for both TCP and UDP traffic

### Requirement 2: AnyTLS 网络检测与防火墙集成

**User Story:** As a VPS 管理员, I want AnyTLS 脚本自动检测网络环境并配置防火墙, so that 我无需手动处理网络配置和端口放行。

#### Acceptance Criteria

1. WHEN detecting network, THE AnyTLS_Script SHALL identify IPv4 address via external API (api.ipify.org, ip.gs, ipv4.icanhazip.com with 3-second connect-timeout), IPv6 address via IPv6 API (api6.ipify.org, ipv6.icanhazip.com), NAT mode (by comparing public IP against local interface IPs excluding 127.x and 169.254.x), and IPv6-only status (no IPv4 but IPv6 present)
2. WHILE the machine is in NAT mode, THE AnyTLS_Script SHALL prompt for both a local listening port and an external client-facing port, storing both in metadata
3. WHEN installation or port modification occurs, THE Firewall_Manager SHALL open the configured TCP port using the active firewall tool (ufw with `ufw allow {port}/tcp`, firewalld with `firewall-cmd --permanent --add-port={port}/tcp && firewall-cmd --reload`, or iptables with idempotent `-C`/`-I` rules)
4. WHEN the machine has IPv6 connectivity and iptables is the active firewall, THE Firewall_Manager SHALL also create ip6tables rules for the configured port using the same idempotent pattern; IF ip6tables rule creation fails, THEN THE Firewall_Manager SHALL log the failure and continue installation with only IPv4 rules
5. IF no firewall tool is detected (ufw inactive, firewalld inactive, iptables not found), THEN THE AnyTLS_Script SHALL display a warning message instructing the user to manually open the required TCP port

### Requirement 3: AnyTLS 客户端配置输出

**User Story:** As a VPS 管理员, I want 脚本自动生成多客户端配置, so that 我可以快速配置各平台客户端连接 AnyTLS 节点。

#### Acceptance Criteria

1. WHEN displaying configuration, THE AnyTLS_Script SHALL generate a complete anytls-client command-line example containing server address, port, password, and SNI parameters, with IPv6 addresses enclosed in square brackets
2. WHEN displaying configuration, THE AnyTLS_Script SHALL generate Clash Meta (mihomo) proxy configuration in YAML format containing name, type (anytls), server, port, password, sni, and skip-cert-verify fields
3. WHEN displaying configuration, THE AnyTLS_Script SHALL generate Surfboard configuration in the format: {name} = anytls, {server}, {port}, {password}, skip-cert-verify=true, sni={sni}
4. IF qrencode is available, THEN THE AnyTLS_Script SHALL generate a terminal QR code encoding the AnyTLS connection URI in the format: anytls://{password}@{host}:{port}/?sni={sni}&insecure=1#{node_name}
5. IF qrencode is not available, THEN THE AnyTLS_Script SHALL display a QR code image URL using a public QR generation API as fallback, encoding the same AnyTLS connection URI
6. WHEN the machine has both IPv4 and IPv6 addresses, THE AnyTLS_Script SHALL display both IPv4 and IPv6 node configurations sequentially, each containing all client format outputs (command-line, Clash Meta, Surfboard, share link, and QR code); WHEN the machine has only IPv4 or only IPv6, THE AnyTLS_Script SHALL display configuration only for the available address type
7. THE AnyTLS_Script SHALL use a node name in the format "AnyTLS-{v4|v6}-{MMdd}" where MMdd is the current month and day
8. IF metadata files are missing or unreadable when displaying configuration, THEN THE AnyTLS_Script SHALL display an error message and return to the menu without crashing

### Requirement 4: install.sh 启动器集成 AnyTLS

**User Story:** As a 用户, I want 统一入口中增加 AnyTLS 选项, so that 我可以从 install.sh 直接选择并安装 AnyTLS。

#### Acceptance Criteria

1. THE Launcher SHALL add an AnyTLS menu option (编号 4) in the main menu after the existing options, displaying protocol description "AnyTLS 代理" and current service status in green (运行中), red (已停止), or gray (未安装)
2. WHEN a user selects the AnyTLS option (input "4"), THE Launcher SHALL download anytls.sh from `https://raw.githubusercontent.com/everett7623/hy2/main/anytls.sh` into a mktemp temporary file and execute it via `bash "$tmpfile"`
3. THE Launcher SHALL detect AnyTLS service status by checking systemd service `anytls-server.service` via `systemctl is-active` or OpenRC via `rc-service anytls-server status`, displaying status consistent with existing Hysteria2 and Shadowsocks format
4. THE Launcher SHALL update the valid input range prompt from [0-3] to [0-4], always accept input "4" regardless of AnyTLS installation status, and display an error message for inputs outside this range

### Requirement 5: 版本号与更新时间统一递增

**User Story:** As a 项目维护者, I want 所有脚本版本号和日期同步更新, so that 发布时版本一致且可通过 CI 验证。

#### Acceptance Criteria

1. THE Script_Manager SHALL update all script file headers (install.sh, hy2.sh, ss.sh, euservhy2.sh, anytls.sh) to version v1.1.0 and the release date in YYYY-MM-DD format
2. THE Script_Manager SHALL update all visible menu display strings containing version numbers to v1.1.0 in each script
3. THE Script_Manager SHALL update the install.sh status bar version display to v1.1.0
4. THE Validator SHALL update the EXPECTED_VERSION variable to "v1.1.0" and add "anytls.sh" to the SCRIPTS list
5. THE Script_Manager SHALL add a v1.1.0 section to CHANGELOG.md documenting all changes in this release
6. THE Validator SHALL update the euservhy2.sh version check to `SCRIPT_VERSION="1.1.0"`
7. WHEN the Validator runs, THE Validator SHALL verify version consistency across all scripts (including the new anytls.sh) and exit with code 0

### Requirement 6: hy2.sh 脚本优化

**User Story:** As a 用户, I want hy2.sh 脚本运行更加健壮和用户友好, so that 安装和管理过程中遇到异常情况时能够正确处理。

#### Acceptance Criteria

1. WHEN the user enters an empty password and auto-generation is triggered, THE Script_Manager SHALL produce a password containing only alphanumeric characters (A-Z, a-z, 0-9) with a fixed length of 20 characters, retrying the random source up to 10 iterations if filtered output is shorter than 20 characters
2. WHEN the machine has no IPv4 connectivity, THE Script_Manager SHALL timeout each IPv4 API call within 3 seconds per attempt (connect-timeout), set the IPV6_ONLY flag to 1, and proceed using only IPv6 addresses for listen address and public IP detection
3. WHEN the auto-update cron script runs and detects the service was active before binary replacement, THE Script_Manager SHALL restart the service after successful binary replacement, wait 2 seconds, verify the service is active, and roll back to the backed-up binary with a service restart if the new version fails to start
4. WHEN the listen address for port hopping is constructed, THE Script_Manager SHALL replace the colon character in the user-entered range (e.g., "20000:50000") with a dash character (e.g., "20000-50000") before writing to the Hysteria2 config listen field
5. WHEN show_config is called and meta files are missing or unreadable, THE Script_Manager SHALL fall back to parsing the config.yaml file directly to extract listen port and password; IF config.yaml is also missing, THEN THE Script_Manager SHALL display an error message indicating no configuration found and return to the menu without terminating the script
6. IF the download temporary file cannot be created via mktemp, THEN THE Script_Manager SHALL display an error message indicating the temp file creation failure and return a non-zero exit code (return 1) without proceeding to the download step

### Requirement 7: ss.sh 脚本优化

**User Story:** As a 用户, I want ss.sh 脚本更加稳定可靠, so that Shadowsocks 的安装、升级和配置修改流程更少出错。

#### Acceptance Criteria

1. WHEN the user selects SS-2022 encryption and the system time sync command (timedatectl) is unavailable, THE Script_Manager SHALL display a yellow warning message "[警告] timedatectl 不可用，SS-2022 要求系统时间精确，请手动确认时间同步" instead of silently failing
2. WHEN modifying configuration fails and rollback is triggered, THE Script_Manager SHALL restore both the config file and meta directory from the backed-up copies created before modification, restart the service, wait 2 seconds, verify service is active via service_is_active, and display rollback status to the user
3. WHEN the ss.sh auto-update script runs, THE Script_Manager SHALL verify the downloaded binary responds to a version flag (e.g., `ssserver --version`) with a non-empty output before replacing the active binary; IF version check fails, THEN THE Script_Manager SHALL discard the download and log the failure
4. WHEN detecting network for Shadowsocks, THE Script_Manager SHALL exclude interfaces matching "warp*", "wg*", and "tun*" from IPv4 address detection to prevent false positive IPv4 connectivity results from WARP/tunnel virtual interfaces
5. IF tar extraction fails during download, THEN THE Script_Manager SHALL clean up both the archive file and the temporary extraction directory before returning a non-zero exit code
6. WHEN the connection test function is invoked, THE Script_Manager SHALL use a timeout of no more than 10 seconds for all network probes (nc, /dev/tcp) to prevent indefinite hangs

### Requirement 8: 通用代码质量优化

**User Story:** As a 开发者, I want 所有脚本遵循统一的编码规范和最佳实践, so that 代码可维护性更高、bug 更少。

#### Acceptance Criteria

1. THE Script_Manager SHALL ensure all download functions use mktemp for temporary files and clean up temporary files in all exit paths (success, failure, and interrupt) via a trap on EXIT, INT, and TERM signals set immediately after mktemp succeeds
2. THE Script_Manager SHALL ensure all service verification checks include a sleep interval of at least 2 seconds, stored in a named variable, between service start/restart and the subsequent service_is_active status check
3. THE Script_Manager SHALL ensure all user input prompts that require a non-empty value display an error message indicating the field cannot be empty and either return to the caller or re-display the prompt without proceeding to use the empty value
4. THE Script_Manager SHALL ensure the bash bootstrap section in all scripts attempts package installation using apk for Alpine, apt-get for Debian/Ubuntu derivatives, dnf for Fedora, and yum for CentOS/RHEL/Rocky/AlmaLinux, based on the detected distribution
5. THE Script_Manager SHALL ensure all scripts (install.sh, hy2.sh, ss.sh, euservhy2.sh, anytls.sh) pass both bash -n syntax check AND contain no instances of grep -oP, ${var,,}, ${var^^}, or head -c; both conditions must be satisfied for compliance
6. THE Script_Manager SHALL ensure all URI encoding functions produce output in the pure-bash fallback path where each byte of a multi-byte UTF-8 character is individually percent-encoded (e.g., a 3-byte character produces three %XX sequences)

### Requirement 9: AnyTLS 自动更新与 BBR 支持

**User Story:** As a VPS 管理员, I want AnyTLS 也支持自动更新和 BBR 加速, so that 节点能保持最新版本且网络性能最优。

#### Acceptance Criteria

1. WHEN a user enables auto-update in the server tools menu, THE AnyTLS_Script SHALL install cron if not present using the detected package manager, create a standalone update script at /usr/local/bin/anytls-autoupdate.sh, and register a cron entry scheduled at 03:00 daily that executes the update script
2. WHEN the auto-update script runs, THE AnyTLS_Script SHALL query the GitHub releases API for the latest AnyTLS version, compare it to the installed binary version, and skip execution if the versions match
3. WHEN the auto-update script detects a newer version, THE AnyTLS_Script SHALL backup the current binary to /usr/local/bin/anytls-server.autoupdate.bak, download the new binary, verify the downloaded file executes successfully with a version flag, replace the active binary, restart the service, and confirm the service is running within 5 seconds after restart
4. IF the service fails to start within 5 seconds after an auto-update binary replacement, THEN THE AnyTLS_Script SHALL restore the backup binary, restart the service with the previous version, and log the rollback event
5. WHEN a user selects BBR optimization, THE AnyTLS_Script SHALL check that the kernel version is 4.9 or higher, attempt BBR3 if kernel is 5.15 or higher, fall back to BBR if BBR3 is unavailable, write the sysctl configuration to /etc/sysctl.d/99-anytls-bbr.conf, and verify the active congestion control algorithm matches the target after applying
6. IF the kernel version is below 4.9 when BBR optimization is selected, THEN THE AnyTLS_Script SHALL display an error message indicating the kernel does not support BBR and return to the menu without modifying system settings
7. WHEN a user disables auto-update, THE AnyTLS_Script SHALL remove the cron entry containing "anytls-autoupdate" and delete the script file at /usr/local/bin/anytls-autoupdate.sh
8. THE AnyTLS_Script SHALL append all auto-update execution results to /var/log/anytls-autoupdate.log prefixed with an ISO 8601 timestamp (YYYY-MM-DD HH:MM:SS)

### Requirement 10: AnyTLS 脚本兼容性

**User Story:** As a 用户, I want AnyTLS 脚本在各种 Linux 环境中都能正常工作, so that 我不需要关心具体的发行版和系统差异。

#### Acceptance Criteria

1. THE AnyTLS_Script SHALL complete installation and service management operations (install, start, stop, restart, status check, uninstall) on Debian 10+, Ubuntu 20.04+, CentOS 7+, Rocky/Alma 8+, Fedora 38+, Arch Linux, and Alpine Linux 3.x without errors caused by distribution-specific differences
2. THE AnyTLS_Script SHALL include the bash bootstrap (detect non-bash shell and re-exec under bash, installing bash via the available package manager if absent), TTY fix (`[ ! -t 0 ] && [ -c /dev/tty ] && exec < /dev/tty`), and CRLF guard (detect `\r` in script file, strip via sed, and re-exec) for remote piped execution compatibility
3. THE AnyTLS_Script SHALL detect the init system by checking for systemd (`/run/systemd/system` directory and `systemctl` command), OpenRC (`rc-service` command), or none, and create a systemd unit file when systemd is detected, an OpenRC init script when OpenRC is detected, or skip service file creation when neither is present
4. THE AnyTLS_Script SHALL not use grep -oP, ${var,,}, or head -c to maintain busybox compatibility
5. THE AnyTLS_Script SHALL install required dependencies (curl, wget, openssl, ca-certificates) using the detected package manager (apk for Alpine, apt-get for Debian/Ubuntu, dnf for Fedora/Rocky/Alma, yum for CentOS 7, pacman for Arch) before attempting binary download
6. WHEN running on a machine without systemd or OpenRC, THE AnyTLS_Script SHALL fall back to nohup-based process management with a PID file stored at /var/run/anytls.pid, supporting start (nohup with stdout/stderr redirected to /var/log/anytls.log), stop (kill via stored PID then remove PID file), and status check (kill -0 on stored PID)
7. IF dependency installation fails for any required package, THEN THE AnyTLS_Script SHALL display an error message indicating which package failed to install and exit with a non-zero status without attempting binary download
8. IF the detected operating system or version is not in the supported list, THEN THE AnyTLS_Script SHALL display a warning message indicating the unsupported distribution and version, and proceed with a best-effort installation attempt
