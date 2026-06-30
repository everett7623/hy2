#!/bin/bash
# =============================================================================
# tests/helpers/validators.bash
# 可独立 source 的验证函数库，供 bats 测试文件使用
#
# 用法：source "$(dirname "$BATS_TEST_FILENAME")/../helpers/validators.bash"
#
# 包含函数：
#   validate_port      — 端口号格式校验（1-65535，纯整数）
#   validate_password  — 密码字符校验（1-128 字符，禁止 " \ $ ` 及控制字符）
#   validate_domain    — 域名格式校验（纯 alnum/dot/hyphen，无协议/端口）
#   filter_ipv6_addrs  — IPv6 地址过滤（排除 WARP/tunnel/fe80/CF-WARP 段）
#   validate_binary    — 二进制有效性验证（ELF magic 或 version 子命令）
#
# 兼容性要求：
#   - 不使用 bash 4.x+ 专有语法（大小写展开、grep 扩展正则、
#     字节截取、关联数组等）
#   - 所有文本处理使用 POSIX 兼容的 tr / awk / sed
#   - 适用于 busybox 环境
# =============================================================================

# Guard: 防止重复 source
[ -n "${_VALIDATORS_BASH_LOADED:-}" ] && return 0
_VALIDATORS_BASH_LOADED=1

# =============================================================================
# validate_port PORT
#
# 验证端口号字符串是否合法：
#   - 纯数字字符串（不含前导/尾随空格、小数点、符号）
#   - 数值范围 [1, 65535]
#
# 测试版本说明：不执行端口占用检查（ss/netstat），仅做格式与范围校验。
# 生产版本可在此函数末尾添加端口占用检测逻辑。
#
# 返回：0 = 合法；1 = 不合法
# =============================================================================
validate_port() {
    local port="$1"

    # 必须是非空字符串
    [ -z "$port" ] && return 1

    # 必须全为数字（禁止 +/-/空格/小数点）
    case "$port" in
        *[!0-9]*) return 1 ;;
    esac

    # 禁止前导零（"007" 不合法；"0" 本身也不合法，超出 1-65535 范围）
    case "$port" in
        0*)  return 1 ;;
    esac

    # 数值范围 [1, 65535]
    # 使用 awk 避免 bash 算术对超长字符串的溢出问题
    awk -v p="$port" 'BEGIN { exit (p >= 1 && p <= 65535) ? 0 : 1 }'
    return $?
}

# =============================================================================
# validate_password PASSWORD
#
# 验证密码字符串是否合法：
#   - 长度 [1, 128] 字符
#   - 不含以下字符：
#       双引号 (")
#       反斜杠 (\)
#       美元符 ($)
#       反引号 (`)
#   - 不含 ASCII 控制字符（0x00-0x1F，即 [:cntrl:] 的前 32 个）及 DEL (0x7F)
#
# 实现说明：
#   - 使用 printf + awk 检测禁止字符，兼容 busybox
#   - 0x7F (DEL) 需单独检测，[:cntrl:] 在部分 awk 实现中已包含它，
#     但显式检测更可靠
#
# 返回：0 = 合法；1 = 不合法
# =============================================================================
validate_password() {
    local pw="$1"

    # 长度 [1, 128]
    local len
    len=$(printf '%s' "$pw" | awk '{ print length }')
    [ "$len" -lt 1 ] && return 1
    [ "$len" -gt 128 ] && return 1

    # 检测禁止字符：" \ $ ` 和控制字符（含 DEL 0x7F）
    # 使用 printf '%s' 避免 echo 对反斜杠的不一致行为
    # awk gsub 返回替换次数：> 0 表示存在禁止字符
    printf '%s' "$pw" | awk '
    {
        # 检查 " \ $ ` 四个明确禁止字符
        if (index($0, "\"") > 0) { exit 1 }
        if (index($0, "\\") > 0) { exit 1 }
        if (index($0, "$")  > 0) { exit 1 }
        if (index($0, "`")  > 0) { exit 1 }

        # 检查 ASCII 控制字符 (0x00-0x1F) 及 DEL (0x7F)
        # 在 awk 中用字符类 [:cntrl:] 匹配 0x00-0x1F 和 0x7F
        if (match($0, /[[:cntrl:]]/)) { exit 1 }

        exit 0
    }' || return 1

    return 0
}

# =============================================================================
# validate_domain DOMAIN
#
# 验证域名格式是否合法（纯 SNI/伪装域名场景）：
#   - 仅允许字符：字母 (A-Za-z)、数字 (0-9)、点号 (.)、连字符 (-)
#   - 不以点号或连字符开头
#   - 不以点号或连字符结尾
#   - 不含协议前缀（如 http://、https://）
#   - 不含端口号（如 :443）
#   - 不得为空字符串
#
# 返回：0 = 合法；1 = 不合法
# =============================================================================
validate_domain() {
    local domain="$1"

    # 非空
    [ -z "$domain" ] && return 1

    # 禁止含 :// 协议前缀
    case "$domain" in
        *://*) return 1 ;;
    esac

    # 禁止含端口号（冒号后跟数字）
    case "$domain" in
        *:*) return 1 ;;
    esac

    # 仅允许 alnum、点号、连字符
    # 使用 tr 删除合法字符后检查是否还有剩余
    local stripped
    stripped=$(printf '%s' "$domain" | tr -d 'A-Za-z0-9.-')
    [ -n "$stripped" ] && return 1

    # 不以点号或连字符开头
    case "$domain" in
        [.-]*) return 1 ;;
    esac

    # 不以点号或连字符结尾
    local last_char
    last_char=$(printf '%s' "$domain" | awk '{ print substr($0, length($0), 1) }')
    case "$last_char" in
        [.-]) return 1 ;;
    esac

    return 0
}

# =============================================================================
# filter_ipv6_addrs INPUT
#
# 从 `ip -6 addr show scope global` 的输出中提取合法的真实 IPv6 地址，
# 排除以下地址：
#   (a) 来自名称匹配以下模式的虚拟/隧道网卡：
#         wgcf, warp, tun*, wg*, tailscale, zt*
#   (b) 以 fe80 开头的链路本地地址
#   (c) 以 2606:4700: 开头的 Cloudflare WARP 地址段
#
# 参数：
#   INPUT — `ip -6 addr show scope global` 的完整输出文本（字符串）
#           如果省略，则从 stdin 读取
#
# 输出：每行一个过滤后的 IPv6 地址（去掉前缀长度 /xxx）
#
# 返回：0（即使结果为空也返回 0，调用方自行判断是否有地址）
# =============================================================================
filter_ipv6_addrs() {
    local input
    if [ $# -gt 0 ]; then
        input="$1"
        printf '%s\n' "$input"
    else
        cat
    fi | awk '
        /^[0-9]+:/ {
            # 解析网卡名：格式 "N: ethN: <FLAGS>"
            iface = $2
            sub(/:.*/, "", iface)
        }
        /inet6/ {
            # 过滤网卡名：wgcf|warp|tun*|wg*|tailscale|zt*
            if (iface ~ /^(wgcf|warp)$/ ||
                iface ~ /^tun/          ||
                iface ~ /^wg/           ||
                iface ~ /^tailscale/    ||
                iface ~ /^zt/) {
                next
            }

            # 提取地址，去掉 /前缀长度
            addr = $2
            sub(/\/.*/, "", addr)

            # 排除链路本地 fe80
            if (addr ~ /^fe80/) { next }

            # 排除 Cloudflare WARP 段 2606:4700:
            if (addr ~ /^2606:4700:/) { next }

            print addr
        }
    '
}

# =============================================================================
# validate_binary FILE
#
# 验证下载的二进制文件是否为有效的可执行文件：
#
# 判定为有效的条件（满足其一即可）：
#   (a) 文件前 4 字节为 ELF magic bytes：0x7F 'E' 'L' 'F'
#       通过 od 读取并比较（避免依赖 GNU head 字节模式）
#   (b) 以 "FILE version" 方式调用，退出码为 0
#
# 此函数不修改文件权限，调用方需确保文件已具备可执行权限（chmod +x）
# 才能走路径 (b)。
#
# 返回：0 = 有效；1 = 无效
# =============================================================================
validate_binary() {
    local file="$1"

    # 文件必须存在且非空
    [ -z "$file" ] && return 1
    [ -f "$file" ] || return 1
    [ -s "$file" ] || return 1

    # ── 方法 (a): 检查 ELF magic bytes ──────────────────────────────────────
    # ELF magic: 0x7F 0x45 0x4C 0x46 (即 \x7fELF)
    # 八进制值：177 105 114 106
    # od -A d -t x1 读取前 4 字节，取第一行前4个十六进制字节判断
    # 使用 od 兼容 busybox，不依赖 GNU head 字节截取模式
    local magic
    magic=$(od -A d -t x1 -N 4 "$file" 2>/dev/null | awk 'NR==1 { print $2, $3, $4, $5 }')
    if [ "$magic" = "7f 45 4c 46" ]; then
        return 0
    fi

    # ── 方法 (b): 执行 version 子命令 ────────────────────────────────────────
    # 需要文件可执行；若 ELF 检查失败则尝试此路径
    if [ -x "$file" ]; then
        "$file" version >/dev/null 2>&1 && return 0
    fi

    return 1
}
