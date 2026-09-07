#!/bin/bash
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
trap 'echo "restore validation failed at line $LINENO" >&2' ERR

# install.sh 无库模式开关，抽取被测函数在隔离环境中验证。
lib=$(mktemp)
awk '
  /^RESTORE_ALLOWED_PREFIX=/,/^}$/ { print; next }
  /^validate_backup_archive\(\) \{$/,/^}$/ { print }
' install.sh > "$lib"
# 颜色变量在抽取片段外，补齐以免未定义。
printf 'RED=""; GREEN=""; YELLOW=""; PLAIN=""; WHITE=""; BOLD=""\n' >> "$lib"
. "$lib"
rm -f "$lib"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/src/etc/sing-box" "$tmp/src/etc/hysteria"
printf '{}' > "$tmp/src/etc/sing-box/vless.json"
printf 'listen: :443\n' > "$tmp/src/etc/hysteria/config.yaml"
( cd "$tmp/src" && tar -czf "$tmp/good.tar.gz" etc )

# 正常备份必须通过。
validate_backup_archive "$tmp/good.tar.gz"

# 截断归档必须在解包前被拒绝：直接解包会写入一半后失败，留下半还原状态。
sz=$(stat -c %s "$tmp/good.tar.gz")
dd if="$tmp/good.tar.gz" of="$tmp/trunc.tar.gz" bs=1 count=$((sz * 60 / 100)) 2>/dev/null
! validate_backup_archive "$tmp/trunc.tar.gz" >/dev/null 2>&1

# 非 gzip / 非 tar 文件必须拒绝。
printf 'not an archive' > "$tmp/bad.tar.gz"
! validate_backup_archive "$tmp/bad.tar.gz" >/dev/null 2>&1

# 空归档必须拒绝。
( cd "$tmp" && tar -czf "$tmp/empty.tar.gz" -T /dev/null 2>/dev/null )
! validate_backup_archive "$tmp/empty.tar.gz" >/dev/null 2>&1

# 越界成员必须拒绝 —— 该函数以 root 身份解到 /，放行等于任意文件写入。
mkdir -p "$tmp/evil/etc" "$tmp/evil/home"
printf 'x' > "$tmp/evil/etc/ok"
printf 'x' > "$tmp/evil/home/pwned"
( cd "$tmp/evil" && tar -czf "$tmp/outside.tar.gz" etc home )
! validate_backup_archive "$tmp/outside.tar.gz" >/dev/null 2>&1

# 绝对路径成员必须拒绝。
( cd "$tmp/src" && tar -czf "$tmp/abs.tar.gz" -P /etc/hostname etc 2>/dev/null ) || true
if tar -tzf "$tmp/abs.tar.gz" 2>/dev/null | grep -q '^/'; then
    ! validate_backup_archive "$tmp/abs.tar.gz" >/dev/null 2>&1
fi

# .. 成员必须拒绝。
mkdir -p "$tmp/dots/etc"
printf 'x' > "$tmp/dots/etc/ok"
( cd "$tmp/dots/etc" && tar -czf "$tmp/dots.tar.gz" ../etc/ok 2>/dev/null ) || true
if tar -tzf "$tmp/dots.tar.gz" 2>/dev/null | grep -q '\.\.'; then
    ! validate_backup_archive "$tmp/dots.tar.gz" >/dev/null 2>&1
fi

# run_script 下载并校验成功后必须把脚本落盘为缓存，否则远程不可达时的
# 兜底只对手动刷新过缓存的用户有效 —— 而多数人从未执行过那个菜单项。
grep -q 'mv -f "${_cache}.tmp" "$_cache"' install.sh
# 缓存写入失败不得影响本次运行。
grep -q 'if mkdir -p "$SCRIPT_CACHE_DIR" 2>/dev/null; then' install.sh

echo 'Restore validation passed.'
