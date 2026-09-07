#!/bin/bash
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
for proto in hy2 ss; do
  src="${proto}.sh"
  au=$(mktemp)
  awk '/cat > "\$AUTO_UPDATE_SCRIPT" <<'\''AUTOUPDATE_EOF'\''/{c=1;next} c&&/^AUTOUPDATE_EOF$/{exit} c' "$src" > "$au"
  # 只加载函数，不执行 main
  lib=$(mktemp)
  awk '/^_norm_tag\(\) \{$/,/^}$/ { print } /^get_latest\(\) \{$/,/^}$/ { print }' "$au" > "$lib"
  echo "=== $proto ==="
  (
    . "$lib"
    # 1) API 可用
    curl() { case " $* " in *' https://api.github.com/'*) [ "$1" = "-fsSL" ] && printf '{"tag_name": "%s"}' "$TAG" ;; *) return 1 ;; esac; }
    if [ "$proto" = hy2 ]; then TAG="app/v2.6.1"; exp="app/v2.6.1|v2.6.1"; else TAG="v1.23.1"; exp="v1.23.1"; fi
    got=$(get_latest); [ "$got" = "$exp" ] && echo "  ✓ API 可用: $got" || { echo "  ✗ API 路径: 期望[$exp] 得到[$got]"; exit 1; }

    # 2) API 限频 + github.com 不可达 -> 镜像重定向（此前这里直接放弃）
    curl() {
      case " $* " in
        *' https://api.github.com/'*) return 1 ;;
        *' https://github.com/'*'/releases/latest '*) printf '%s' "$ORIG" ;;
        *' https://kkgithub.com/'*'/releases/latest '*) printf '%s' "$MIRROR" ;;
        *) return 1 ;;
      esac
    }
    if [ "$proto" = hy2 ]; then
      ORIG="https://github.com/apernet/hysteria/releases/latest"
      MIRROR="https://kkgithub.com/apernet/hysteria/releases/tag/app/v2.6.2"; exp="app/v2.6.2|v2.6.2"
    else
      ORIG="https://github.com/shadowsocks/shadowsocks-rust/releases/latest"
      MIRROR="https://kkgithub.com/shadowsocks/shadowsocks-rust/releases/tag/v1.23.2"; exp="v1.23.2"
    fi
    got=$(get_latest); [ "$got" = "$exp" ] && echo "  ✓ 限频后走镜像: $got" || { echo "  ✗ 镜像路径: 期望[$exp] 得到[$got]"; exit 1; }

    # 3) 全部只回原始 URL -> 必须判空，绝不能把 URL 当版本号
    curl() { case " $* " in *' https://api.github.com/'*) return 1 ;; *'/releases/latest '*) printf '%s' "$ORIG" ;; *) return 1 ;; esac; }
    got=$(get_latest)
    case "$got" in
      *http*) echo "  ✗ 脏 tag 泄漏: [$got]"; exit 1 ;;
      *) echo "  ✓ 脏 tag 被拒，返回空值 [$got]" ;;
    esac

    # 4) 全部失败 -> 空值，main 会据此跳过
    curl() { return 1; }
    got=$(get_latest)
    case "$got" in
      ''|'|') echo "  ✓ 全失败返回空，main 将跳过更新" ;;
      *) echo "  ✗ 全失败却返回 [$got]"; exit 1 ;;
    esac
  )
  rm -f "$au" "$lib"
done
echo 'Auto-update validation passed.'
