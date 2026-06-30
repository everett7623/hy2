#!/usr/bin/env bash
# tests/helpers/generators.bash
# Random input generators for bats-core property-based tests.
#
# Usage: source this file in .bats test files.
# All generators are POSIX-compatible (bash 3.x+, busybox-safe).
# Avoids bash 4.x+ syntax: no case-transform expansions, no grep -P patterns,
# no head byte-count, no readarray/mapfile, no associative arrays.
#
# Feature: bugfix-optimize-anytls
# Requirements: 1.3, 1.4, 7.4, 3.1, 4.2

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# _rand_int MIN MAX
# Outputs a random integer in [MIN, MAX].
_rand_int() {
    local min="$1" max="$2"
    local range=$(( max - min + 1 ))
    echo $(( (RANDOM * RANDOM + RANDOM) % range + min ))
}

# _rand_bytes N
# Outputs N random bytes (via /dev/urandom) as a raw octet stream to stdout.
# Falls back to RANDOM-based generation if /dev/urandom is unavailable.
_rand_bytes() {
    local n="$1"
    if [ -r /dev/urandom ]; then
        dd if=/dev/urandom bs=1 count="$n" 2>/dev/null
    else
        # Fallback: generate n random single bytes using printf
        local i=0
        while [ "$i" -lt "$n" ]; do
            printf "\\$(printf '%03o' $(( RANDOM % 256 )))"
            i=$(( i + 1 ))
        done
    fi
}

# _rand_printable_char
# Outputs one random printable ASCII character (0x20-0x7E) excluding
# the four forbidden chars: " \ $ `
_rand_printable_char() {
    local c
    while true; do
        c=$(( RANDOM % 95 + 32 ))
        # Exclude: 34=", 36=$, 92=\, 96=`
        if [ "$c" -ne 34 ] && [ "$c" -ne 36 ] && [ "$c" -ne 92 ] && [ "$c" -ne 96 ]; then
            printf "\\$(printf '%03o' "$c")"
            return
        fi
    done
}

# _rand_alpha_char
# Outputs one random ASCII letter (a-z or A-Z).
_rand_alpha_char() {
    local pool="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    local idx=$(( RANDOM % 52 ))
    printf '%s' "$(echo "$pool" | cut -c$(( idx + 1 )))"
}

# _rand_alnum_char
# Outputs one random ASCII alphanumeric character (a-z, A-Z, 0-9).
_rand_alnum_char() {
    local pool="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    local idx=$(( RANDOM % 62 ))
    printf '%s' "$(echo "$pool" | cut -c$(( idx + 1 )))"
}

# _rand_alnum_or_hyphen
# Outputs one random character from [a-zA-Z0-9-] (for domain labels).
_rand_alnum_or_hyphen() {
    local pool="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"
    local idx=$(( RANDOM % 63 ))
    printf '%s' "$(echo "$pool" | cut -c$(( idx + 1 )))"
}

# _rand_domain_label LEN
# Outputs a random domain label of LEN chars: starts/ends with alnum, middle
# chars are alnum or hyphen.
_rand_domain_label() {
    local len="${1:-6}"
    if [ "$len" -lt 1 ]; then
        len=1
    fi
    if [ "$len" -eq 1 ]; then
        _rand_alnum_char
        return
    fi
    local result
    result="$(_rand_alnum_char)"
    local i=1
    while [ "$i" -lt $(( len - 1 )) ]; do
        result="${result}$(_rand_alnum_or_hyphen)"
        i=$(( i + 1 ))
    done
    result="${result}$(_rand_alnum_char)"
    printf '%s' "$result"
}

# ---------------------------------------------------------------------------
# 1. Port number generators
# ---------------------------------------------------------------------------
# Requirements: 1.3

# gen_valid_port
# Outputs a random valid port number in [1, 65535].
gen_valid_port() {
    _rand_int 1 65535
}

# gen_valid_port_boundary
# Outputs one of the boundary valid port values: 1 or 65535.
gen_valid_port_boundary() {
    if [ $(( RANDOM % 2 )) -eq 0 ]; then
        echo 1
    else
        echo 65535
    fi
}

# gen_invalid_port_zero
# Outputs the out-of-range port 0.
gen_invalid_port_zero() {
    echo 0
}

# gen_invalid_port_too_large
# Outputs a port number > 65535.
gen_invalid_port_too_large() {
    _rand_int 65536 99999
}

# gen_invalid_port_negative
# Outputs a negative number formatted as a string.
gen_invalid_port_negative() {
    echo "-$(_rand_int 1 9999)"
}

# gen_invalid_port_float
# Outputs a floating-point string (invalid port).
gen_invalid_port_float() {
    echo "$(_rand_int 1 1000).$(_rand_int 0 99)"
}

# gen_invalid_port_alpha
# Outputs a string mixing digits and letters (invalid port).
gen_invalid_port_alpha() {
    local n=$(_rand_int 1 999)
    local letters="abcxyz"
    local idx=$(( RANDOM % 6 ))
    local c=$(echo "$letters" | cut -c$(( idx + 1 )))
    echo "${n}${c}"
}

# gen_invalid_port_empty
# Outputs an empty string (invalid port).
gen_invalid_port_empty() {
    printf ''
}

# gen_invalid_port_leading_zero
# Outputs a port with a leading zero (e.g. "0443"), which is invalid as a
# decimal integer representation.
gen_invalid_port_leading_zero() {
    local n=$(_rand_int 1 9999)
    echo "0${n}"
}

# gen_any_port
# Outputs a random port input (mix of valid and invalid), plus its expected
# validity on stdout in the format "PORT VALID" where VALID is 0 (valid) or 1
# (invalid).
gen_any_port() {
    local choice=$(( RANDOM % 8 ))
    case "$choice" in
        0) printf '%s valid\n' "$(gen_valid_port)" ;;
        1) printf '%s valid\n' "$(gen_valid_port_boundary)" ;;
        2) printf '%s invalid\n' "$(gen_invalid_port_zero)" ;;
        3) printf '%s invalid\n' "$(gen_invalid_port_too_large)" ;;
        4) printf '%s invalid\n' "$(gen_invalid_port_negative)" ;;
        5) printf '%s invalid\n' "$(gen_invalid_port_float)" ;;
        6) printf '%s invalid\n' "$(gen_invalid_port_alpha)" ;;
        7) printf '%s invalid\n' "$(gen_invalid_port_leading_zero)" ;;
    esac
}

# ---------------------------------------------------------------------------
# 2. Password generators
# ---------------------------------------------------------------------------
# Requirements: 1.4

# gen_valid_password [LEN]
# Outputs a random valid password of LEN chars (default: random 1-128).
# Characters: printable ASCII, excluding " \ $ ` and control chars.
gen_valid_password() {
    local len="${1:-}"
    if [ -z "$len" ]; then
        len=$(_rand_int 1 128)
    fi
    local result=""
    local i=0
    while [ "$i" -lt "$len" ]; do
        result="${result}$(_rand_printable_char)"
        i=$(( i + 1 ))
    done
    printf '%s' "$result"
}

# gen_valid_password_boundary
# Outputs a valid password of length exactly 1 or exactly 128.
gen_valid_password_boundary() {
    if [ $(( RANDOM % 2 )) -eq 0 ]; then
        gen_valid_password 1
    else
        gen_valid_password 128
    fi
}

# gen_invalid_password_empty
# Outputs an empty string (invalid: length < 1).
gen_invalid_password_empty() {
    printf ''
}

# gen_invalid_password_too_long
# Outputs a password of length 129-256 (invalid: exceeds 128).
gen_invalid_password_too_long() {
    local len=$(_rand_int 129 256)
    gen_valid_password "$len"
}

# gen_invalid_password_with_dquote
# Outputs a password containing a double-quote character.
gen_invalid_password_with_dquote() {
    local half=$(_rand_int 1 30)
    local left=$(gen_valid_password "$half")
    local right=$(gen_valid_password "$half")
    printf '%s"%s' "$left" "$right"
}

# gen_invalid_password_with_backslash
# Outputs a password containing a backslash character.
gen_invalid_password_with_backslash() {
    local half=$(_rand_int 1 30)
    local left=$(gen_valid_password "$half")
    local right=$(gen_valid_password "$half")
    printf '%s\\%s' "$left" "$right"
}

# gen_invalid_password_with_dollar
# Outputs a password containing a dollar sign.
gen_invalid_password_with_dollar() {
    local half=$(_rand_int 1 30)
    local left=$(gen_valid_password "$half")
    local right=$(gen_valid_password "$half")
    printf '%s$%s' "$left" "$right"
}

# gen_invalid_password_with_backtick
# Outputs a password containing a backtick.
gen_invalid_password_with_backtick() {
    local half=$(_rand_int 1 30)
    local left=$(gen_valid_password "$half")
    local right=$(gen_valid_password "$half")
    printf '%s`%s' "$left" "$right"
}

# gen_invalid_password_with_control
# Outputs a password containing a control character (0x01-0x1F).
gen_invalid_password_with_control() {
    local half=$(_rand_int 1 30)
    local left=$(gen_valid_password "$half")
    local right=$(gen_valid_password "$half")
    local ctrl=$(( RANDOM % 31 + 1 ))
    printf '%s' "$left"
    printf "\\$(printf '%03o' "$ctrl")"
    printf '%s' "$right"
}

# gen_invalid_password_with_del
# Outputs a password containing the DEL character (0x7F).
gen_invalid_password_with_del() {
    local half=$(_rand_int 1 30)
    local left=$(gen_valid_password "$half")
    local right=$(gen_valid_password "$half")
    printf '%s' "$left"
    printf '\177'
    printf '%s' "$right"
}

# ---------------------------------------------------------------------------
# 3. Domain name generators
# ---------------------------------------------------------------------------
# Requirements: 7.4

# gen_valid_domain
# Outputs a random valid domain name (labels joined by dots, no protocol/port).
gen_valid_domain() {
    local num_labels=$(_rand_int 1 4)
    local domain=""
    local i=0
    while [ "$i" -lt "$num_labels" ]; do
        local label_len=$(_rand_int 1 10)
        local label
        label=$(_rand_domain_label "$label_len")
        if [ "$i" -eq 0 ]; then
            domain="$label"
        else
            domain="${domain}.${label}"
        fi
        i=$(( i + 1 ))
    done
    printf '%s' "$domain"
}

# gen_invalid_domain_http_prefix
# Outputs a domain with an http:// prefix (invalid).
gen_invalid_domain_http_prefix() {
    printf 'http://%s' "$(gen_valid_domain)"
}

# gen_invalid_domain_https_prefix
# Outputs a domain with an https:// prefix (invalid).
gen_invalid_domain_https_prefix() {
    printf 'https://%s' "$(gen_valid_domain)"
}

# gen_invalid_domain_with_port
# Outputs a domain with a :PORT suffix (invalid).
gen_invalid_domain_with_port() {
    local port=$(_rand_int 1 65535)
    printf '%s:%d' "$(gen_valid_domain)" "$port"
}

# gen_invalid_domain_leading_dot
# Outputs a domain starting with a dot (invalid).
gen_invalid_domain_leading_dot() {
    printf '.%s' "$(gen_valid_domain)"
}

# gen_invalid_domain_trailing_dot
# Outputs a domain ending with a dot (invalid).
gen_invalid_domain_trailing_dot() {
    printf '%s.' "$(gen_valid_domain)"
}

# gen_invalid_domain_leading_hyphen
# Outputs a label starting with a hyphen (invalid).
gen_invalid_domain_leading_hyphen() {
    printf '-%s' "$(gen_valid_domain)"
}

# gen_invalid_domain_trailing_hyphen
# Outputs a label ending with a hyphen (invalid).
gen_invalid_domain_trailing_hyphen() {
    printf '%s-' "$(gen_valid_domain)"
}

# gen_invalid_domain_special_chars
# Outputs a domain containing special characters (!, @, #, etc.).
gen_invalid_domain_special_chars() {
    local specials="!@#%^&*()_+=[]{}|;'<>,?"
    local idx=$(( RANDOM % 25 ))
    local sc=$(echo "$specials" | cut -c$(( idx + 1 )))
    local base=$(gen_valid_domain)
    printf '%s%s' "$base" "$sc"
}

# gen_invalid_domain_empty
# Outputs an empty string (invalid domain).
gen_invalid_domain_empty() {
    printf ''
}

# gen_invalid_domain_space
# Outputs a domain containing a space (invalid).
gen_invalid_domain_space() {
    printf '%s %s' "$(gen_valid_domain)" "$(gen_valid_domain)"
}

# ---------------------------------------------------------------------------
# 4. Mock `ip addr` output generators
# ---------------------------------------------------------------------------
# Requirements: 3.1

# _ip_addr_iface_block IFACE INET6_ADDR [SCOPE]
# Outputs a minimal `ip addr` block for the given interface and IPv6 address.
_ip_addr_iface_block() {
    local iface="$1" addr="$2" scope="${3:-global}"
    printf '2: %s: <BROADCAST,MULTICAST,UP,LOWER_UP>\n' "$iface"
    printf '    inet6 %s/64 scope %s\n' "$addr" "$scope"
    printf '       valid_lft forever preferred_lft forever\n'
}

# gen_ip_addr_warp
# Outputs a mock `ip addr` block for a WARP/wgcf interface with a WARP
# Cloudflare address (2606:4700: prefix).
gen_ip_addr_warp() {
    local iface
    case $(( RANDOM % 3 )) in
        0) iface="wgcf" ;;
        1) iface="warp0" ;;
        2) iface="wg0" ;;
    esac
    _ip_addr_iface_block "$iface" "2606:4700:110:8949:4b2:c7ff:fee5:bcc0" global
}

# gen_ip_addr_tunnel
# Outputs a mock `ip addr` block for a tunnel interface (tun0, tailscale0, zt*).
gen_ip_addr_tunnel() {
    local iface
    case $(( RANDOM % 4 )) in
        0) iface="tun0" ;;
        1) iface="tun1" ;;
        2) iface="tailscale0" ;;
        3) iface="ztabcdef01" ;;
    esac
    local last=$(( RANDOM % 65535 ))
    local addr="fd12:3456:789a:$(printf '%04x' "$last")::1"
    _ip_addr_iface_block "$iface" "$addr" global
}

# gen_ip_addr_fe80
# Outputs a mock `ip addr` block with a fe80 link-local address.
gen_ip_addr_fe80() {
    local iface="eth0"
    local word=$(printf '%04x' $(( RANDOM % 65535 )))
    local addr="fe80::${word}:1ff:fe${word}:${word}"
    _ip_addr_iface_block "$iface" "$addr" link
}

# gen_ip_addr_global_real
# Outputs a mock `ip addr` block with a legitimate global IPv6 address
# (not WARP, not fe80, not WARP Cloudflare range).
gen_ip_addr_global_real() {
    local iface="eth0"
    # Use a non-Cloudflare-WARP prefix: 2001:db8 for docs, but for testing
    # use a realistic-looking global unicast prefix (non-2606:4700:).
    local a=$(printf '%04x' $(( RANDOM % 65535 + 1 )))
    local b=$(printf '%04x' $(( RANDOM % 65535 + 1 )))
    local c=$(printf '%04x' $(( RANDOM % 65535 + 1 )))
    local d=$(printf '%04x' $(( RANDOM % 65535 + 1 )))
    # Avoid 2606:4700 and fe80 prefixes
    local prefix="2a0${a:0:1}"
    local addr="${prefix}:${a}:${b}:${c}::${d}"
    _ip_addr_iface_block "$iface" "$addr" global
}

# gen_ip_addr_mixed
# Outputs a combined mock `ip addr` output containing all types:
# a real global address, a WARP address, a fe80 address, and a tunnel address.
# The real global address should be the ONLY one that passes IPv6 filtering.
gen_ip_addr_mixed() {
    gen_ip_addr_global_real
    gen_ip_addr_warp
    gen_ip_addr_fe80
    gen_ip_addr_tunnel
}

# gen_ip_addr_only_filtered
# Outputs a mock `ip addr` output where ALL addresses should be filtered out
# (WARP + fe80 + tunnel only, no real global address).
gen_ip_addr_only_filtered() {
    gen_ip_addr_warp
    gen_ip_addr_fe80
    gen_ip_addr_tunnel
}

# gen_ip_addr_multiple_real
# Outputs a mock `ip addr` output with N (1-3) real global addresses plus
# filtered ones. All N real addresses should survive IPv6 filtering.
gen_ip_addr_multiple_real() {
    local n=$(_rand_int 1 3)
    local i=0
    while [ "$i" -lt "$n" ]; do
        # Use different iface names to simulate multiple physical interfaces
        local iface="eth${i}"
        local a=$(printf '%04x' $(( RANDOM % 65535 + 1 )))
        local b=$(printf '%04x' $(( RANDOM % 65535 + 1 )))
        local c=$(printf '%04x' $(( RANDOM % 65535 + 1 )))
        local d=$(printf '%04x' $(( RANDOM % 65535 + 1 )))
        local prefix="2a0${a:0:1}"
        local addr="${prefix}:${a}:${b}:${c}::${d}"
        printf '2: %s: <BROADCAST,MULTICAST,UP,LOWER_UP>\n' "$iface"
        printf '    inet6 %s/64 scope global\n' "$addr"
        printf '       valid_lft forever preferred_lft forever\n'
        i=$(( i + 1 ))
    done
    gen_ip_addr_warp
    gen_ip_addr_fe80
}

# ---------------------------------------------------------------------------
# 5. Random ELF / non-ELF file content generators
# ---------------------------------------------------------------------------
# Requirements: 4.2

# gen_elf_header_bytes
# Outputs the ELF magic 4 bytes followed by 60 zero bytes to stdout (raw).
# This simulates the beginning of a minimal ELF file.
gen_elf_header_bytes() {
    printf '\177ELF'
    # Output 60 null bytes to simulate ELF header continuation
    local i=0
    while [ "$i" -lt 60 ]; do
        printf '\000'
        i=$(( i + 1 ))
    done
}

# gen_elf_file PATH
# Creates a file at PATH with a valid ELF magic header (first 4 bytes = \x7fELF).
gen_elf_file() {
    local path="$1"
    gen_elf_header_bytes > "$path"
}

# gen_non_elf_random_file PATH
# Creates a file at PATH with random bytes that do NOT start with \x7fELF.
gen_non_elf_random_file() {
    local path="$1"
    # Start with a non-ELF first byte (e.g. 0x00 or a random non-0x7f byte)
    # to ensure it won't accidentally be ELF magic.
    printf '\000\001\002\003' > "$path"
    # Append some more random-looking bytes
    local i=0
    while [ "$i" -lt 60 ]; do
        printf "\\$(printf '%03o' $(( RANDOM % 127 + 1 )))" >> "$path"
        i=$(( i + 1 ))
    done
}

# gen_html_error_file PATH
# Creates a file at PATH mimicking an HTML error page (e.g. GitHub 404),
# which is NOT a valid ELF binary.
gen_html_error_file() {
    local path="$1"
    cat > "$path" <<'HTML_EOF'
<!DOCTYPE html>
<html>
<head><title>404 Not Found</title></head>
<body><h1>404 Not Found</h1><p>The requested resource was not found.</p></body>
</html>
HTML_EOF
}

# gen_empty_file PATH
# Creates an empty file at PATH (0 bytes). Not a valid ELF binary.
gen_empty_file() {
    local path="$1"
    : > "$path"
}

# gen_truncated_elf_file PATH
# Creates a file at PATH with only the first 2 bytes of an ELF magic
# (truncated download scenario). Should NOT pass ELF validation since the
# full 4-byte magic is incomplete.
gen_truncated_elf_file() {
    local path="$1"
    printf '\177E' > "$path"
}
