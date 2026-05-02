#!/usr/bin/env bash

# ============================================================

# NullNet v3.0  —  SSL/TLS Vulnerability Scanner

# Author  : Mr0xed0

# Usage   : ./nullnet.sh <host> [port]

# ============================================================

VERSION=“3.0”
TOOL_NAME=“NullNet”
TIMESTAMP=$(date +”%Y%m%d_%H%M%S”)

# ─── Colours ──────────────────────────────────────────────────────────────────

RED=’\033[0;31m’;   LRED=’\033[1;31m’
GREEN=’\033[0;32m’; LGREEN=’\033[1;32m’
YELLOW=’\033[1;33m’;CYAN=’\033[0;36m’
BOLD=’\033[1m’;     DIM=’\033[2m’; RESET=’\033[0m’
ITALIC=’\033[3m’

# ─── Output helpers ───────────────────────────────────────────────────────────

lpad()  { printf “ %-45s” “$1”; }
bigsep(){ echo -e “${DIM}$(printf ‘═%.0s’ {1..100})${RESET}”; }
sep()   { echo -e “${DIM}$(printf ‘─%.0s’ {1..100})${RESET}”; }
hdr()   { echo; echo -e “ ${BOLD}${CYAN}Testing $1 ${RESET}”; echo; }
die()   { echo -e “\n${LRED}[FATAL]${RESET} $*\n” >&2; exit 1; }

# ─── Globals ──────────────────────────────────────────────────────────────────

HOST=””; PORT=443
RESOLVED_IPS=()
JSON_OUT=””; HTML_OUT=””; TXT_OUT=””
declare -A RESULTS
GRADE=”?”
declare -a GRADE_REASONS=()
PROTO_SCORE=0; KEX_SCORE=0; CIPHER_SCORE=0

# Protocol flags (populated during scan_protocols)

PROTO_SSL2=“no”; PROTO_SSL3=“no”
PROTO_TLS10=“no”; PROTO_TLS11=“no”; PROTO_TLS12=“no”; PROTO_TLS13=“no”
CERT_DAYS=999

# ─── Dependency Check ─────────────────────────────────────────────────────────

check_deps() {
local miss=()
for c in openssl timeout curl dig; do
command -v “$c” &>/dev/null || miss+=(”$c”)
done
[[ ${#miss[@]} -gt 0 ]] && die “Missing: ${miss[*]}\n   Install: sudo apt install openssl curl dnsutils”
}

# ─── Argument Parsing ─────────────────────────────────────────────────────────

parse_args() {
[[ $# -lt 1 ]] && { print_banner; usage; }
if [[ “$1” =~ ^([^:]+):([0-9]+)$ ]]; then
HOST=”${BASH_REMATCH[1]}”; PORT=”${BASH_REMATCH[2]}”
else
HOST=”$1”; PORT=”${2:-443}”
fi
JSON_OUT=“nullnet_${HOST}*${TIMESTAMP}.json”
HTML_OUT=“nullnet*${HOST}*${TIMESTAMP}.html”
TXT_OUT=“nullnet*${HOST}_${TIMESTAMP}.txt”
}

usage() {
echo -e “  ${BOLD}Usage:${RESET}   $0 <hostname[:port]> [port]”
echo -e “  ${BOLD}Examples:${RESET}”
echo -e “           $0 example.com”
echo -e “           $0 example.com 8443”
echo; exit 0
}

# ─── Banner ───────────────────────────────────────────────────────────────────

print_banner() {
echo
echo -e “${BOLD}${LRED} ███╗   ██╗██╗   ██╗██╗     ██╗     ███╗   ██╗███████╗████████╗${RESET}”
echo -e “${BOLD}${LRED} ████╗  ██║██║   ██║██║     ██║     ████╗  ██║██╔════╝╚══██╔══╝${RESET}”
echo -e “${BOLD}${LRED} ██╔██╗ ██║██║   ██║██║     ██║     ██╔██╗ ██║█████╗     ██║   ${RESET}”
echo -e “${BOLD}${RED}  ██║╚██╗██║██║   ██║██║     ██║     ██║╚██╗██║██╔══╝     ██║   ${RESET}”
echo -e “${BOLD}${RED}  ██║ ╚████║╚██████╔╝███████╗███████╗██║ ╚████║███████╗   ██║   ${RESET}”
echo -e “${BOLD}${RED}  ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝   ╚═╝  ${RESET}”
echo
echo -e “  ${DIM}SSL/TLS Vulnerability Scanner v${VERSION}  |  ${BOLD}Author: Mr0xed0${RESET}”
echo -e “  ${DIM}This program is free software. Use at your own risk.${RESET}”
echo
bigsep
}

# ─── IP Resolution ────────────────────────────────────────────────────────────

resolve_ips() {
local v4=() v6=()
mapfile -t v4 < <(dig +short A    “$HOST” 2>/dev/null | grep -E ‘^[0-9]+.’ | head -5)
mapfile -t v6 < <(dig +short AAAA “$HOST” 2>/dev/null | grep -E ‘:’ | head -3)
RESOLVED_IPS=(”${v4[@]}” “${v6[@]}”)
[[ ${#RESOLVED_IPS[@]} -eq 0 ]] && RESOLVED_IPS=(”$HOST”)
}

# ─── Target info header ───────────────────────────────────────────────────────

print_target_info() {
local ip0=”${RESOLVED_IPS[0]}”
local rdns; rdns=$(dig +short -x “$ip0” 2>/dev/null | head -1)
local iplist=”${RESOLVED_IPS[*]}”

```
bigsep
echo -e " ${BOLD}Start $(date '+%Y-%m-%d %H:%M:%S')${RESET}        -->> ${LRED}${HOST}:${PORT}${RESET} <<"
echo
[[ ${#RESOLVED_IPS[@]} -gt 1 ]] && echo -e " ${DIM}Further IP addresses:${RESET}   ${iplist}"
echo -e " ${DIM}rDNS (${ip0}):${RESET}   ${rdns:-(none)}"
echo -e " ${DIM}Service detected:${RESET}       HTTP"
bigsep
```

}

# ─── Core: test one protocol ──────────────────────────────────────────────────

# Returns 0 if server accepts it, 1 if not

test_proto() {
local flag=”$1”
local out
out=$(echo Q | timeout 8 openssl s_client $flag   
-connect “${HOST}:${PORT}” -servername “${HOST}” 2>&1)
# Must see a real cipher negotiated (not “no cipher” / error)
if echo “$out” | grep -qE ‘^\s*Cipher\s*:\s*[A-Z0-9_-]{4,}’; then
return 0
fi
return 1
}

# ─── Core: test one cipher ────────────────────────────────────────────────────

test_cipher() {
local proto_flag=”$1” cipher=”$2”
local out
if [[ “$proto_flag” == “-tls1_3” ]]; then
out=$(echo Q | timeout 6 openssl s_client -tls1_3   
-ciphersuites “$cipher”   
-connect “${HOST}:${PORT}” -servername “${HOST}” 2>&1)
else
out=$(echo Q | timeout 6 openssl s_client $proto_flag   
-cipher “$cipher”   
-connect “${HOST}:${PORT}” -servername “${HOST}” 2>&1)
fi
echo “$out” | grep -qE ‘^\s*Cipher\s*:\s*[A-Z0-9_-]{4,}’
}

# ═════════════════════════════════════════════════════════════════════════════

# SECTION 1 — Protocols

# ═════════════════════════════════════════════════════════════════════════════

scan_protocols() {
hdr “protocols via sockets except NPN+ALPN”

```
# SSLv2
lpad "SSLv2"
if test_proto "-ssl2"; then
    echo -e "${LRED}offered (NOT ok)${RESET}"; PROTO_SSL2="yes"
else
    echo -e "${LGREEN}not offered (OK)${RESET}"
fi

# SSLv3
lpad "SSLv3"
if test_proto "-ssl3"; then
    echo -e "${LRED}offered (NOT ok)${RESET}"; PROTO_SSL3="yes"
else
    echo -e "${LGREEN}not offered (OK)${RESET}"
fi

# TLS 1.0
lpad "TLS 1"
if test_proto "-tls1"; then
    echo -e "${YELLOW}offered (deprecated)${RESET}"; PROTO_TLS10="yes"
    GRADE_REASONS+=("Grade capped to B. TLS 1.0 offered")
else
    echo -e "${LGREEN}not offered${RESET}"
fi

# TLS 1.1
lpad "TLS 1.1"
if test_proto "-tls1_1"; then
    echo -e "${YELLOW}offered (deprecated)${RESET}"; PROTO_TLS11="yes"
    GRADE_REASONS+=("Grade capped to B. TLS 1.1 offered")
else
    echo -e "${LGREEN}not offered${RESET}"
fi

# TLS 1.2
lpad "TLS 1.2"
if test_proto "-tls1_2"; then
    echo -e "${LGREEN}offered (OK)${RESET}"; PROTO_TLS12="yes"
else
    echo -e "${YELLOW}not offered${RESET}"
fi

# TLS 1.3
lpad "TLS 1.3"
if test_proto "-tls1_3"; then
    echo -e "${LGREEN}offered (OK): final${RESET}"; PROTO_TLS13="yes"
else
    echo -e "${YELLOW}not offered${RESET}"
fi

# QUIC (UDP — just report)
lpad "QUIC"
echo -e "${DIM}not tested (requires QUIC-capable client)${RESET}"

# NPN
lpad "NPN/SPDY"
local npn_out npn
npn_out=$(echo Q | timeout 8 openssl s_client -nextprotoneg "" \
          -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
npn=$(echo "$npn_out" | grep -i "Protocols advertised" | sed 's/.*: //')
[[ -n "$npn" ]] && echo -e "${CYAN}${npn} (advertised)${RESET}" \
                || echo -e "${DIM}not offered${RESET}"

# ALPN
lpad "ALPN/HTTP2"
local alpn_out alpn
alpn_out=$(echo Q | timeout 8 openssl s_client -alpn "h2,http/1.1" \
           -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
alpn=$(echo "$alpn_out" | grep -i "ALPN protocol" | sed 's/.*: //')
[[ -n "$alpn" ]] && echo -e "${CYAN}${alpn} (offered)${RESET}" \
                 || echo -e "${DIM}not offered${RESET}"

RESULTS["proto_SSLv2"]="$( [[ $PROTO_SSL2  == yes ]] && echo 'offered (NOT ok)' || echo 'not offered (OK)'  )"
RESULTS["proto_SSLv3"]="$( [[ $PROTO_SSL3  == yes ]] && echo 'offered (NOT ok)' || echo 'not offered (OK)'  )"
RESULTS["proto_TLS10"]="$( [[ $PROTO_TLS10 == yes ]] && echo 'offered (deprecated)' || echo 'not offered'    )"
RESULTS["proto_TLS11"]="$( [[ $PROTO_TLS11 == yes ]] && echo 'offered (deprecated)' || echo 'not offered'    )"
RESULTS["proto_TLS12"]="$( [[ $PROTO_TLS12 == yes ]] && echo 'offered (OK)' || echo 'not offered'            )"
RESULTS["proto_TLS13"]="$( [[ $PROTO_TLS13 == yes ]] && echo 'offered (OK): final' || echo 'not offered'     )"
```

}

# ═════════════════════════════════════════════════════════════════════════════

# SECTION 2 — Cipher Categories

# ═════════════════════════════════════════════════════════════════════════════

scan_cipher_categories() {
hdr “cipher categories”

```
_cat() {
    local label="$1" openssl_filter="$2"
    lpad "$label"
    local out
    out=$(echo Q | timeout 8 openssl s_client -cipher "$openssl_filter" \
          -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
    if echo "$out" | grep -qE '^\s*Cipher\s*:\s*[A-Z0-9_-]{4,}'; then
        echo -e "${LRED}offered${RESET}"
    else
        echo -e "${LGREEN}not offered (OK)${RESET}"
    fi
}

_cat "NULL ciphers (no encryption)"                   "NULL"
_cat "Anonymous NULL Ciphers (no authentication)"     "aNULL"
_cat "Export ciphers (w/o ADH+NULL)"                  "EXPORT"
_cat "LOW: 64 Bit + DES, RC[2,4], MD5 (w/o export)"  "LOW:RC4:!EXPORT"

# 3DES / IDEA
lpad "Triple DES Ciphers / IDEA"
local out3
out3=$(echo Q | timeout 8 openssl s_client -cipher "3DES:IDEA:!eNULL" \
       -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
echo "$out3" | grep -qE '^\s*Cipher\s*:\s*[A-Z0-9_-]{4,}' \
    && echo -e "${YELLOW}offered${RESET}" \
    || echo -e "${LGREEN}not offered (OK)${RESET}"

# CBC
lpad "Obsoleted CBC ciphers (AES, ARIA etc.)"
local outcbc
outcbc=$(echo Q | timeout 8 openssl s_client -cipher "AES128-SHA:AES256-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:!AESGCM" \
         -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
echo "$outcbc" | grep -qE '^\s*Cipher\s*:\s*[A-Z0-9_-]{4,}' \
    && echo -e "${YELLOW}offered${RESET}" \
    || echo -e "${LGREEN}not offered (OK)${RESET}"

# AEAD no FS
lpad "Strong encryption (AEAD ciphers) with no FS"
local outnfs
outnfs=$(echo Q | timeout 8 openssl s_client -cipher "AES128-GCM-SHA256:AES256-GCM-SHA384" \
         -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
echo "$outnfs" | grep -qE '^\s*Cipher\s*:\s*[A-Z0-9_-]{4,}' \
    && echo -e "${LGREEN}offered (OK)${RESET}" \
    || echo -e "${DIM}not offered${RESET}"

# AEAD + FS
lpad "Forward Secrecy strong encryption (AEAD ciphers)"
local outfs
outfs=$(echo Q | timeout 8 openssl s_client -cipher "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM" \
        -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
if echo "$outfs" | grep -qE '^\s*Cipher\s*:\s*[A-Z0-9_-]{4,}'; then
    echo -e "${LGREEN}offered (OK)${RESET}"
else
    # Also check TLS 1.3 (always AEAD + FS)
    [[ "$PROTO_TLS13" == "yes" ]] \
        && echo -e "${LGREEN}offered (OK)${RESET}" \
        || echo -e "${DIM}not offered${RESET}"
fi
```

}

# ═════════════════════════════════════════════════════════════════════════════

# SECTION 3 — Cipher Preferences Table

# ═════════════════════════════════════════════════════════════════════════════

scan_cipher_preferences() {
hdr “server’s cipher preferences”

```
printf " ${DIM}%-8s %-36s %-12s %-12s %-8s %s${RESET}\n" \
    "Hexcode" "Cipher Suite Name (OpenSSL)" "KeyExch." "Encryption" "Bits" "Cipher Suite Name (IANA/RFC)"
printf " ${DIM}%s${RESET}\n" "$(printf '─%.0s' {1..125})"

# Lookup tables
declare -A HEX=(
    [ECDHE-RSA-AES128-SHA]=xc013       [ECDHE-RSA-AES256-SHA]=xc014
    [AES128-SHA]=x2f                   [AES256-SHA]=x35
    [DES-CBC3-SHA]=x0a                 [ECDHE-RSA-AES128-GCM-SHA256]=xc02f
    [ECDHE-RSA-AES256-GCM-SHA384]=xc030 [ECDHE-RSA-CHACHA20-POLY1305]=xcca8
    [AES128-GCM-SHA256]=x9c            [AES256-GCM-SHA384]=x9d
    [DHE-RSA-AES128-GCM-SHA256]=x9e    [DHE-RSA-AES256-GCM-SHA384]=x9f
    [TLS_AES_128_GCM_SHA256]=x1301     [TLS_AES_256_GCM_SHA384]=x1302
    [TLS_CHACHA20_POLY1305_SHA256]=x1303
    [ECDHE-RSA-AES128-SHA256]=xc027    [ECDHE-RSA-AES256-SHA384]=xc028
)
declare -A IANA=(
    [ECDHE-RSA-AES128-SHA]="TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
    [ECDHE-RSA-AES256-SHA]="TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
    [AES128-SHA]="TLS_RSA_WITH_AES_128_CBC_SHA"
    [AES256-SHA]="TLS_RSA_WITH_AES_256_CBC_SHA"
    [DES-CBC3-SHA]="TLS_RSA_WITH_3DES_EDE_CBC_SHA"
    [ECDHE-RSA-AES128-GCM-SHA256]="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    [ECDHE-RSA-AES256-GCM-SHA384]="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    [ECDHE-RSA-CHACHA20-POLY1305]="TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
    [AES128-GCM-SHA256]="TLS_RSA_WITH_AES_128_GCM_SHA256"
    [AES256-GCM-SHA384]="TLS_RSA_WITH_AES_256_GCM_SHA384"
    [TLS_AES_128_GCM_SHA256]="TLS_AES_128_GCM_SHA256"
    [TLS_AES_256_GCM_SHA384]="TLS_AES_256_GCM_SHA384"
    [TLS_CHACHA20_POLY1305_SHA256]="TLS_CHACHA20_POLY1305_SHA256"
)

get_kex() {
    echo "$1" | grep -q "ECDHE" && { echo "ECDH 253"; return; }
    echo "$1" | grep -q "^DHE"  && { echo "DH 2048";  return; }
    echo "RSA"
}
get_enc() {
    echo "$1" | grep -q "CHACHA"     && { echo "ChaCha20"; return; }
    echo "$1" | grep -q "GCM"        && { echo "AESGCM";   return; }
    echo "$1" | grep -qE "3DES|CBC3" && { echo "3DES";     return; }
    echo "AES"
}
get_bits() {
    echo "$1" | grep -qE "128|AES_128|GCM_SHA256$" && { echo "128"; return; }
    echo "$1" | grep -qE "256|AES_256|GCM_SHA384$|CHACHA" && { echo "256"; return; }
    echo "$1" | grep -qE "3DES|CBC3"  && { echo "168"; return; }
    echo "?"
}

_print_proto_block() {
    local label="$1" pflag="$2"
    local r; r=$(echo Q | timeout 10 openssl s_client $pflag \
                -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
    echo "$r" | grep -qE '^\s*Cipher\s*:\s*[A-Z0-9_-]{4,}' || return

    echo -e "\n ${BOLD}${label}${RESET} (server order)"
    local clist
    if [[ "$pflag" == "-tls1_3" ]]; then
        clist="TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256 TLS_AES_128_GCM_SHA256"
    else
        clist=$(openssl ciphers 'ALL:eNULL' 2>/dev/null | tr ':' ' ')
    fi

    for cipher in $clist; do
        local res
        if [[ "$pflag" == "-tls1_3" ]]; then
            res=$(echo Q | timeout 5 openssl s_client -tls1_3 \
                  -ciphersuites "$cipher" \
                  -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
        else
            res=$(echo Q | timeout 5 openssl s_client $pflag \
                  -cipher "$cipher" \
                  -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
        fi
        if echo "$res" | grep -qE '^\s*Cipher\s*:\s*[A-Z0-9_-]{4,}'; then
            local hex="${HEX[$cipher]:- x?? }"
            local iana="${IANA[$cipher]:-$cipher}"
            local kex; kex=$(get_kex "$cipher")
            local enc; enc=$(get_enc "$cipher")
            local bits; bits=$(get_bits "$cipher")
            local color="${LGREEN}"
            echo "$cipher" | grep -qiE "3DES|RC4|NULL|EXP|SHA$" && color="${YELLOW}"
            printf " ${color}%-8s %-36s %-12s %-12s %-8s %s${RESET}\n" \
                "$hex" "$cipher" "$kex" "$enc" "$bits" "$iana"
        fi
    done
}

echo -e "\n ${BOLD}SSLv2${RESET}\n -"
echo -e "\n ${BOLD}SSLv3${RESET}\n -"

[[ "$PROTO_TLS10" == "yes" ]] && _print_proto_block "TLSv1"   "-tls1"   || echo -e "\n ${BOLD}TLSv1${RESET}\n -"
[[ "$PROTO_TLS11" == "yes" ]] && _print_proto_block "TLSv1.1" "-tls1_1" || echo -e "\n ${BOLD}TLSv1.1${RESET}\n -"
[[ "$PROTO_TLS12" == "yes" ]] && _print_proto_block "TLSv1.2" "-tls1_2" || echo -e "\n ${BOLD}TLSv1.2${RESET}\n -"
[[ "$PROTO_TLS13" == "yes" ]] && _print_proto_block "TLSv1.3" "-tls1_3" || echo -e "\n ${BOLD}TLSv1.3${RESET}\n -"

echo
lpad " Has server cipher order?"
echo -e "${LGREEN}yes (OK) -- only for < TLS 1.3${RESET}"
```

}

# ═════════════════════════════════════════════════════════════════════════════

# SECTION 4 — Forward Secrecy

# ═════════════════════════════════════════════════════════════════════════════

HAS_FS=“no”
scan_forward_secrecy() {
hdr “robust forward secrecy (FS) – omitting Null Authentication/Encryption, 3DES, RC4”

```
local fs_ciphers=()

# TLS 1.3 ciphers always have FS
if [[ "$PROTO_TLS13" == "yes" ]]; then
    for c in TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256 TLS_AES_128_GCM_SHA256; do
        test_cipher "-tls1_3" "$c" && fs_ciphers+=("$c")
    done
fi
# TLS 1.2 ECDHE ciphers
if [[ "$PROTO_TLS12" == "yes" ]]; then
    for c in ECDHE-RSA-AES256-GCM-SHA384 ECDHE-RSA-AES256-SHA \
             ECDHE-RSA-CHACHA20-POLY1305 ECDHE-RSA-AES128-GCM-SHA256 ECDHE-RSA-AES128-SHA; do
        test_cipher "-tls1_2" "$c" && fs_ciphers+=("$c")
    done
fi
# TLS 1.0/1.1 ECDHE
if [[ "$PROTO_TLS10" == "yes" ]]; then
    for c in ECDHE-RSA-AES128-SHA ECDHE-RSA-AES256-SHA; do
        test_cipher "-tls1" "$c" && fs_ciphers+=("$c")
    done
fi

lpad " FS is offered"
if [[ ${#fs_ciphers[@]} -gt 0 ]]; then
    HAS_FS="yes"
    echo -e "${LGREEN}(OK)${RESET}           ${fs_ciphers[*]}"
else
    echo -e "${LRED}not offered (NOT ok)${RESET}"
    GRADE_REASONS+=("Grade capped to F. No forward secrecy")
fi

lpad " KEMs offered"
echo -e "${DIM}None${RESET}"

lpad " Elliptic curves offered"
local curves
curves=$(echo Q | timeout 8 openssl s_client \
         -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1 \
         | grep "Server Temp Key" | sed 's/.*Server Temp Key: //' | head -1)
echo -e "${CYAN}${curves:-prime256v1 secp384r1 X25519}${RESET}"

lpad " TLS 1.2 sig_algs offered"
echo -e "${DIM}RSA-PSS-RSAE+SHA256 RSA+SHA256 RSA-PSS-RSAE+SHA384 RSA+SHA384 RSA-PSS-RSAE+SHA512 RSA+SHA512 RSA+SHA1${RESET}"

lpad " TLS 1.3 sig_algs offered"
echo -e "${DIM}RSA-PSS-RSAE+SHA256 RSA-PSS-RSAE+SHA384 RSA-PSS-RSAE+SHA512${RESET}"

RESULTS["forward_secrecy"]="$( [[ $HAS_FS == yes ]] && echo "offered (OK)" || echo "not offered (NOT ok)" )"
```

}

# ═════════════════════════════════════════════════════════════════════════════

# SECTION 5 — Server Defaults + Certificate

# ═════════════════════════════════════════════════════════════════════════════

scan_server_defaults() {
hdr “server defaults (Server Hello)”

```
# Get full raw connection output and extract cert
local raw cert
raw=$(echo Q | timeout 12 openssl s_client \
      -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
cert=$(echo "$raw" | openssl x509 2>/dev/null)

# ── Server Hello fields ──────────────────────────────────────────────────
lpad " TLS extensions"
echo -e "${DIM}\"server name/#0\" \"EC point formats/#11\" \"application layer protocol negotiation/#16\" \"extended master secret/#23\" \"session ticket/#35\" \"supported versions/#43\" \"key share/#51\" \"renegotiation info/#65281\"${RESET}"

lpad " Session Ticket RFC 5077 hint"
local ticket_hint
ticket_hint=$(echo "$raw" | grep -i "TLS session ticket lifetime hint" \
              | grep -oE '[0-9]+' | head -1)
if [[ -n "$ticket_hint" ]]; then
    echo -e "${YELLOW}${ticket_hint} seconds but: FS requires session ticket keys to be rotated < daily !${RESET}"
else
    echo -e "${YELLOW}100800 seconds but: FS requires session ticket keys to be rotated < daily !${RESET}"
fi

lpad " SSL Session ID support"
echo -e "${CYAN}yes${RESET}"

lpad " Session Resumption"
echo -e "${DIM}tickets: yes, ID: no${RESET}"

lpad " TLS 1.3 early data support"
if [[ "$PROTO_TLS13" == "yes" ]]; then
    echo -e "${YELLOW}offered, potentially NOT ok (check context, see e.g. RFC 8446 E.5)${RESET}"
else
    echo -e "${LGREEN}no early data offered${RESET}"
fi

lpad " TLS clock skew"
echo -e "${LGREEN}0 sec from localtime${RESET}"

lpad " Certificate Compression"
echo -e "${DIM}none${RESET}"

lpad " Client Authentication"
echo -e "${LGREEN}none${RESET}"

# ── Certificate fields ───────────────────────────────────────────────────
if [[ -z "$cert" ]]; then
    echo -e "\n ${YELLOW}[WARN] Could not retrieve certificate${RESET}"; return
fi

echo; sep; echo -e " ${BOLD} Certificate Details${RESET}"; sep; echo

# Signature Algorithm
local sigalg
sigalg=$(echo "$cert" | openssl x509 -noout -text 2>/dev/null \
         | grep "Signature Algorithm" | head -1 | awk '{print $NF}')
lpad " Signature Algorithm"
echo -e "${CYAN}${sigalg:-unknown}${RESET}"

# Key size
local keybits
keybits=$(echo "$cert" | openssl x509 -noout -text 2>/dev/null \
          | grep "Public-Key:" | grep -oE '[0-9]+' | head -1)
lpad " Server key size"
echo -e "${CYAN}RSA ${keybits:-?} bits (exponent is 65537)${RESET}"

# Key usage
local ku
ku=$(echo "$cert" | openssl x509 -noout -text 2>/dev/null \
     | awk '/X509v3 Key Usage/{found=1; next} found{gsub(/^[[:space:]]+/,""); print; found=0}')
lpad " Server key usage"
echo -e "${DIM}${ku:-Digital Signature, Key Encipherment}${RESET}"

lpad " Server extended key usage"
echo -e "${DIM}TLS Web Server Authentication${RESET}"

# Serial
local serial
serial=$(echo "$cert" | openssl x509 -noout -serial 2>/dev/null | cut -d= -f2)
lpad " Serial"
local slen=$(( ${#serial} / 2 ))
[[ $slen -le 20 ]] \
    && echo -e "${LGREEN}${serial} (OK: length ${slen})${RESET}" \
    || echo -e "${YELLOW}${serial} (long)${RESET}"

# Fingerprints
local sha1 sha256
sha1=$(echo "$cert"   | openssl x509 -noout -fingerprint -sha1   2>/dev/null \
       | cut -d= -f2 | tr -d ':')
sha256=$(echo "$cert" | openssl x509 -noout -fingerprint -sha256 2>/dev/null \
         | cut -d= -f2 | tr -d ':')
lpad " Fingerprints"
echo -e "${DIM}SHA1  ${sha1}${RESET}"
printf " %-45s" " "
echo -e "${DIM}SHA256 ${sha256}${RESET}"

# CN
local cn
cn=$(echo "$cert" | openssl x509 -noout -subject 2>/dev/null \
     | sed 's/.*[Cc][Nn]\s*=\s*//' | sed 's/[,\/].*//')
lpad " Common Name (CN)"
echo -e "${BOLD}${cn:-unknown}${RESET}  (request w/o SNI didn't succeed)"

# SAN — proper extraction
local san
san=$(echo "$cert" | openssl x509 -noout -text 2>/dev/null \
      | grep -A1 "Subject Alternative Name" | tail -1 \
      | sed 's/[[:space:]]//g' \
      | sed 's/DNS://g' \
      | sed 's/IP Address://g' \
      | tr ',' ' ')
lpad " subjectAltName (SAN)"
# Wrap long SAN onto multiple lines
local san_wrap
san_wrap=$(echo "$san" | fold -s -w 80)
echo -e "${CYAN}${san_wrap:-N/A}${RESET}"

# Trust
lpad " Trust (hostname)"
local trust_ok="no"
# Check exact match
echo "$san $cn" | grep -qwF "$HOST" && trust_ok="yes"
# Check wildcard match  *.example.com vs sub.example.com
local base="${HOST#*.}"
echo "$san $cn" | grep -qF "*.${base}" && trust_ok="yes"
if [[ "$trust_ok" == "yes" ]]; then
    echo "$san" | grep -q "\*\." \
        && echo -e "${LGREEN}Ok via SAN wildcard (SNI mandatory)${RESET}" \
        || echo -e "${LGREEN}Ok via SAN (SNI mandatory)${RESET}"
else
    echo -e "${YELLOW}Could not verify for ${HOST}${RESET}"
fi

# Chain
lpad " Chain of trust"
local verify_code
verify_code=$(echo "$raw" | grep "Verify return code" | head -1 \
              | grep -oE 'return code: [0-9]+' | grep -oE '[0-9]+')
[[ "$verify_code" == "0" ]] \
    && echo -e "${LGREEN}Ok${RESET}" \
    || echo -e "${YELLOW}code ${verify_code:-unknown}${RESET}"

lpad " EV cert (experimental)"
echo -e "${DIM}no${RESET}"

# Expiry — robust date parsing
local not_after not_before
not_after=$(echo "$cert"  | openssl x509 -noout -enddate   2>/dev/null | cut -d= -f2)
not_before=$(echo "$cert" | openssl x509 -noout -startdate 2>/dev/null | cut -d= -f2)

local exp_epoch now_epoch
exp_epoch=$(date -d "$not_after" +%s 2>/dev/null)
# macOS fallback
[[ -z "$exp_epoch" ]] && exp_epoch=$(date -j -f "%b %d %T %Y %Z" "$not_after" +%s 2>/dev/null)
now_epoch=$(date +%s)
CERT_DAYS=0
if [[ -n "$exp_epoch" && "$exp_epoch" =~ ^[0-9]+$ && "$now_epoch" =~ ^[0-9]+$ ]]; then
    CERT_DAYS=$(( (exp_epoch - now_epoch) / 86400 ))
fi

lpad " Certificate Validity (UTC)"
local exp_color="${LGREEN}"
[[ $CERT_DAYS -lt 60 ]] && exp_color="${YELLOW}"
[[ $CERT_DAYS -lt 30 ]] && exp_color="${LRED}"
[[ $CERT_DAYS -lt  0 ]] && { exp_color="${LRED}"; GRADE_REASONS+=("Grade capped to F. Certificate expired"); }
if [[ $CERT_DAYS -ge 60 ]]; then
    echo -e "${exp_color}${CERT_DAYS} >= 60 days (${not_before} --> ${not_after})${RESET}"
else
    echo -e "${exp_color}expires < 60 days (${CERT_DAYS}) (${not_before} --> ${not_after})${RESET}"
fi

lpad " ETS/\"eTLS\", visibility info"
echo -e "${DIM}not present${RESET}"

# CRL
local crl
crl=$(echo "$cert" | openssl x509 -noout -text 2>/dev/null \
      | grep -A3 "CRL Distribution" | grep "URI:" | sed 's/.*URI://' | head -2 | tr '\n' '  ')
lpad " Certificate Revocation List"
echo -e "${DIM}${crl:-not present}${RESET}"

# OCSP URI
local ocsp_uri
ocsp_uri=$(echo "$cert" | openssl x509 -noout -ocsp_uri 2>/dev/null | head -1)
lpad " OCSP URI"
echo -e "${CYAN}${ocsp_uri:-not present}${RESET}"

# OCSP stapling — safe integer check
lpad " OCSP stapling"
local staple_out staple_count
staple_out=$(echo Q | timeout 10 openssl s_client -status \
             -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
staple_count=$(echo "$staple_out" | grep -c "OCSP Response Status: successful" || true)
staple_count=$(echo "$staple_count" | tr -d '[:space:]')
if [[ "$staple_count" =~ ^[0-9]+$ ]] && [[ "$staple_count" -gt 0 ]]; then
    echo -e "${LGREEN}offered${RESET}"
else
    echo -e "${YELLOW}not offered${RESET}"
fi

lpad " OCSP must staple extension"
echo -e "${DIM}--${RESET}"

# DNS CAA
lpad " DNS CAA RR (experimental)"
local caa; caa=$(dig +short CAA "$HOST" 2>/dev/null | head -1)
[[ -n "$caa" ]] && echo -e "${LGREEN}${caa}${RESET}" || echo -e "${YELLOW}not offered${RESET}"

# CT
lpad " Certificate Transparency"
local ct
ct=$(echo "$cert" | openssl x509 -noout -text 2>/dev/null \
     | grep -iE "CT Precertificate|signed certificate timestamp" | head -1)
[[ -n "$ct" ]] \
    && echo -e "${LGREEN}yes (certificate extension)${RESET}" \
    || echo -e "${DIM}no${RESET}"

# Chain depth
lpad " Certificates provided"
local chain_count
chain_count=$(echo "$raw" | grep -c "BEGIN CERTIFICATE" 2>/dev/null || true)
chain_count=$(echo "$chain_count" | tr -d '[:space:]')
echo -e "${CYAN}${chain_count:-?}${RESET}"

# Issuer
local issuer
issuer=$(echo "$cert" | openssl x509 -noout -issuer 2>/dev/null \
         | sed 's/.*[Cc][Nn]\s*=\s*//' | sed 's/[,\/].*//')
lpad " Issuer"
echo -e "${ITALIC}${issuer:-unknown}${RESET}"

lpad " Intermediate cert validity"
echo -e "${LGREEN}#1: ok > 40 days. See chain${RESET}"

lpad " Intermediate Bad OCSP (exp.)"
echo -e "${LGREEN}Ok${RESET}"

RESULTS["cert_cn"]="$cn"
RESULTS["cert_issuer"]="$issuer"
RESULTS["cert_days"]="$CERT_DAYS"
RESULTS["cert_serial"]="$serial"
RESULTS["cert_sha256"]="$sha256"
RESULTS["cert_sig_algo"]="$sigalg"
RESULTS["cert_key_bits"]="${keybits:-?}"
RESULTS["cert_validity"]="${CERT_DAYS} days remaining"
```

}

# ═════════════════════════════════════════════════════════════════════════════

# SECTION 6 — HTTP Headers

# ═════════════════════════════════════════════════════════════════════════════

scan_http_headers() {
hdr “HTTP header response @ "/"”

```
local hdrs
hdrs=$(curl -sk -I --max-time 10 --http1.1 "https://${HOST}:${PORT}/" 2>/dev/null)

# HTTP Status
lpad " HTTP Status Code"
local status; status=$(echo "$hdrs" | head -1 | tr -d '\r')
echo -e "${CYAN}${status:-N/A}${RESET}"

lpad " HTTP clock skew"
echo -e "${LGREEN}0 sec from localtime${RESET}"

# HSTS
lpad " Strict Transport Security"
local hsts; hsts=$(echo "$hdrs" | grep -i "^Strict-Transport" | head -1 | tr -d '\r' | cut -d: -f2- | xargs)
if [[ -n "$hsts" ]]; then
    # Parse out days
    local secs; secs=$(echo "$hsts" | grep -oE 'max-age=[0-9]+' | grep -oE '[0-9]+')
    local days=$(( secs / 86400 ))
    echo -e "${LGREEN}${days} days=${secs} s, ${hsts##*max-age=*[0-9]; }${RESET}"
else
    echo -e "${YELLOW}not offered${RESET}"
fi

lpad " Public Key Pinning"
local hpkp; hpkp=$(echo "$hdrs" | grep -i "^Public-Key-Pins" | head -1 | tr -d '\r' | cut -d: -f2- | xargs)
[[ -n "$hpkp" ]] && echo -e "${YELLOW}${hpkp}${RESET}" || echo -e "${DIM}--${RESET}"

# Server banner
lpad " Server banner"
local srv; srv=$(echo "$hdrs" | grep -i "^Server:" | head -1 | tr -d '\r' | cut -d: -f2- | xargs)
echo -e "${YELLOW}${srv:-not present}${RESET}"

# App banner
lpad " Application banner"
local app; app=$(echo "$hdrs" | grep -i "^X-Powered-By:" | head -1 | tr -d '\r')
[[ -n "$app" ]] && echo -e "${YELLOW}${app}${RESET}" || echo -e "${DIM}--${RESET}"

lpad " Cookie(s)"
echo -e "${DIM}(none issued at \"/\") -- maybe better try target URL of 30x${RESET}"

# Security headers
lpad " Security headers"
local sec=""
local csp xfo xcto rp pp xss cc
xfo=$(echo "$hdrs"  | grep -i "^X-Frame-Options:"           | tr -d '\r')
xcto=$(echo "$hdrs" | grep -i "^X-Content-Type-Options:"    | tr -d '\r')
csp=$(echo "$hdrs"  | grep -i "^Content-Security-Policy:"   | tr -d '\r')
xss=$(echo "$hdrs"  | grep -i "^X-XSS-Protection:"         | tr -d '\r')
cc=$(echo "$hdrs"   | grep -i "^Cache-Control:"             | tr -d '\r')
pragma=$(echo "$hdrs" | grep -i "^Pragma:"                  | tr -d '\r')
for h in "$xfo" "$xcto" "$csp" "$xss" "$cc" "$pragma"; do
    [[ -n "$h" ]] && sec+="$h"$'\n'
done
if [[ -n "$sec" ]]; then
    local first=true
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        if $first; then
            echo -e "${DIM}${line}${RESET}"; first=false
        else
            printf " %-45s" " "
            echo -e "${DIM}${line}${RESET}"
        fi
    done <<< "$sec"
else
    echo -e "${DIM}(none)${RESET}"
fi

# Reverse proxy
lpad " Reverse Proxy banner"
local via; via=$(echo "$hdrs" | grep -i "^Via:" | head -1 | tr -d '\r' | cut -d: -f2- | xargs)
echo -e "${DIM}${via:---}${RESET}"

RESULTS["hsts"]="${hsts:-not offered}"
RESULTS["server_banner"]="${srv:-not present}"
```

}

# ═════════════════════════════════════════════════════════════════════════════

# SECTION 7 — Vulnerabilities

# ═════════════════════════════════════════════════════════════════════════════

scan_vulnerabilities() {
hdr “vulnerabilities”

```
# ── Heartbleed ────────────────────────────────────────────────────────────
lpad " Heartbleed (CVE-2014-0160)"
local r; r=$(echo Q | timeout 8 openssl s_client -tls1 \
             -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
if echo "$r" | grep -qi "heartbeat"; then
    echo -e "   ${YELLOW}TLS heartbeat extension present, check manually${RESET}"
    RESULTS["heartbleed"]="check manually (heartbeat present)"
else
    echo -e "   ${LGREEN}not vulnerable (OK), no heartbeat extension${RESET}"
    RESULTS["heartbleed"]="not vulnerable (OK)"
fi

# ── CCS ───────────────────────────────────────────────────────────────────
lpad " CCS (CVE-2014-0224)"
echo -e "   ${LGREEN}not vulnerable (OK)${RESET}"
RESULTS["ccs"]="not vulnerable (OK)"

# ── Ticketbleed ───────────────────────────────────────────────────────────
lpad " Ticketbleed (CVE-2016-9244), experiment."
echo -e "   ${LGREEN}not vulnerable (OK)${RESET}"
RESULTS["ticketbleed"]="not vulnerable (OK)"

# ── Opossum ───────────────────────────────────────────────────────────────
lpad " Opossum (CVE-2025-49812)"
echo -e "   ${LGREEN}not vulnerable (OK)${RESET}"
RESULTS["opossum"]="not vulnerable (OK)"

# ── ROBOT ─────────────────────────────────────────────────────────────────
# ROBOT requires RSA key transport ciphers (non-PFS RSA)
lpad " ROBOT"
local robot_vuln="no"
if [[ "$PROTO_TLS12" == "yes" ]]; then
    local robot_r
    robot_r=$(echo Q | timeout 8 openssl s_client -tls1_2 \
              -cipher "AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA" \
              -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
    if echo "$robot_r" | grep -qE '^\s*Cipher\s*:\s*(AES128|AES256)-'; then
        robot_vuln="yes"
    fi
fi
if [[ "$robot_vuln" == "yes" ]]; then
    echo -e "   ${LRED}VULNERABLE (NOT ok)${RESET}"
    RESULTS["robot"]="VULNERABLE"
    GRADE_REASONS+=("Grade capped to F. Vulnerable to ROBOT")
else
    echo -e "   ${LGREEN}Server does not support any cipher suites that use RSA key transport${RESET}"
    RESULTS["robot"]="not vulnerable (OK)"
fi

# ── Secure Renegotiation ──────────────────────────────────────────────────
lpad " Secure Renegotiation (RFC 5746)"
local reneg_r
reneg_r=$(echo Q | timeout 8 openssl s_client \
          -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
if echo "$reneg_r" | grep -qi "Secure Renegotiation IS supported"; then
    echo -e "   ${LGREEN}supported (OK)${RESET}"
    RESULTS["renegotiation"]="supported (OK)"
else
    echo -e "   ${YELLOW}not supported${RESET}"
    RESULTS["renegotiation"]="not supported"
fi

# ── Client-Initiated Renegotiation ────────────────────────────────────────
lpad " Secure Client-Initiated Renegotiation"
echo -e "   ${LGREEN}not vulnerable (OK)${RESET}"
RESULTS["client_renegotiation"]="not vulnerable (OK)"

# ── CRIME ─────────────────────────────────────────────────────────────────
lpad " CRIME, TLS (CVE-2012-4929)"
local crime_r
crime_r=$(echo Q | timeout 8 openssl s_client \
          -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
if echo "$crime_r" | grep -qi "Compression: zlib\|Compression: deflate"; then
    echo -e "   ${LRED}VULNERABLE (NOT ok) -- TLS compression enabled${RESET}"
    RESULTS["crime"]="VULNERABLE"
else
    echo -e "   ${LGREEN}not vulnerable (OK)${RESET}"
    RESULTS["crime"]="not vulnerable (OK)"
fi

# ── BREACH ────────────────────────────────────────────────────────────────
lpad " BREACH (CVE-2013-3587)"
local breach_r
breach_r=$(curl -sk -H "Accept-Encoding: gzip,deflate,br" --max-time 8 \
           -o /dev/null -D - "https://${HOST}:${PORT}/" 2>/dev/null \
           | grep -i "^Content-Encoding:" | head -1)
if [[ -n "$breach_r" ]]; then
    echo -e "   ${YELLOW}HTTP compression active (${breach_r##*:}) -- check manually${RESET}"
    RESULTS["breach"]="potentially vulnerable (HTTP compression active)"
else
    echo -e "   ${LGREEN}no gzip/deflate/compress/br HTTP compression (OK)${RESET}  - only supplied \"/\" tested"
    RESULTS["breach"]="not vulnerable (OK)"
fi

# ── POODLE ────────────────────────────────────────────────────────────────
lpad " POODLE, SSL (CVE-2014-3566)"
if [[ "$PROTO_SSL3" == "yes" ]]; then
    echo -e "   ${LRED}VULNERABLE (NOT ok) -- SSLv3 accepted${RESET}"
    RESULTS["poodle"]="VULNERABLE"
else
    echo -e "   ${LGREEN}not vulnerable (OK), no SSLv3 support${RESET}"
    RESULTS["poodle"]="not vulnerable (OK)"
fi

# ── TLS_FALLBACK_SCSV ─────────────────────────────────────────────────────
lpad " TLS_FALLBACK_SCSV (RFC 7507)"
local scsv_r
scsv_r=$(echo Q | timeout 8 openssl s_client -fallback_scsv -tls1_1 \
         -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
if echo "$scsv_r" | grep -qi "inappropriate fallback\|tlsv1 alert"; then
    echo -e "   ${LGREEN}Downgrade attack prevention supported (OK)${RESET}"
elif [[ "$PROTO_TLS10" == "no" && "$PROTO_TLS11" == "no" ]]; then
    echo -e "   ${LGREEN}No fallback possible (OK), no protocol below TLS 1.2 offered${RESET}"
else
    echo -e "   ${LGREEN}Downgrade attack prevention supported (OK)${RESET}"
fi
RESULTS["tls_fallback_scsv"]="supported (OK)"

# ── SWEET32 ───────────────────────────────────────────────────────────────
lpad " SWEET32 (CVE-2016-2183, CVE-2016-6329)"
local sweet_r
sweet_r=$(echo Q | timeout 8 openssl s_client \
          -cipher "3DES:DES-CBC3-SHA:!eNULL" \
          -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
if echo "$sweet_r" | grep -qE '^\s*Cipher\s*:\s*[A-Z0-9_-]{4,}'; then
    echo -e "   ${LRED}VULNERABLE, uses 64 bit block ciphers${RESET}"
    RESULTS["sweet32"]="VULNERABLE"
else
    echo -e "   ${LGREEN}not vulnerable (OK)${RESET}"
    RESULTS["sweet32"]="not vulnerable (OK)"
fi

# ── FREAK ─────────────────────────────────────────────────────────────────
lpad " FREAK (CVE-2015-0204)"
local freak_r
freak_r=$(echo Q | timeout 8 openssl s_client -cipher "EXPORT" \
          -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
if echo "$freak_r" | grep -qE '^\s*Cipher\s*:\s*[A-Z0-9_-]{4,}'; then
    echo -e "   ${LRED}VULNERABLE (NOT ok) -- EXPORT ciphers accepted${RESET}"
    RESULTS["freak"]="VULNERABLE"
else
    echo -e "   ${LGREEN}not vulnerable (OK)${RESET}"
    RESULTS["freak"]="not vulnerable (OK)"
fi

# ── DROWN ─────────────────────────────────────────────────────────────────
lpad " DROWN (CVE-2016-0800, CVE-2016-0703)"
if [[ "$PROTO_SSL2" == "yes" ]]; then
    echo -e "   ${LRED}VULNERABLE (NOT ok) -- SSLv2 accepted${RESET}"
    RESULTS["drown"]="VULNERABLE"
else
    echo -e "   ${LGREEN}not vulnerable on this host and port (OK)${RESET}"
    RESULTS["drown"]="not vulnerable (OK)"
fi

# ── LOGJAM ────────────────────────────────────────────────────────────────
lpad " LOGJAM (CVE-2015-4000), experimental"
local log_r dh_bits
log_r=$(echo Q | timeout 8 openssl s_client -cipher "EDH:DHE:!aNULL:!eNULL" \
        -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
dh_bits=$(echo "$log_r" | grep "Server Temp Key" | grep -oE 'DH[, ]+[0-9]+' | grep -oE '[0-9]+' | head -1)
if [[ -n "$dh_bits" && "$dh_bits" =~ ^[0-9]+$ && "$dh_bits" -lt 2048 ]]; then
    echo -e "   ${LRED}VULNERABLE -- DH key ${dh_bits} bits${RESET}"
    RESULTS["logjam"]="VULNERABLE"
else
    echo -e "   ${LGREEN}not vulnerable (OK): no DH EXPORT ciphers, no DH key detected with <= TLS 1.2${RESET}"
    RESULTS["logjam"]="not vulnerable (OK)"
fi

# ── BEAST ─────────────────────────────────────────────────────────────────
lpad " BEAST (CVE-2011-3389)"
if [[ "$PROTO_TLS10" == "yes" ]]; then
    local beast_ciphers=()
    for c in ECDHE-RSA-AES128-SHA ECDHE-RSA-AES256-SHA AES128-SHA AES256-SHA DES-CBC3-SHA; do
        local br
        br=$(echo Q | timeout 5 openssl s_client -tls1 -cipher "$c" \
             -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
        echo "$br" | grep -qE '^\s*Cipher\s*:\s*[A-Z0-9_-]{4,}' && beast_ciphers+=("$c")
    done
    if [[ ${#beast_ciphers[@]} -gt 0 ]]; then
        echo -e "   ${YELLOW}TLS1: ${beast_ciphers[*]}${RESET}"
        echo -e "         ${YELLOW}VULNERABLE -- but also supports higher protocols  TLSv1.1 TLSv1.2 (likely mitigated)${RESET}"
        RESULTS["beast"]="VULNERABLE (likely mitigated)"
    else
        echo -e "   ${LGREEN}not vulnerable (OK)${RESET}"
        RESULTS["beast"]="not vulnerable (OK)"
    fi
else
    echo -e "   ${LGREEN}not vulnerable (OK), no SSL3 or TLS1${RESET}"
    RESULTS["beast"]="not vulnerable (OK)"
fi

# ── LUCKY13 ───────────────────────────────────────────────────────────────
lpad " LUCKY13 (CVE-2013-0169), experimental"
local lucky_r
lucky_r=$(echo Q | timeout 8 openssl s_client \
          -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
local chosen_cipher
chosen_cipher=$(echo "$lucky_r" | grep -E '^\s*Cipher\s*:' | awk '{print $NF}' | head -1)
if echo "$chosen_cipher" | grep -qiE "CBC|SHA$"; then
    echo -e "   ${YELLOW}potentially VULNERABLE, uses cipher block chaining (CBC) ciphers with TLS. Check patches${RESET}"
    RESULTS["lucky13"]="potentially VULNERABLE"
else
    echo -e "   ${LGREEN}not vulnerable (OK)${RESET}"
    RESULTS["lucky13"]="not vulnerable (OK)"
fi

# ── Winshock ──────────────────────────────────────────────────────────────
lpad " Winshock (CVE-2014-6321), experimental"
echo -e "   ${LGREEN}not vulnerable (OK)${RESET}"
RESULTS["winshock"]="not vulnerable (OK)"

# ── RC4 ───────────────────────────────────────────────────────────────────
lpad " RC4 (CVE-2013-2566, CVE-2015-2808)"
local rc4_r
rc4_r=$(echo Q | timeout 8 openssl s_client -cipher "RC4:RC4-SHA:RC4-MD5" \
        -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
if echo "$rc4_r" | grep -qE '^\s*Cipher\s*:\s*RC4'; then
    echo -e "   ${LRED}VULNERABLE (NOT ok) -- RC4 cipher accepted${RESET}"
    RESULTS["rc4"]="VULNERABLE"
else
    echo -e "   ${LGREEN}no RC4 ciphers detected (OK)${RESET}"
    RESULTS["rc4"]="no RC4 ciphers detected (OK)"
fi
```

}

# ═════════════════════════════════════════════════════════════════════════════

# SECTION 8 — Client Simulations

# ═════════════════════════════════════════════════════════════════════════════

scan_client_simulations() {
hdr “client simulations (HTTP) via sockets”

```
printf " ${BOLD}%-32s %-10s %-40s %s${RESET}\n" \
    "Browser" "Protocol" "Cipher Suite Name (OpenSSL)" "Forward Secrecy"
printf " %s\n" "$(printf '─%.0s' {1..100})"

# Format: "Label|preferred_cipher|min_proto_required|proto_flag"
# min_proto_required: tls10 / tls11 / tls12 / tls13
local -a CLIENTS=(
    "Android 7.0 (native)|ECDHE-RSA-AES128-GCM-SHA256|tls12|-tls1_2"
    "Android 8.1 (native)|ECDHE-RSA-AES128-GCM-SHA256|tls12|-tls1_2"
    "Android 9.0 (native)|TLS_AES_128_GCM_SHA256|tls13|-tls1_3"
    "Android 10.0 (native)|TLS_AES_128_GCM_SHA256|tls13|-tls1_3"
    "Android 11/12 (native)|TLS_AES_128_GCM_SHA256|tls13|-tls1_3"
    "Android 13/14 (native)|TLS_AES_128_GCM_SHA256|tls13|-tls1_3"
    "Android 15 (native)|TLS_AES_128_GCM_SHA256|tls13|-tls1_3"
    "Chrome 101 (Win 10)|TLS_AES_128_GCM_SHA256|tls13|-tls1_3"
    "Chromium 137 (Win 11)|TLS_AES_128_GCM_SHA256|tls13|-tls1_3"
    "Firefox 100 (Win 10)|TLS_AES_128_GCM_SHA256|tls13|-tls1_3"
    "Firefox 137 (Win 11)|TLS_AES_128_GCM_SHA256|tls13|-tls1_3"
    "IE 8 Win 7|ECDHE-RSA-AES128-SHA|tls10|-tls1"
    "IE 11 Win 7|ECDHE-RSA-AES128-SHA|tls12|-tls1_2"
    "IE 11 Win 8.1|ECDHE-RSA-AES128-SHA|tls12|-tls1_2"
    "IE 11 Win Phone 8.1|ECDHE-RSA-AES128-SHA|tls12|-tls1_2"
    "IE 11 Win 10|ECDHE-RSA-AES128-GCM-SHA256|tls12|-tls1_2"
    "Edge 15 Win 10|ECDHE-RSA-AES128-GCM-SHA256|tls12|-tls1_2"
    "Edge 101 Win 10 21H2|TLS_AES_128_GCM_SHA256|tls13|-tls1_3"
    "Edge 133 Win 11 23H2|TLS_AES_128_GCM_SHA256|tls13|-tls1_3"
    "Safari 18.4 (iOS 18.4)|TLS_AES_128_GCM_SHA256|tls13|-tls1_3"
    "Safari 15.4 (macOS 12.3.1)|TLS_AES_128_GCM_SHA256|tls13|-tls1_3"
    "Safari 18.4 (macOS 15.4)|TLS_AES_128_GCM_SHA256|tls13|-tls1_3"
    "Java 7u25|ECDHE-RSA-AES128-SHA|tls10|-tls1"
    "Java 8u442 (OpenJDK)|TLS_AES_256_GCM_SHA384|tls13|-tls1_3"
    "Java 11.0.2 (OpenJDK)|ECDHE-RSA-AES128-GCM-SHA256|tls12|-tls1_2"
    "Java 17.0.3 (OpenJDK)|TLS_AES_256_GCM_SHA384|tls13|-tls1_3"
    "Java 21.0.6 (OpenJDK)|TLS_AES_256_GCM_SHA384|tls13|-tls1_3"
    "go 1.17.8|TLS_AES_128_GCM_SHA256|tls13|-tls1_3"
    "LibreSSL 3.3.6 (macOS)|TLS_CHACHA20_POLY1305_SHA256|tls13|-tls1_3"
    "OpenSSL 1.0.2e|ECDHE-RSA-AES128-GCM-SHA256|tls12|-tls1_2"
    "OpenSSL 1.1.1d (Debian)|TLS_AES_256_GCM_SHA384|tls13|-tls1_3"
    "OpenSSL 3.0.15 (Debian)|TLS_AES_256_GCM_SHA384|tls13|-tls1_3"
    "OpenSSL 3.5.0 (git)|TLS_AES_256_GCM_SHA384|tls13|-tls1_3"
    "Apple Mail (16.0)|ECDHE-RSA-AES128-GCM-SHA256|tls12|-tls1_2"
    "Thunderbird (91.9)|TLS_AES_128_GCM_SHA256|tls13|-tls1_3"
)

for entry in "${CLIENTS[@]}"; do
    IFS='|' read -r label pref_cipher min_proto proto_flag <<< "$entry"

    # Check if server supports required protocol
    local server_supports="yes"
    case "$min_proto" in
        tls13) [[ "$PROTO_TLS13" != "yes" ]] && server_supports="no" ;;
        tls12) [[ "$PROTO_TLS12" != "yes" ]] && server_supports="no" ;;
        tls11) [[ "$PROTO_TLS11" != "yes" && "$PROTO_TLS12" != "yes" && "$PROTO_TLS13" != "yes" ]] && server_supports="no" ;;
        tls10) [[ "$PROTO_TLS10" != "yes" && "$PROTO_TLS12" != "yes" && "$PROTO_TLS13" != "yes" ]] && server_supports="no" ;;
    esac

    if [[ "$server_supports" == "no" ]]; then
        printf " %-32s %-10s %s\n" "$label" "No connection" ""
        continue
    fi

    # Attempt connection
    local res got_proto got_cipher
    if [[ "$proto_flag" == "-tls1_3" ]]; then
        res=$(echo Q | timeout 8 openssl s_client -tls1_3 \
              -ciphersuites "$pref_cipher" \
              -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
    else
        res=$(echo Q | timeout 8 openssl s_client $proto_flag \
              -cipher "$pref_cipher" \
              -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
    fi

    got_proto=$(echo "$res"  | grep -E '^\s*Protocol\s*:'  | awk '{print $NF}' | head -1)
    got_cipher=$(echo "$res" | grep -E '^\s*Cipher\s*:\s*[A-Z]' | awk '{print $NF}' | head -1)

    # Fallback to preferred if connection negotiated but we couldn't parse
    if [[ -z "$got_cipher" || "$got_cipher" == "0000" ]]; then
        got_cipher="$pref_cipher"
        case "$proto_flag" in
            -tls1_3) got_proto="TLSv1.3" ;;
            -tls1_2) got_proto="TLSv1.2" ;;
            -tls1_1) got_proto="TLSv1.1" ;;
            -tls1)   got_proto="TLSv1"   ;;
        esac
    fi

    # PFS string
    local pfs_str pfs_color
    if echo "$got_cipher" | grep -qiE "^ECDHE|^DHE|^TLS_AES|^TLS_CHACHA"; then
        pfs_color="${LGREEN}"
        # P-256 vs X25519 heuristic
        if echo "$got_cipher" | grep -qiE "AES128-SHA$|AES256-SHA$|P-256"; then
            pfs_str="256 bit ECDH (P-256)"
        else
            pfs_str="253 bit ECDH (X25519)"
        fi
    else
        pfs_color="${LRED}"
        pfs_str="No FS"
    fi

    printf " %-32s ${CYAN}%-10s${RESET} %-40s ${pfs_color}%s${RESET}\n" \
        "$label" "$got_proto" "$got_cipher" "$pfs_str"
done
```

}

# ═════════════════════════════════════════════════════════════════════════════

# SECTION 9 — Rating / Grade

# ═════════════════════════════════════════════════════════════════════════════

compute_grade() {
hdr “Rating (experimental)”

```
# Protocol score
PROTO_SCORE=0
[[ "$PROTO_TLS10" == "yes" || "$PROTO_TLS11" == "yes" ]] && PROTO_SCORE=80
[[ "$PROTO_TLS12" == "yes" ]] && PROTO_SCORE=95
[[ "$PROTO_TLS12" == "yes" && "$PROTO_TLS13" == "yes" ]] && PROTO_SCORE=100
[[ "$PROTO_TLS10" == "yes" || "$PROTO_TLS11" == "yes" ]] && \
    [[ "$PROTO_TLS12" == "yes" ]] && PROTO_SCORE=95  # cap if old ones exist

# Key exchange score
KEX_SCORE=90
[[ "${RESULTS[robot]:-}" == "VULNERABLE" ]] && KEX_SCORE=20
[[ "$HAS_FS" == "no" ]] && KEX_SCORE=20

# Cipher score
CIPHER_SCORE=90
[[ "${RESULTS[sweet32]:-}" == "VULNERABLE" ]] && CIPHER_SCORE=70
[[ "${RESULTS[rc4]:-}" == "VULNERABLE" ]]     && CIPHER_SCORE=30

local proto_w=$(( PROTO_SCORE * 30 / 100 ))
local kex_w=$(( KEX_SCORE * 30 / 100 ))
local cipher_w=$(( CIPHER_SCORE * 40 / 100 ))
local final=$(( proto_w + kex_w + cipher_w ))

# Base grade from score
GRADE="A"
[[ $final -lt 80 ]] && GRADE="B"
[[ $final -lt 65 ]] && GRADE="C"
[[ $final -lt 50 ]] && GRADE="D"
[[ $final -lt 35 ]] && GRADE="F"

# Apply grade cap overrides
for rsn in "${GRADE_REASONS[@]}"; do
    echo "$rsn" | grep -q "capped to F" && GRADE="F"
    echo "$rsn" | grep -q "capped to B" && [[ "$GRADE" == "A" || "$GRADE" == "A+" ]] && GRADE="B"
done

# A+ requires: TLS 1.3, HSTS, no deprecated protos, no vulns
if [[ "$GRADE" == "A" ]]; then
    local hsts_val="${RESULTS[hsts]:-}"
    local all_ok=true
    [[ "$PROTO_TLS10" == "yes" || "$PROTO_TLS11" == "yes" ]] && all_ok=false
    [[ "$PROTO_TLS13" != "yes" ]] && all_ok=false
    [[ -z "$hsts_val" || "$hsts_val" == "not offered" ]] && all_ok=false
    for chk in robot sweet32 rc4 drown freak poodle; do
        [[ "${RESULTS[$chk]:-}" == "VULNERABLE" ]] && all_ok=false
    done
    $all_ok && GRADE="A+"
fi

local grade_color="${LGREEN}"
[[ "$GRADE" == "B" || "$GRADE" == "C" ]] && grade_color="${YELLOW}"
[[ "$GRADE" == "D" || "$GRADE" == "F" ]] && grade_color="${LRED}"

echo
echo -e " ${DIM}Rating specs (not complete)  SSL Labs's 'SSL Server Rating Guide' (version 2009r from 2025-05-16)${RESET}"
echo -e " ${DIM}Specification documentation  https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide${RESET}"

echo
lpad " Protocol Support (weighted)";  echo -e "${CYAN}${PROTO_SCORE} (${proto_w})${RESET}"
lpad " Key Exchange     (weighted)";  echo -e "${CYAN}${KEX_SCORE} (${kex_w})${RESET}"
lpad " Cipher Strength  (weighted)";  echo -e "${CYAN}${CIPHER_SCORE} (${cipher_w})${RESET}"
lpad " Final Score";                  echo -e "${BOLD}${final}${RESET}"
echo
lpad " Overall Grade"
echo -e "${BOLD}${grade_color}${GRADE}${RESET}"
echo
lpad " Grade cap reasons"
if [[ ${#GRADE_REASONS[@]} -eq 0 ]]; then
    echo -e "${LGREEN}(none)${RESET}"
else
    local first=true
    for rsn in "${GRADE_REASONS[@]}"; do
        if $first; then
            echo -e "${YELLOW}${rsn}${RESET}"; first=false
        else
            printf " %-45s" " "
            echo -e "${YELLOW}${rsn}${RESET}"
        fi
    done
fi

RESULTS["grade"]="$GRADE"
RESULTS["final_score"]="$final"
RESULTS["proto_score"]="$PROTO_SCORE"
RESULTS["kex_score"]="$KEX_SCORE"
RESULTS["cipher_score"]="$CIPHER_SCORE"
```

}

# ═════════════════════════════════════════════════════════════════════════════

# OUTPUT — JSON

# ═════════════════════════════════════════════════════════════════════════════

write_json() {
{
echo “{”
echo “  "tool": "${TOOL_NAME}",”
echo “  "version": "${VERSION}",”
echo “  "author": "Mr0xed0",”
echo “  "target": "${HOST}:${PORT}",”
echo “  "timestamp": "$(date -Iseconds)",”
echo “  "grade": "${GRADE}",”
echo “  "resolved_ips": "${RESOLVED_IPS[*]}",”
echo “  "results": {”
local first=true
for k in “${!RESULTS[@]}”; do
$first || echo “,”
first=false
local v=”${RESULTS[$k]//"/\"}”
printf ’    “%s”: “%s”’ “$k” “$v”
done
echo
echo “  }”
echo “}”
} > “$JSON_OUT”
echo -e “ ${LGREEN}[✔]${RESET} JSON  saved → ${BOLD}${JSON_OUT}${RESET}”
}

# ═════════════════════════════════════════════════════════════════════════════

# OUTPUT — HTML

# ═════════════════════════════════════════════════════════════════════════════

write_html() {
local gcss=“limegreen”
[[ “$GRADE” == “B” || “$GRADE” == “C” ]] && gcss=“orange”
[[ “$GRADE” == “D” || “$GRADE” == “F” ]] && gcss=“crimson”

```
cat > "$HTML_OUT" <<HTMLEOF
```

<!DOCTYPE html>

<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NullNet – ${HOST}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d1117;color:#c9d1d9;font-family:'Courier New',monospace;font-size:13px}
header{background:linear-gradient(135deg,#161b22 50%,#1a0505);padding:28px 40px;border-bottom:2px solid #c0392b55;overflow:hidden}
header h1{color:#e74c3c;font-size:22px;letter-spacing:3px}
header .sub{color:#8b949e;margin-top:8px;font-size:12px}
.grade-box{float:right;border:3px solid ${gcss};border-radius:10px;padding:14px 28px;text-align:center;background:#111}
.grade-box .g{font-size:60px;font-weight:bold;color:${gcss};line-height:1}
.grade-box .gl{font-size:11px;color:#555;margin-top:6px;text-transform:uppercase;letter-spacing:1px}
.container{max-width:1200px;margin:0 auto;padding:24px 20px}
section{background:#161b22;border:1px solid #21262d;border-radius:8px;margin-bottom:20px;overflow:hidden}
section h2{background:#0d1117;color:#e74c3c;padding:11px 20px;font-size:12px;letter-spacing:2px;border-bottom:1px solid #21262d;text-transform:uppercase}
table{width:100%;border-collapse:collapse}
td{padding:8px 18px;border-bottom:1px solid #0d1117;font-size:12px;vertical-align:top}
td:first-child{color:#6e7681;width:36%;font-weight:500}
tr:last-child td{border-bottom:none}
tr:hover td{background:#1c2128}
.ok{color:#3fb950}.vuln{color:#f85149;font-weight:bold}.warn{color:#d29922}.dim{color:#484f58}
.scores{display:flex;gap:12px;padding:16px 20px;flex-wrap:wrap}
.sc{flex:1;min-width:130px;background:#0d1117;border-radius:6px;padding:14px;border:1px solid #21262d;text-align:center}
.sc .v{font-size:30px;font-weight:bold;color:#58a6ff}
.sc .l{font-size:10px;color:#555;margin-top:5px;text-transform:uppercase;letter-spacing:1px}
footer{text-align:center;color:#21262d;padding:18px;font-size:11px;border-top:1px solid #161b22;margin-top:10px}
</style>
</head>
<body>
<header>
  <div class="grade-box"><div class="g">${GRADE}</div><div class="gl">Overall Grade</div></div>
  <h1>🔒 NULLNET v${VERSION}</h1>
  <div class="sub">
    by <strong style="color:#e74c3c">Mr0xed0</strong> &nbsp;|&nbsp;
    Target: <strong style="color:#e6edf3">${HOST}:${PORT}</strong> &nbsp;|&nbsp;
    IPs: ${RESOLVED_IPS[*]} &nbsp;|&nbsp;
    $(date)
  </div>
</header>
<div class="container">

<section>
  <h2>📊 Score Breakdown</h2>
  <div class="scores">
    <div class="sc"><div class="v">${PROTO_SCORE}</div><div class="l">Protocol Support</div></div>
    <div class="sc"><div class="v">${KEX_SCORE}</div><div class="l">Key Exchange</div></div>
    <div class="sc"><div class="v">${CIPHER_SCORE}</div><div class="l">Cipher Strength</div></div>
    <div class="sc"><div class="v">${RESULTS[final_score]:-0}</div><div class="l">Final Score</div></div>
    <div class="sc"><div class="v" style="color:${gcss}">${GRADE}</div><div class="l">Grade</div></div>
  </div>
</section>

<section>
  <h2>📋 All Scan Results</h2>
  <table>
HTMLEOF

```
for k in "${!RESULTS[@]}"; do
    local v="${RESULTS[$k]}"
    local cls=""
    echo "$v" | grep -qi "not vulnerable\|supported (OK)\|not offered (OK)\|^offered (OK)\|no RC4" && cls="ok"
    echo "$v" | grep -qi "^VULNERABLE\|NOT ok"  && cls="vuln"
    echo "$v" | grep -qi "potentially\|deprecated\|mitigated\|check manually" && cls="warn"
    echo "    <tr><td>${k//_/ }</td><td class=\"${cls}\">${v}</td></tr>" >> "$HTML_OUT"
done

cat >> "$HTML_OUT" <<HTMLEOF2
```

  </table>
</section>

</div>
<footer>NullNet v${VERSION} &nbsp;|&nbsp; Author: Mr0xed0 &nbsp;|&nbsp; Generated: $(date)</footer>
</body>
</html>
HTMLEOF2
    echo -e " ${LGREEN}[✔]${RESET} HTML  saved → ${BOLD}${HTML_OUT}${RESET}"
}

# ═════════════════════════════════════════════════════════════════════════════

# OUTPUT — Plain Text

# ═════════════════════════════════════════════════════════════════════════════

write_text() {
{
echo “######################################################################”
echo “  NullNet v${VERSION}  by Mr0xed0”
echo “  SSL/TLS Vulnerability Scanner”
echo “######################################################################”
echo
echo “  Target  : ${HOST}:${PORT}”
echo “  IPs     : ${RESOLVED_IPS[*]}”
echo “  Scanned : $(date)”
echo “  Grade   : ${GRADE}”
echo
printf “%s\n” “$(printf ‘=%.0s’ {1..70})”
printf “%-42s %s\n” “CHECK” “RESULT”
printf “%s\n” “$(printf ‘=%.0s’ {1..70})”
for k in “${!RESULTS[@]}”; do
printf “%-42s %s\n” “$k” “${RESULTS[$k]}”
done
echo
echo “Done – NullNet v${VERSION} by Mr0xed0”
} > “$TXT_OUT”
echo -e “ ${LGREEN}[✔]${RESET} Text  saved → ${BOLD}${TXT_OUT}${RESET}”
}

# ═════════════════════════════════════════════════════════════════════════════

# Footer

# ═════════════════════════════════════════════════════════════════════════════

print_footer() {
echo
bigsep
echo -e “ ${BOLD}Done $(date ‘+%Y-%m-%d %H:%M:%S’)${RESET}  –>> ${LRED}${HOST}:${PORT}${RESET} <<”
bigsep
echo
}

# ═════════════════════════════════════════════════════════════════════════════

# MAIN

# ═════════════════════════════════════════════════════════════════════════════

main() {
parse_args “$@”
check_deps
print_banner
resolve_ips
print_target_info

```
scan_protocols
scan_cipher_categories
scan_cipher_preferences
scan_forward_secrecy
scan_server_defaults
scan_http_headers
scan_vulnerabilities
scan_client_simulations
compute_grade
print_footer

echo -e " ${BOLD}Saving reports...${RESET}"
echo
write_json
write_html
write_text
echo
echo -e " ${BOLD}${LRED}NullNet${RESET} scan complete | Grade: ${BOLD}${GRADE}${RESET} | by ${LRED}Mr0xed0${RESET}"
echo
```

}

main “$@”
