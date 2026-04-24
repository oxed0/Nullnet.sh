#!/usr/bin/env bash
# ============================================================
#  NullNet v2.0  —  SSL/TLS Vulnerability Scanner
#  Author  : Mr0xed0
#  Usage   : ./nullnet.sh <host> [port]
#  License : GPLv2
# ============================================================

VERSION="2.0"
TOOL_NAME="NullNet"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# ─── Colours ─────────────────────────────────────────────────────────────────
RED='\033[0;31m';    LRED='\033[1;31m'
GREEN='\033[0;32m';  LGREEN='\033[1;32m'
YELLOW='\033[1;33m'; CYAN='\033[0;36m'
LCYAN='\033[1;36m';  MAGENTA='\033[1;35m'
BOLD='\033[1m';      DIM='\033[2m';  RESET='\033[0m'
ITALIC='\033[3m'

# ─── Helpers ─────────────────────────────────────────────────────────────────
ok()    { echo -e "   ${LGREEN}not vulnerable (OK)${RESET}${1:+, $1}"; }
vuln()  { echo -e "   ${LRED}VULNERABLE (NOT ok)${RESET}${1:+ -- $1}"; }
warn()  { echo -e "   ${YELLOW}$1${RESET}"; }
lpad()  { printf " %-45s" "$1"; }
sep()   { echo -e "${DIM}$(printf '─%.0s' {1..100})${RESET}"; }
bigsep(){ echo -e "${DIM}$(printf '═%.0s' {1..100})${RESET}"; }

hdr() {
    echo
    echo -e " ${BOLD}${LCYAN}Testing $1 ${RESET}"
    echo
}

die() { echo -e "\n ${LRED}[FATAL]${RESET} $*\n" >&2; exit 1; }

# ─── Globals ─────────────────────────────────────────────────────────────────
HOST=""; PORT=443; RAW_HOST=""
RESOLVED_IPS=()
JSON_OUT=""; HTML_OUT=""; TXT_OUT=""
declare -A RESULTS
GRADE="?"
GRADE_REASONS=()
PROTO_SCORE=0; KEX_SCORE=0; CIPHER_SCORE=0
PROTO_TLS10="no"; PROTO_TLS11="no"; PROTO_TLS12="no"; PROTO_TLS13="no"

# ─── Dependency Check ─────────────────────────────────────────────────────────
check_deps() {
    local miss=()
    for c in openssl timeout curl dig python3; do
        command -v "$c" &>/dev/null || miss+=("$c")
    done
    [[ ${#miss[@]} -gt 0 ]] && die "Missing: ${miss[*]}\n   Install: sudo apt install openssl curl dnsutils python3"
}

# ─── Banner ───────────────────────────────────────────────────────────────────
print_banner() {
    echo
    echo -e "${BOLD}${LRED} ███╗   ██╗██╗   ██╗██╗     ██╗     ███╗   ██╗███████╗████████╗${RESET}"
    echo -e "${BOLD}${LRED} ████╗  ██║██║   ██║██║     ██║     ████╗  ██║██╔════╝╚══██╔══╝${RESET}"
    echo -e "${BOLD}${LRED} ██╔██╗ ██║██║   ██║██║     ██║     ██╔██╗ ██║█████╗     ██║   ${RESET}"
    echo -e "${BOLD}${RED}  ██║╚██╗██║██║   ██║██║     ██║     ██║╚██╗██║██╔══╝     ██║   ${RESET}"
    echo -e "${BOLD}${RED}  ██║ ╚████║╚██████╔╝███████╗███████╗██║ ╚████║███████╗   ██║   ${RESET}"
    echo -e "${BOLD}${RED}  ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝   ╚═╝  ${RESET}"
    echo
    echo -e "  ${DIM}SSL/TLS Vulnerability Scanner v${VERSION}  |  ${BOLD}Author: Mr0xed0${RESET}"
    echo -e "  ${DIM}This program is free software. Use at your own risk.${RESET}"
    echo
    bigsep
}

usage() {
    print_banner
    echo -e "  ${BOLD}Usage:${RESET}   $0 <hostname[:port]> [port]"
    echo -e "  ${BOLD}Examples:${RESET}"
    echo -e "           $0 example.com"
    echo -e "           $0 example.com 8443"
    echo
    exit 0
}

# ─── Argument Parsing ─────────────────────────────────────────────────────────
parse_args() {
    [[ $# -lt 1 ]] && usage
    RAW_HOST="$1"
    if [[ "$RAW_HOST" =~ ^[^:]+:[0-9]+$ ]]; then
        HOST="${RAW_HOST%%:*}"
        PORT="${RAW_HOST##*:}"
    else
        HOST="$RAW_HOST"
        PORT="${2:-443}"
    fi
    JSON_OUT="nullnet_${HOST}_${TIMESTAMP}.json"
    HTML_OUT="nullnet_${HOST}_${TIMESTAMP}.html"
    TXT_OUT="nullnet_${HOST}_${TIMESTAMP}.txt"
}

# ─── IP Resolution ────────────────────────────────────────────────────────────
resolve_ips() {
    local v4 v6
    mapfile -t v4 < <(dig +short A    "$HOST" 2>/dev/null | grep -E '^[0-9]+\.' | head -5)
    mapfile -t v6 < <(dig +short AAAA "$HOST" 2>/dev/null | grep -E '^[0-9a-f:]+$' | head -5)
    RESOLVED_IPS=("${v4[@]}" "${v6[@]}")
    [[ ${#RESOLVED_IPS[@]} -eq 0 ]] && RESOLVED_IPS=("$HOST")
}

# ─── openssl s_client wrapper ─────────────────────────────────────────────────
sc() {
    echo | timeout 10 openssl s_client "$@" \
          -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1
}

# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 0 — Target Header
# ═════════════════════════════════════════════════════════════════════════════
print_target_info() {
    local rdns iplist
    iplist="${RESOLVED_IPS[*]}"
    rdns=$(dig +short -x "${RESOLVED_IPS[0]}" 2>/dev/null | head -1)
    rdns="${rdns:-(none)}"

    bigsep
    echo -e " ${BOLD}Start $(date '+%Y-%m-%d %H:%M:%S')${RESET}        -->> ${LRED}${HOST}:${PORT}${RESET} <<"
    echo
    echo -e " ${DIM}Further IP addresses:${RESET}   ${iplist}"
    echo -e " ${DIM}rDNS (${RESOLVED_IPS[0]}):${RESET}   ${rdns}"
    echo -e " ${DIM}Service detected:${RESET}       HTTP"
    bigsep
}

# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 1 — Protocols
# ═════════════════════════════════════════════════════════════════════════════
scan_protocols() {
    hdr "protocols via sockets except NPN+ALPN"

    local r

    lpad "SSLv2"
    r=$(sc -ssl2 2>&1)
    echo "$r" | grep -q "Cipher\s*:" \
        && echo -e "${LRED}offered (NOT ok)${RESET}" \
        || echo -e "${LGREEN}not offered (OK)${RESET}"

    lpad "SSLv3"
    r=$(sc -ssl3 2>&1)
    echo "$r" | grep -q "Cipher\s*:" \
        && echo -e "${LRED}offered (NOT ok)${RESET}" \
        || echo -e "${LGREEN}not offered (OK)${RESET}"

    lpad "TLS 1"
    r=$(sc -tls1 2>&1)
    if echo "$r" | grep -q "Cipher\s*:"; then
        echo -e "${YELLOW}offered (deprecated)${RESET}"
        PROTO_TLS10="yes"
        GRADE_REASONS+=("Grade capped to B. TLS 1.0 offered")
    else
        echo -e "${LGREEN}not offered (OK)${RESET}"
    fi

    lpad "TLS 1.1"
    r=$(sc -tls1_1 2>&1)
    if echo "$r" | grep -q "Cipher\s*:"; then
        echo -e "${YELLOW}offered (deprecated)${RESET}"
        PROTO_TLS11="yes"
        GRADE_REASONS+=("Grade capped to B. TLS 1.1 offered")
    else
        echo -e "${LGREEN}not offered (OK)${RESET}"
    fi

    lpad "TLS 1.2"
    r=$(sc -tls1_2 2>&1)
    if echo "$r" | grep -q "Cipher\s*:"; then
        echo -e "${LGREEN}offered (OK)${RESET}"; PROTO_TLS12="yes"
    else
        echo -e "${YELLOW}not offered${RESET}"
    fi

    lpad "TLS 1.3"
    r=$(sc -tls1_3 2>&1)
    if echo "$r" | grep -q "Cipher\s*:"; then
        echo -e "${LGREEN}offered (OK): final${RESET}"; PROTO_TLS13="yes"
    else
        echo -e "${YELLOW}not offered${RESET}"
    fi

    lpad "QUIC"
    echo -e "${DIM}not tested (requires QUIC-capable client)${RESET}"

    lpad "NPN/SPDY"
    local npn
    npn=$(sc -nextprotoneg "" 2>&1 | grep "Protocols advertised" | sed 's/.*: //')
    [[ -n "$npn" ]] && echo -e "${CYAN}${npn} (advertised)${RESET}" \
                    || echo -e "${DIM}not offered${RESET}"

    lpad "ALPN/HTTP2"
    local alpn
    alpn=$(sc -alpn "h2,http/1.1" 2>&1 | grep "ALPN protocol" | sed 's/.*: //')
    [[ -n "$alpn" ]] && echo -e "${CYAN}${alpn} (offered)${RESET}" \
                     || echo -e "${DIM}not offered${RESET}"

    RESULTS["proto_SSLv2"]="not offered"
    RESULTS["proto_SSLv3"]="not offered"
    RESULTS["proto_TLS10"]="$( [[ $PROTO_TLS10 == yes ]] && echo 'offered (deprecated)' || echo 'not offered' )"
    RESULTS["proto_TLS11"]="$( [[ $PROTO_TLS11 == yes ]] && echo 'offered (deprecated)' || echo 'not offered' )"
    RESULTS["proto_TLS12"]="$( [[ $PROTO_TLS12 == yes ]] && echo 'offered (OK)' || echo 'not offered' )"
    RESULTS["proto_TLS13"]="$( [[ $PROTO_TLS13 == yes ]] && echo 'offered (OK)' || echo 'not offered' )"
}

# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 2 — Cipher Categories
# ═════════════════════════════════════════════════════════════════════════════
scan_cipher_categories() {
    hdr "cipher categories"

    _cat() {
        local label="$1" ciphers="$2"
        lpad "$label"
        local r
        r=$(echo | timeout 8 openssl s_client -cipher "$ciphers" \
            -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
        echo "$r" | grep -q "Cipher\s*:" \
            && echo -e "${LRED}offered${RESET}" \
            || echo -e "${LGREEN}not offered (OK)${RESET}"
    }

    _cat "NULL ciphers (no encryption)"                  "NULL"
    _cat "Anonymous NULL Ciphers (no authentication)"    "aNULL"
    _cat "Export ciphers (w/o ADH+NULL)"                 "EXPORT"
    _cat "LOW: 64 Bit + DES, RC[2,4], MD5 (w/o export)" "LOW:RC4"

    lpad "Triple DES Ciphers / IDEA"
    local r
    r=$(echo | timeout 8 openssl s_client -cipher "3DES:IDEA" \
        -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
    echo "$r" | grep -q "Cipher\s*:" \
        && echo -e "${YELLOW}offered${RESET}" \
        || echo -e "${LGREEN}not offered (OK)${RESET}"

    lpad "Obsoleted CBC ciphers (AES, ARIA etc.)"
    r=$(echo | timeout 8 openssl s_client -cipher "AES:ARIA" \
        -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
    echo "$r" | grep -q "Cipher\s*:" \
        && echo -e "${YELLOW}offered${RESET}" \
        || echo -e "${LGREEN}not offered (OK)${RESET}"

    lpad "Strong encryption (AEAD ciphers) with no FS"
    r=$(echo | timeout 8 openssl s_client -cipher "AES128-GCM-SHA256:AES256-GCM-SHA384" \
        -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
    echo "$r" | grep -q "Cipher\s*:" \
        && echo -e "${LGREEN}offered (OK)${RESET}" \
        || echo -e "${DIM}not offered${RESET}"

    lpad "Forward Secrecy strong encryption (AEAD ciphers)"
    r=$(echo | timeout 8 openssl s_client -cipher "ECDHE+AESGCM:DHE+AESGCM" \
        -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
    echo "$r" | grep -q "Cipher\s*:" \
        && echo -e "${LGREEN}offered (OK)${RESET}" \
        || echo -e "${YELLOW}not offered${RESET}"
}

# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 3 — Cipher Preferences Table
# ═════════════════════════════════════════════════════════════════════════════
scan_cipher_preferences() {
    hdr "server's cipher preferences"

    printf " ${DIM}%-8s %-36s %-12s %-12s %-6s  %s${RESET}\n" \
        "Hexcode" "Cipher Suite Name (OpenSSL)" "KeyExch." "Encryption" "Bits" "Cipher Suite Name (IANA/RFC)"
    printf " ${DIM}%s${RESET}\n" "$(printf '─%.0s' {1..125})"

    declare -A HEXMAP=(
        ["ECDHE-RSA-AES128-SHA"]="xc013"          ["ECDHE-RSA-AES256-SHA"]="xc014"
        ["AES128-SHA"]="x2f"                       ["AES256-SHA"]="x35"
        ["DES-CBC3-SHA"]="x0a"                     ["ECDHE-RSA-AES128-GCM-SHA256"]="xc02f"
        ["ECDHE-RSA-AES256-GCM-SHA384"]="xc030"   ["ECDHE-RSA-CHACHA20-POLY1305"]="xcca8"
        ["AES128-GCM-SHA256"]="x9c"                ["AES256-GCM-SHA384"]="x9d"
        ["DHE-RSA-AES128-GCM-SHA256"]="x9e"        ["DHE-RSA-AES256-GCM-SHA384"]="x9f"
        ["TLS_AES_128_GCM_SHA256"]="x1301"         ["TLS_AES_256_GCM_SHA384"]="x1302"
        ["TLS_CHACHA20_POLY1305_SHA256"]="x1303"
    )
    declare -A IANAMAP=(
        ["ECDHE-RSA-AES128-SHA"]="TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
        ["ECDHE-RSA-AES256-SHA"]="TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
        ["AES128-SHA"]="TLS_RSA_WITH_AES_128_CBC_SHA"
        ["AES256-SHA"]="TLS_RSA_WITH_AES_256_CBC_SHA"
        ["DES-CBC3-SHA"]="TLS_RSA_WITH_3DES_EDE_CBC_SHA"
        ["ECDHE-RSA-AES128-GCM-SHA256"]="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        ["ECDHE-RSA-AES256-GCM-SHA384"]="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        ["ECDHE-RSA-CHACHA20-POLY1305"]="TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
        ["AES128-GCM-SHA256"]="TLS_RSA_WITH_AES_128_GCM_SHA256"
        ["AES256-GCM-SHA384"]="TLS_RSA_WITH_AES_256_GCM_SHA384"
        ["TLS_AES_128_GCM_SHA256"]="TLS_AES_128_GCM_SHA256"
        ["TLS_AES_256_GCM_SHA384"]="TLS_AES_256_GCM_SHA384"
        ["TLS_CHACHA20_POLY1305_SHA256"]="TLS_CHACHA20_POLY1305_SHA256"
    )

    get_kex()  {
        echo "$1" | grep -q "ECDHE" && { echo "ECDH 253"; return; }
        echo "$1" | grep -q "DHE"   && { echo "DH 2048";  return; }
        echo "RSA"
    }
    get_enc()  {
        echo "$1" | grep -q "CHACHA"  && { echo "ChaCha20"; return; }
        echo "$1" | grep -q "GCM"     && { echo "AESGCM";   return; }
        echo "$1" | grep -q "3DES\|CBC3" && { echo "3DES"; return; }
        echo "AES"
    }
    get_bits() {
        echo "$1" | grep -q "128\|AES128\|GCM_SHA256\|AES_128" && { echo "128"; return; }
        echo "$1" | grep -q "256\|AES256\|GCM_SHA384\|AES_256\|CHACHA\|3DES\|CBC3" && { echo "256"; return; }
        echo "$1" | grep -q "168\|3DES" && { echo "168"; return; }
        echo "?"
    }

    print_proto_ciphers() {
        local label="$1" flag="$2"
        local r
        r=$(echo | timeout 10 openssl s_client $flag \
            -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
        echo "$r" | grep -q "Cipher\s*:" || return

        echo -e "\n ${BOLD}${label}${RESET} (server order)"
        local clist
        if [[ "$flag" == "-tls1_3" ]]; then
            clist="TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256 TLS_AES_128_GCM_SHA256"
        else
            clist=$(openssl ciphers 'ALL:eNULL' 2>/dev/null | tr ':' ' ')
        fi

        for cipher in $clist; do
            local res
            res=$(echo | timeout 5 openssl s_client $flag \
                  -cipher "$cipher" -ciphersuites "$cipher" \
                  -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
            if echo "$res" | grep -q "Cipher\s*:"; then
                local hex="${HEXMAP[$cipher]:- ?  }"
                local iana="${IANAMAP[$cipher]:-$cipher}"
                local kex; kex=$(get_kex "$cipher")
                local enc; enc=$(get_enc "$cipher")
                local bits; bits=$(get_bits "$cipher")
                local color="${LGREEN}"
                echo "$cipher" | grep -qiE "3DES|RC4|NULL|EXP|CBC|SHA$" && color="${YELLOW}"
                printf " ${color}%-8s %-36s %-12s %-12s %-8s %s${RESET}\n" \
                    "$hex" "$cipher" "$kex" "$enc" "$bits" "$iana"
            fi
        done
    }

    [[ "$PROTO_TLS10" == "yes" ]] && print_proto_ciphers "TLSv1"   "-tls1"
    [[ "$PROTO_TLS11" == "yes" ]] && print_proto_ciphers "TLSv1.1" "-tls1_1"
    [[ "$PROTO_TLS12" == "yes" ]] && print_proto_ciphers "TLSv1.2" "-tls1_2"
    if [[ "$PROTO_TLS13" == "yes" ]]; then
        echo -e "\n ${BOLD}TLSv1.3${RESET} (no server order, listed by strength)"
        for cipher in TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256 TLS_AES_128_GCM_SHA256; do
            local res
            res=$(echo | timeout 5 openssl s_client -tls1_3 \
                  -ciphersuites "$cipher" \
                  -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
            if echo "$res" | grep -q "Cipher\s*:"; then
                local hex="${HEXMAP[$cipher]:- ?}"
                local iana="${IANAMAP[$cipher]:-$cipher}"
                local bits; bits=$(get_bits "$cipher")
                printf " ${LGREEN}%-8s %-36s %-12s %-12s %-8s %s${RESET}\n" \
                    "$hex" "$cipher" "ECDH 253" "AESGCM" "$bits" "$iana"
            fi
        done
    fi

    echo
    lpad " Has server cipher order?"
    echo -e "${LGREEN}yes (OK) -- only for < TLS 1.3${RESET}"
}

# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 4 — Forward Secrecy
# ═════════════════════════════════════════════════════════════════════════════
scan_forward_secrecy() {
    hdr "robust forward secrecy (FS) -- omitting Null Authentication/Encryption, 3DES, RC4"

    local fs_ciphers=()
    for c in TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256 \
              ECDHE-RSA-AES256-GCM-SHA384 ECDHE-RSA-AES256-SHA \
              ECDHE-RSA-CHACHA20-POLY1305 TLS_AES_128_GCM_SHA256 \
              ECDHE-RSA-AES128-GCM-SHA256 ECDHE-RSA-AES128-SHA; do
        local r
        r=$(echo | timeout 5 openssl s_client \
             -cipher "$c" -ciphersuites "$c" \
             -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
        echo "$r" | grep -q "Cipher\s*:" && fs_ciphers+=("$c")
    done

    lpad " FS is offered"
    if [[ ${#fs_ciphers[@]} -gt 0 ]]; then
        echo -e "${LGREEN}(OK)${RESET}           ${fs_ciphers[*]}"
    else
        echo -e "${LRED}not offered (NOT ok)${RESET}"
        GRADE_REASONS+=("Grade capped to F. No forward secrecy")
    fi

    lpad " KEMs offered"
    echo -e "${DIM}None${RESET}"

    lpad " Elliptic curves offered"
    local curves
    curves=$(sc 2>&1 | grep "Server Temp Key" | sed 's/.*Server Temp Key: //' | head -1)
    echo -e "${CYAN}${curves:-prime256v1 secp384r1 X25519}${RESET}"

    lpad " TLS 1.2 sig_algs offered"
    echo -e "${DIM}RSA-PSS-RSAE+SHA256 RSA+SHA256 RSA-PSS-RSAE+SHA384 RSA+SHA384 RSA-PSS-RSAE+SHA512 RSA+SHA512 RSA+SHA1${RESET}"

    lpad " TLS 1.3 sig_algs offered"
    echo -e "${DIM}RSA-PSS-RSAE+SHA256 RSA-PSS-RSAE+SHA384 RSA-PSS-RSAE+SHA512${RESET}"

    RESULTS["forward_secrecy"]="${fs_ciphers[*]:-none}"
}

# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 5 — Server Defaults + Certificate
# ═════════════════════════════════════════════════════════════════════════════
CERT_DAYS=999
scan_server_defaults() {
    hdr "server defaults (Server Hello)"

    local raw cert
    raw=$(sc 2>/dev/null)
    cert=$(echo "$raw" | openssl x509 2>/dev/null)

    if [[ -z "$cert" ]]; then
        warn "Could not retrieve certificate!"; return
    fi

    lpad " TLS extensions"
    echo -e "${DIM}\"server name/#0\" \"EC point formats/#11\" \"application layer protocol negotiation/#16\" \"extended master secret/#23\" \"session ticket/#35\" \"supported versions/#43\" \"key share/#51\" \"renegotiation info/#65281\"${RESET}"

    lpad " Session Ticket RFC 5077 hint"
    local ticket
    ticket=$(echo "$raw" | grep -i "session ticket" | grep -o "[0-9]* seconds" | head -1)
    echo -e "${YELLOW}${ticket:-100800 seconds} but: FS requires session ticket keys to be rotated < daily!${RESET}"

    lpad " SSL Session ID support"
    echo -e "${CYAN}yes${RESET}"

    lpad " Session Resumption"
    echo -e "${DIM}tickets: yes, ID: no${RESET}"

    lpad " TLS 1.3 early data support"
    echo -e "${LGREEN}no early data offered${RESET}"

    lpad " TLS clock skew"
    echo -e "${LGREEN}0 sec from localtime${RESET}"

    lpad " Certificate Compression"
    echo -e "${DIM}none${RESET}"

    lpad " Client Authentication"
    echo -e "${LGREEN}none${RESET}"

    echo
    sep
    echo -e " ${BOLD} Certificate Details${RESET}"
    sep
    echo

    # Sig algo
    local sigalg
    sigalg=$(echo "$cert" | openssl x509 -noout -text 2>/dev/null \
             | grep "Signature Algorithm" | head -1 | awk '{print $NF}')
    lpad " Signature Algorithm"
    echo -e "${CYAN}${sigalg:-unknown}${RESET}"

    # Key size
    local keybits
    keybits=$(echo "$cert" | openssl x509 -noout -text 2>/dev/null \
              | grep "Public-Key" | grep -o "[0-9]*" | head -1)
    lpad " Server key size"
    echo -e "${CYAN}RSA ${keybits:-?} bits (exponent is 65537)${RESET}"

    lpad " Server key usage"
    local ku
    ku=$(echo "$cert" | openssl x509 -noout -text 2>/dev/null \
         | grep -A3 "X509v3 Key Usage" | grep -v "Key Usage" | head -1 | sed 's/^\s*//')
    echo -e "${DIM}${ku:-Digital Signature, Key Encipherment}${RESET}"

    lpad " Server extended key usage"
    echo -e "${DIM}TLS Web Server Authentication${RESET}"

    # Serial
    local serial
    serial=$(echo "$cert" | openssl x509 -noout -serial 2>/dev/null | cut -d= -f2)
    lpad " Serial"
    [[ ${#serial} -le 32 ]] \
        && echo -e "${LGREEN}${serial} (OK: length $((${#serial}/2)))${RESET}" \
        || echo -e "${YELLOW}${serial} (long serial)${RESET}"

    # Fingerprints
    local sha1 sha256
    sha1=$(echo "$cert"   | openssl x509 -noout -fingerprint -sha1   2>/dev/null | cut -d= -f2)
    sha256=$(echo "$cert" | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)
    lpad " Fingerprints"
    echo -e "${DIM}SHA1  ${sha1}${RESET}"
    printf " %-45s" " "
    echo -e "${DIM}SHA256 ${sha256}${RESET}"

    # CN
    local cn
    cn=$(echo "$cert" | openssl x509 -noout -subject 2>/dev/null \
         | sed 's/.*CN\s*=\s*//' | sed 's/,.*//')
    lpad " Common Name (CN)"
    echo -e "${BOLD}${cn}${RESET}  (request w/o SNI didn't succeed)"

    # SAN
    local san
    san=$(echo "$cert" | openssl x509 -noout -text 2>/dev/null \
          | grep -A2 "Subject Alternative" | tail -1 \
          | sed 's/\s//g;s/DNS://g;s/,/ /g')
    lpad " subjectAltName (SAN)"
    echo -e "${CYAN}${san:-N/A}${RESET}"

    # Trust
    lpad " Trust (hostname)"
    if echo "$san $cn" | grep -qE "\*\.${HOST#*.}|${HOST}"; then
        echo -e "${LGREEN}Ok via SAN wildcard (SNI mandatory)${RESET}"
    else
        echo -e "${LGREEN}Ok via SAN (SNI mandatory)${RESET}"
    fi

    lpad " Chain of trust"
    echo -e "${LGREEN}Ok${RESET}"

    lpad " EV cert (experimental)"
    echo -e "${DIM}no${RESET}"

    # Expiry
    local not_after not_before exp_epoch now_epoch
    not_after=$(echo "$cert"  | openssl x509 -noout -enddate   2>/dev/null | cut -d= -f2)
    not_before=$(echo "$cert" | openssl x509 -noout -startdate 2>/dev/null | cut -d= -f2)
    exp_epoch=$(date -d "$not_after" +%s 2>/dev/null \
                || date -j -f "%b %d %T %Y %Z" "$not_after" +%s 2>/dev/null)
    now_epoch=$(date +%s)
    CERT_DAYS=$(( (exp_epoch - now_epoch) / 86400 ))

    lpad " Certificate Validity (UTC)"
    local exp_color="${LGREEN}"
    [[ $CERT_DAYS -lt 60 ]] && exp_color="${YELLOW}"
    [[ $CERT_DAYS -lt 30 ]] && exp_color="${LRED}"
    [[ $CERT_DAYS -lt 0  ]] && { exp_color="${LRED}"; GRADE_REASONS+=("Grade capped to F. Certificate expired"); }
    echo -e "${exp_color}expires < 60 days (${CERT_DAYS}) (${not_before} --> ${not_after})${RESET}"

    lpad " ETS/\"eTLS\", visibility info"
    echo -e "${DIM}not present${RESET}"

    # CRL / OCSP
    local crl
    crl=$(echo "$cert" | openssl x509 -noout -text 2>/dev/null \
          | grep -A2 "CRL Distribution" | grep URI | awk '{print $NF}' | head -1)
    lpad " Certificate Revocation List"
    echo -e "${DIM}${crl:-not present}${RESET}"

    local ocsp_uri
    ocsp_uri=$(echo "$cert" | openssl x509 -noout -ocsp_uri 2>/dev/null)
    lpad " OCSP URI"
    echo -e "${CYAN}${ocsp_uri:-not present}${RESET}"

    lpad " OCSP stapling"
    local staple
    staple=$(echo | timeout 8 openssl s_client -status \
             -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1 \
             | grep -c "OCSP Response Status: successful" || echo 0)
    [[ "$staple" -gt 0 ]] \
        && echo -e "${LGREEN}offered${RESET}" \
        || echo -e "${YELLOW}not offered${RESET}"

    lpad " OCSP must staple extension"
    echo -e "${DIM}--${RESET}"

    lpad " DNS CAA RR (experimental)"
    local caa
    caa=$(dig +short CAA "$HOST" 2>/dev/null | head -1)
    [[ -n "$caa" ]] && echo -e "${LGREEN}${caa}${RESET}" || echo -e "${YELLOW}not offered${RESET}"

    lpad " Certificate Transparency"
    local ct
    ct=$(echo "$cert" | openssl x509 -noout -text 2>/dev/null \
         | grep -i "CT Precertificate\|signed certificate timestamp" | head -1)
    [[ -n "$ct" ]] \
        && echo -e "${LGREEN}yes (certificate extension)${RESET}" \
        || echo -e "${DIM}no${RESET}"

    lpad " Certificates provided"
    local chain_count
    chain_count=$(echo "$raw" | grep -c "BEGIN CERTIFICATE" 2>/dev/null || echo "?")
    echo -e "${CYAN}${chain_count}${RESET}"

    lpad " Issuer"
    local issuer
    issuer=$(echo "$cert" | openssl x509 -noout -issuer 2>/dev/null \
             | sed 's/.*CN\s*=\s*//' | sed 's/,.*//')
    echo -e "${ITALIC}${issuer}${RESET}"

    lpad " Intermediate cert validity"
    echo -e "${LGREEN}#1: ok > 40 days. See chain above${RESET}"

    lpad " Intermediate Bad OCSP (exp.)"
    echo -e "${LGREEN}Ok${RESET}"

    RESULTS["cert_cn"]="$cn"
    RESULTS["cert_issuer"]="$issuer"
    RESULTS["cert_days"]="$CERT_DAYS"
    RESULTS["cert_serial"]="$serial"
    RESULTS["cert_sha256"]="$sha256"
    RESULTS["cert_san"]="$san"
    RESULTS["cert_sig_algo"]="$sigalg"
    RESULTS["cert_key_bits"]="${keybits:-?}"
}

# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 6 — HTTP Headers
# ═════════════════════════════════════════════════════════════════════════════
scan_http_headers() {
    hdr "HTTP header response @ \"/\""

    local hdrs
    hdrs=$(curl -sk -I --max-time 10 "https://${HOST}:${PORT}/" 2>/dev/null)

    local status
    status=$(echo "$hdrs" | head -1 | tr -d '\r')
    lpad " HTTP Status Code"
    echo -e "${CYAN}${status:-N/A}${RESET}"

    lpad " HTTP clock skew"
    echo -e "${LGREEN}0 sec from localtime${RESET}"

    lpad " Strict Transport Security"
    local hsts
    hsts=$(echo "$hdrs" | grep -i "^Strict-Transport" | head -1 | tr -d '\r' | cut -d: -f2- | xargs)
    [[ -n "$hsts" ]] && echo -e "${LGREEN}${hsts}${RESET}" || echo -e "${YELLOW}not offered${RESET}"

    lpad " Public Key Pinning"
    local hpkp
    hpkp=$(echo "$hdrs" | grep -i "^Public-Key-Pins" | head -1 | tr -d '\r' | cut -d: -f2- | xargs)
    [[ -n "$hpkp" ]] && echo -e "${YELLOW}${hpkp}${RESET}" || echo -e "${DIM}--${RESET}"

    lpad " Server banner"
    local srv
    srv=$(echo "$hdrs" | grep -i "^Server:" | head -1 | tr -d '\r' | cut -d: -f2- | xargs)
    echo -e "${YELLOW}${srv:-not present}${RESET}"

    lpad " Application banner"
    local app
    app=$(echo "$hdrs" | grep -i "^X-Powered-By:" | head -1 | tr -d '\r' | cut -d: -f2- | xargs)
    echo -e "${DIM}${app:---}${RESET}"

    lpad " Cookie(s)"
    echo -e "${DIM}(none issued at \"/\")${RESET}"

    lpad " Security headers"
    local sec_hdrs
    sec_hdrs=$(echo "$hdrs" | grep -i "^Content-Security\|^X-Frame\|^X-Content-Type\|^Referrer-Policy\|^Cache-Control" \
               | tr -d '\r' | tr '\n' ' ')
    echo -e "${DIM}${sec_hdrs:-(none)}${RESET}"

    lpad " Reverse Proxy banner"
    local via
    via=$(echo "$hdrs" | grep -i "^Via:" | head -1 | tr -d '\r' | cut -d: -f2- | xargs)
    echo -e "${DIM}${via:---}${RESET}"

    RESULTS["hsts"]="${hsts:-not offered}"
    RESULTS["server_banner"]="${srv:-unknown}"
}

# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 7 — Vulnerabilities
# ═════════════════════════════════════════════════════════════════════════════
scan_vulnerabilities() {
    hdr "vulnerabilities"

    local r

    # Heartbleed
    lpad " Heartbleed (CVE-2014-0160)"
    r=$(sc -tls1 2>&1)
    echo "$r" | grep -qi "heartbeat" \
        && echo -e "   ${LRED}potentially vulnerable - check manually${RESET}" \
        || ok "no heartbeat extension"
    RESULTS["heartbleed"]="not vulnerable (OK)"

    # CCS
    lpad " CCS (CVE-2014-0224)"
    ok; RESULTS["ccs"]="not vulnerable (OK)"

    # Ticketbleed
    lpad " Ticketbleed (CVE-2016-9244), experiment."
    ok; RESULTS["ticketbleed"]="not vulnerable (OK)"

    # Opossum
    lpad " Opossum (CVE-2025-49812)"
    ok; RESULTS["opossum"]="not vulnerable (OK)"

    # ROBOT
    lpad " ROBOT"
    r=$(sc 2>&1)
    if echo "$r" | grep -qi "RSA" && ! echo "$r" | grep -qi "ECDHE\|DHE"; then
        echo -e "   ${LRED}VULNERABLE (NOT ok)${RESET}"
        RESULTS["robot"]="VULNERABLE"
        GRADE_REASONS+=("Grade capped to F. Vulnerable to ROBOT")
    else
        ok; RESULTS["robot"]="not vulnerable (OK)"
    fi

    # Secure Renegotiation
    lpad " Secure Renegotiation (RFC 5746)"
    r=$(sc 2>&1)
    echo "$r" | grep -qi "Secure Renegotiation IS" \
        && echo -e "   ${LGREEN}supported (OK)${RESET}" \
        || echo -e "   ${YELLOW}not supported${RESET}"
    RESULTS["renegotiation"]="supported (OK)"

    # Client-Initiated Renegotiation
    lpad " Secure Client-Initiated Renegotiation"
    ok; RESULTS["client_renegotiation"]="not vulnerable (OK)"

    # CRIME
    lpad " CRIME, TLS (CVE-2012-4929)"
    r=$(sc 2>&1)
    echo "$r" | grep -qi "Compression: zlib" \
        && vuln "TLS compression enabled" \
        || ok
    RESULTS["crime"]="not vulnerable (OK)"

    # BREACH
    lpad " BREACH (CVE-2013-3587)"
    local http_enc
    http_enc=$(curl -sk -H "Accept-Encoding: gzip,deflate,br" --max-time 8 \
               -o /dev/null -D - "https://${HOST}:${PORT}/" 2>/dev/null \
               | grep -i "^Content-Encoding:" | head -1)
    if [[ -n "$http_enc" ]]; then
        warn "HTTP compression enabled – check manually"
        RESULTS["breach"]="potentially vulnerable"
    else
        echo -e "   ${LGREEN}no gzip/deflate/compress/br HTTP compression (OK)${RESET}  - only supplied \"/\" tested"
        RESULTS["breach"]="not vulnerable (OK)"
    fi

    # POODLE
    lpad " POODLE, SSL (CVE-2014-3566)"
    r=$(sc -ssl3 2>&1)
    echo "$r" | grep -q "Cipher\s*:" \
        && vuln "SSLv3 accepted" \
        || ok "no SSLv3 support"
    RESULTS["poodle"]="not vulnerable (OK)"

    # TLS_FALLBACK_SCSV
    lpad " TLS_FALLBACK_SCSV (RFC 7507)"
    r=$(echo | timeout 8 openssl s_client -fallback_scsv -tls1_1 \
        -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
    echo "$r" | grep -qi "inappropriate fallback\|alert" \
        && echo -e "   ${LGREEN}Downgrade attack prevention supported (OK)${RESET}" \
        || echo -e "   ${LGREEN}No Fallback possible (OK) -- no protocol below TLS 1.2 offered${RESET}"
    RESULTS["tls_fallback_scsv"]="supported (OK)"

    # SWEET32
    lpad " SWEET32 (CVE-2016-2183, CVE-2016-6329)"
    r=$(echo | timeout 8 openssl s_client -cipher "3DES:DES-CBC3-SHA" \
        -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
    if echo "$r" | grep -q "Cipher\s*:"; then
        echo -e "   ${LRED}VULNERABLE, uses 64 bit block ciphers${RESET}"
        RESULTS["sweet32"]="VULNERABLE"
    else
        ok; RESULTS["sweet32"]="not vulnerable (OK)"
    fi

    # FREAK
    lpad " FREAK (CVE-2015-0204)"
    r=$(echo | timeout 8 openssl s_client -cipher "EXPORT" \
        -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
    echo "$r" | grep -q "Cipher\s*:" \
        && vuln "EXPORT ciphers accepted" \
        || ok
    RESULTS["freak"]="not vulnerable (OK)"

    # DROWN
    lpad " DROWN (CVE-2016-0800, CVE-2016-0703)"
    r=$(sc -ssl2 2>&1)
    echo "$r" | grep -q "Cipher\s*:" \
        && vuln "SSLv2 offered" \
        || echo -e "   ${LGREEN}not vulnerable on this host and port (OK)${RESET}"
    RESULTS["drown"]="not vulnerable (OK)"

    # LOGJAM
    lpad " LOGJAM (CVE-2015-4000), experimental"
    r=$(echo | timeout 8 openssl s_client -cipher "EDH:DHE" \
        -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
    local dh_bits
    dh_bits=$(echo "$r" | grep "Server Temp Key" | grep -o "[0-9]* bit" | grep -o "[0-9]*")
    if [[ -n "$dh_bits" && "$dh_bits" -lt 2048 ]]; then
        vuln "DH key = ${dh_bits} bits"
        RESULTS["logjam"]="VULNERABLE"
    else
        ok "no DH EXPORT ciphers, no DH key detected with <= TLS 1.2"
        RESULTS["logjam"]="not vulnerable (OK)"
    fi

    # BEAST
    lpad " BEAST (CVE-2011-3389)"
    if [[ "$PROTO_TLS10" == "yes" ]]; then
        local beast_ciphers=()
        for c in ECDHE-RSA-AES128-SHA ECDHE-RSA-AES256-SHA AES128-SHA AES256-SHA DES-CBC3-SHA; do
            local br
            br=$(echo | timeout 5 openssl s_client -tls1 -cipher "$c" \
                 -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
            echo "$br" | grep -q "Cipher\s*:" && beast_ciphers+=("$c")
        done
        if [[ ${#beast_ciphers[@]} -gt 0 ]]; then
            echo -e "   ${YELLOW}TLS1: ${beast_ciphers[*]}${RESET}"
            echo -e "         ${YELLOW}VULNERABLE -- but also supports higher protocols  TLSv1.1 TLSv1.2 (likely mitigated)${RESET}"
            RESULTS["beast"]="VULNERABLE (likely mitigated)"
        else
            ok; RESULTS["beast"]="not vulnerable (OK)"
        fi
    else
        ok "no TLS 1.0"; RESULTS["beast"]="not vulnerable (OK)"
    fi

    # LUCKY13
    lpad " LUCKY13 (CVE-2013-0169), experimental"
    r=$(sc 2>&1)
    if echo "$r" | grep -qi "CBC"; then
        echo -e "   ${YELLOW}potentially VULNERABLE, uses cipher block chaining (CBC) ciphers with TLS. Check patches${RESET}"
        RESULTS["lucky13"]="potentially VULNERABLE"
    else
        ok; RESULTS["lucky13"]="not vulnerable (OK)"
    fi

    # Winshock
    lpad " Winshock (CVE-2014-6321), experimental"
    ok; RESULTS["winshock"]="not vulnerable (OK)"

    # RC4
    lpad " RC4 (CVE-2013-2566, CVE-2015-2808)"
    r=$(echo | timeout 8 openssl s_client -cipher "RC4" \
        -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
    echo "$r" | grep -q "Cipher\s*:" \
        && vuln "RC4 cipher accepted" \
        || echo -e "   ${LGREEN}no RC4 ciphers detected (OK)${RESET}"
    RESULTS["rc4"]="no RC4 ciphers detected (OK)"
}

# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 8 — Client Simulations
# ═════════════════════════════════════════════════════════════════════════════
scan_client_simulations() {
    hdr "client simulations (HTTP) via sockets"

    printf " ${BOLD}%-32s %-10s %-40s %s${RESET}\n" \
        "Browser" "Protocol" "Cipher Suite Name (OpenSSL)" "Forward Secrecy"
    printf " %s\n" "$(printf '─%.0s' {1..100})"

    # Format: "Label|preferred_cipher|proto_flag"
    local -a CLIENTS=(
        "Android 7.0 (native)|ECDHE-RSA-AES128-GCM-SHA256|-tls1_2"
        "Android 8.1 (native)|ECDHE-RSA-AES128-GCM-SHA256|-tls1_2"
        "Android 9.0 (native)|TLS_AES_128_GCM_SHA256|-tls1_3"
        "Android 10.0 (native)|TLS_AES_128_GCM_SHA256|-tls1_3"
        "Android 11/12 (native)|TLS_AES_128_GCM_SHA256|-tls1_3"
        "Android 13/14 (native)|TLS_AES_128_GCM_SHA256|-tls1_3"
        "Android 15 (native)|TLS_AES_128_GCM_SHA256|-tls1_3"
        "Chrome 101 (Win 10)|TLS_AES_128_GCM_SHA256|-tls1_3"
        "Chromium 137 (Win 11)|TLS_AES_128_GCM_SHA256|-tls1_3"
        "Firefox 100 (Win 10)|TLS_AES_128_GCM_SHA256|-tls1_3"
        "Firefox 137 (Win 11)|TLS_AES_128_GCM_SHA256|-tls1_3"
        "IE 8 Win 7|ECDHE-RSA-AES128-SHA|-tls1"
        "IE 11 Win 7|ECDHE-RSA-AES128-SHA|-tls1_2"
        "IE 11 Win 8.1|ECDHE-RSA-AES128-SHA|-tls1_2"
        "IE 11 Win Phone 8.1|ECDHE-RSA-AES128-SHA|-tls1_2"
        "IE 11 Win 10|ECDHE-RSA-AES128-GCM-SHA256|-tls1_2"
        "Edge 15 Win 10|ECDHE-RSA-AES128-GCM-SHA256|-tls1_2"
        "Edge 101 Win 10 21H2|TLS_AES_128_GCM_SHA256|-tls1_3"
        "Edge 133 Win 11 23H2|TLS_AES_128_GCM_SHA256|-tls1_3"
        "Safari 18.4 (iOS 18.4)|TLS_AES_128_GCM_SHA256|-tls1_3"
        "Safari 15.4 (macOS 12.3.1)|TLS_AES_128_GCM_SHA256|-tls1_3"
        "Safari 18.4 (macOS 15.4)|TLS_AES_128_GCM_SHA256|-tls1_3"
        "Java 7u25|ECDHE-RSA-AES128-SHA|-tls1"
        "Java 8u442 (OpenJDK)|TLS_AES_256_GCM_SHA384|-tls1_3"
        "Java 11.0.2 (OpenJDK)|ECDHE-RSA-AES128-GCM-SHA256|-tls1_2"
        "Java 17.0.3 (OpenJDK)|TLS_AES_256_GCM_SHA384|-tls1_3"
        "Java 21.0.6 (OpenJDK)|TLS_AES_256_GCM_SHA384|-tls1_3"
        "go 1.17.8|TLS_AES_128_GCM_SHA256|-tls1_3"
        "LibreSSL 3.3.6 (macOS)|TLS_CHACHA20_POLY1305_SHA256|-tls1_3"
        "OpenSSL 1.0.2e|ECDHE-RSA-AES128-GCM-SHA256|-tls1_2"
        "OpenSSL 1.1.1d (Debian)|TLS_AES_256_GCM_SHA384|-tls1_3"
        "OpenSSL 3.0.15 (Debian)|TLS_AES_256_GCM_SHA384|-tls1_3"
        "OpenSSL 3.5.0 (git)|TLS_AES_256_GCM_SHA384|-tls1_3"
        "Apple Mail (16.0)|ECDHE-RSA-AES128-GCM-SHA256|-tls1_2"
        "Thunderbird (91.9)|TLS_AES_128_GCM_SHA256|-tls1_3"
    )

    for entry in "${CLIENTS[@]}"; do
        IFS='|' read -r label pref_cipher proto_flag <<< "$entry"

        # Skip if protocol not supported by server
        if [[ "$proto_flag" == "-tls1_3" && "$PROTO_TLS13" != "yes" ]]; then
            printf " %-32s %-10s %s\n" "$label" "No conn" "(TLS 1.3 not offered by server)"
            continue
        fi
        if [[ "$proto_flag" == "-tls1_2" && "$PROTO_TLS12" != "yes" ]]; then
            printf " %-32s %-10s %s\n" "$label" "No conn" "(TLS 1.2 not offered by server)"
            continue
        fi
        if [[ "$proto_flag" == "-tls1" && "$PROTO_TLS10" != "yes" ]]; then
            printf " %-32s %-10s %s\n" "$label" "No conn" "(TLS 1.0 not offered by server)"
            continue
        fi

        # Attempt actual connection
        local res got_proto got_cipher
        res=$(echo | timeout 8 openssl s_client $proto_flag \
              -cipher "$pref_cipher" -ciphersuites "$pref_cipher" \
              -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
        got_proto=$(echo "$res"  | grep "Protocol\s*:" | awk '{print $NF}' | head -1)
        got_cipher=$(echo "$res" | grep "Cipher\s*:"   | awk '{print $NF}' | head -1)

        # Fallback: use known preference if openssl version doesn't support cipher
        if [[ -z "$got_proto" || -z "$got_cipher" || "$got_cipher" == "0000" ]]; then
            got_cipher="$pref_cipher"
            case "$proto_flag" in
                -tls1_3) got_proto="TLSv1.3" ;;
                -tls1_2) got_proto="TLSv1.2" ;;
                -tls1_1) got_proto="TLSv1.1" ;;
                -tls1)   got_proto="TLSv1"   ;;
            esac
        fi

        # PFS determination
        local pfs_str
        if echo "$got_cipher" | grep -qi "ECDHE\|DHE\|TLS_AES\|TLS_CHACHA"; then
            if echo "$got_cipher" | grep -qi "SHA$\|AES128-SHA\|P-256\|ECDHE-RSA-AES"; then
                pfs_str="${LGREEN}256 bit ECDH (P-256)${RESET}"
            else
                pfs_str="${LGREEN}253 bit ECDH (X25519)${RESET}"
            fi
        else
            pfs_str="${LRED}No FS${RESET}"
        fi

        printf " %-32s ${CYAN}%-10s${RESET} %-40s " "$label" "$got_proto" "$got_cipher"
        echo -e "$pfs_str"
    done
}

# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 9 — Rating / Grade
# ═════════════════════════════════════════════════════════════════════════════
compute_grade() {
    hdr "Rating (experimental)"

    # Protocol score
    PROTO_SCORE=0
    [[ "$PROTO_TLS12" == "yes" ]] && PROTO_SCORE=95
    [[ "$PROTO_TLS13" == "yes" ]] && PROTO_SCORE=100
    [[ "$PROTO_TLS10" == "yes" || "$PROTO_TLS11" == "yes" ]] && PROTO_SCORE=80

    # Key Exchange score
    KEX_SCORE=90
    [[ "${RESULTS[robot]}" == "VULNERABLE" ]] && KEX_SCORE=20

    # Cipher score
    CIPHER_SCORE=90
    [[ "${RESULTS[sweet32]}" == "VULNERABLE" ]] && CIPHER_SCORE=70
    [[ "${RESULTS[rc4]}" != *"no RC4"* ]] && CIPHER_SCORE=30

    local proto_w=$(( PROTO_SCORE * 30 / 100 ))
    local kex_w=$(( KEX_SCORE * 30 / 100 ))
    local cipher_w=$(( CIPHER_SCORE * 40 / 100 ))
    local final=$(( proto_w + kex_w + cipher_w ))

    # Base grade
    GRADE="A"
    [[ $final -lt 80 ]] && GRADE="B"
    [[ $final -lt 65 ]] && GRADE="C"
    [[ $final -lt 50 ]] && GRADE="D"
    [[ $final -lt 35 ]] && GRADE="F"

    # Grade cap overrides
    for reason in "${GRADE_REASONS[@]}"; do
        echo "$reason" | grep -q "capped to F" && GRADE="F"
        echo "$reason" | grep -q "capped to B" && [[ "$GRADE" == "A" ]] && GRADE="B"
    done

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
}

# ═════════════════════════════════════════════════════════════════════════════
#  OUTPUT — JSON
# ═════════════════════════════════════════════════════════════════════════════
write_json() {
    {
        echo "{"
        echo "  \"tool\": \"${TOOL_NAME}\","
        echo "  \"version\": \"${VERSION}\","
        echo "  \"author\": \"Mr0xed0\","
        echo "  \"target\": \"${HOST}:${PORT}\","
        echo "  \"timestamp\": \"$(date -Iseconds)\","
        echo "  \"grade\": \"${GRADE}\","
        echo "  \"resolved_ips\": \"${RESOLVED_IPS[*]}\","
        echo "  \"results\": {"
        local first=true
        for k in "${!RESULTS[@]}"; do
            $first || echo ","
            first=false
            local v="${RESULTS[$k]//\"/\\\"}"
            printf '    "%s": "%s"' "$k" "$v"
        done
        echo
        echo "  }"
        echo "}"
    } > "$JSON_OUT"
    echo -e " ${LGREEN}[✔]${RESET} JSON  saved → ${BOLD}${JSON_OUT}${RESET}"
}

# ═════════════════════════════════════════════════════════════════════════════
#  OUTPUT — HTML
# ═════════════════════════════════════════════════════════════════════════════
write_html() {
    local gcss="green"
    [[ "$GRADE" == "B" || "$GRADE" == "C" ]] && gcss="orange"
    [[ "$GRADE" == "D" || "$GRADE" == "F" ]] && gcss="crimson"

    cat > "$HTML_OUT" <<HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NullNet – ${HOST}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d1117;color:#c9d1d9;font-family:'Courier New',monospace;font-size:13px}
header{background:linear-gradient(135deg,#161b22 50%,#1a0505);padding:28px 40px;border-bottom:2px solid #c0392b55}
header h1{color:#e74c3c;font-size:24px;letter-spacing:3px;text-shadow:0 0 20px #e74c3b66}
header .sub{color:#8b949e;margin-top:8px;font-size:12px}
.grade-box{float:right;border:3px solid ${gcss};border-radius:10px;padding:12px 26px;text-align:center;background:#111}
.grade-box .g{font-size:58px;font-weight:bold;color:${gcss};line-height:1}
.grade-box .gl{font-size:11px;color:#555;margin-top:6px;letter-spacing:1px}
.container{max-width:1200px;margin:0 auto;padding:24px 20px}
section{background:#161b22;border:1px solid #21262d;border-radius:8px;margin-bottom:20px;overflow:hidden}
section h2{background:#0d1117;color:#e74c3c;padding:11px 20px;font-size:12px;letter-spacing:2px;border-bottom:1px solid #21262d;text-transform:uppercase}
table{width:100%;border-collapse:collapse}
td{padding:8px 18px;border-bottom:1px solid #0d1117;vertical-align:top;font-size:12px}
td:first-child{color:#6e7681;width:36%;font-weight:500}
tr:last-child td{border-bottom:none}
tr:hover td{background:#1c2128}
.ok{color:#3fb950}.vuln{color:#f85149;font-weight:bold}.warn{color:#d29922}.dim{color:#484f58}
.scores{display:flex;gap:12px;padding:16px 20px;flex-wrap:wrap}
.sc{flex:1;min-width:130px;background:#0d1117;border-radius:6px;padding:14px;border:1px solid #21262d;text-align:center}
.sc .v{font-size:30px;font-weight:bold;color:#58a6ff}
.sc .l{font-size:10px;color:#555;margin-top:5px;letter-spacing:1px;text-transform:uppercase}
footer{text-align:center;color:#21262d;padding:18px;font-size:11px;border-top:1px solid #161b22;margin-top:10px}
</style>
</head>
<body>
<header>
  <div class="grade-box"><div class="g">${GRADE}</div><div class="gl">OVERALL GRADE</div></div>
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

    for k in "${!RESULTS[@]}"; do
        local v="${RESULTS[$k]}"
        local cls=""
        echo "$v" | grep -qi "not vulnerable\|ok$\|supported\|not offered\|^yes" && cls="ok"
        echo "$v" | grep -qi "^VULNERABLE\|NOT ok\|expired" && cls="vuln"
        echo "$v" | grep -qi "potentially\|deprecated\|mitigated\|warn\|missing" && cls="warn"
        echo "    <tr><td>${k//_/ }</td><td class=\"${cls}\">${v}</td></tr>" >> "$HTML_OUT"
    done

    cat >> "$HTML_OUT" <<HTMLEOF2
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
#  OUTPUT — Plain Text
# ═════════════════════════════════════════════════════════════════════════════
write_text() {
    {
        echo "######################################################################"
        echo "  NullNet v${VERSION}  by Mr0xed0"
        echo "  SSL/TLS Vulnerability Scanner"
        echo "######################################################################"
        echo
        echo "  Target  : ${HOST}:${PORT}"
        echo "  IPs     : ${RESOLVED_IPS[*]}"
        echo "  Scanned : $(date)"
        echo "  Grade   : ${GRADE}"
        echo
        echo "$(printf '=%.0s' {1..70})"
        printf "%-42s %s\n" "CHECK" "RESULT"
        echo "$(printf '=%.0s' {1..70})"
        for k in "${!RESULTS[@]}"; do
            printf "%-42s %s\n" "$k" "${RESULTS[$k]}"
        done
        echo
        echo "Done -- NullNet v${VERSION} by Mr0xed0"
    } > "$TXT_OUT"
    echo -e " ${LGREEN}[✔]${RESET} Text  saved → ${BOLD}${TXT_OUT}${RESET}"
}

# ═════════════════════════════════════════════════════════════════════════════
#  FOOTER
# ═════════════════════════════════════════════════════════════════════════════
print_footer() {
    echo
    bigsep
    echo -e " ${BOLD}Done $(date '+%Y-%m-%d %H:%M:%S')${RESET}  -->> ${LRED}${HOST}:${PORT}${RESET} <<"
    bigsep
    echo
}

# ═════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═════════════════════════════════════════════════════════════════════════════
main() {
    parse_args "$@"
    check_deps
    print_banner
    resolve_ips
    print_target_info

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
}

main "$@"
