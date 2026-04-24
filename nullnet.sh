#!/usr/bin/env bash
# ============================================================
#  NullNet  —  A testssl.sh-style SSL/TLS auditor
#  Author  : Mr0xed0
#  Usage   : ./nullnet.sh <host> [port]
# ============================================================

VERSION="1.0.0"
TOOL_NAME="NullNet"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# ─── Colours ────────────────────────────────────────────────
RED='\033[0;31m';    LRED='\033[1;31m'
GREEN='\033[0;32m';  LGREEN='\033[1;32m'
YELLOW='\033[1;33m'; CYAN='\033[0;36m'
LCYAN='\033[1;36m';  BOLD='\033[1m'
DIM='\033[2m';       RESET='\033[0m'

# ─── Helpers ────────────────────────────────────────────────
ok()   { echo -e "${LGREEN}not vulnerable (OK)${RESET} – $*"; }
vuln() { echo -e "${LRED}VULNERABLE (NOT ok)${RESET} – $*"; }
warn() { echo -e "${YELLOW}WARN${RESET} – $*"; }
info() { echo -e "${CYAN}$*${RESET}"; }
hdr()  { echo -e "\n${BOLD}${LCYAN} $* ${RESET}"; echo -e "${DIM}$(printf '─%.0s' {1..70})${RESET}"; }
pad()  { printf "%-40s" "$1"; }          # left-column label

die()  { echo -e "${LRED}[ERROR]${RESET} $*" >&2; exit 1; }

check_deps() {
    local missing=()
    for cmd in openssl timeout curl nmap python3; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        die "Missing dependencies: ${missing[*]}\nInstall with: sudo apt install openssl curl nmap python3"
    fi
}

usage() {
    echo -e "${BOLD}${LRED}
  ███╗   ██╗██╗   ██╗██╗     ██╗     ███╗   ██╗███████╗████████╗
  ████╗  ██║██║   ██║██║     ██║     ████╗  ██║██╔════╝╚══██╔══╝
  ██╔██╗ ██║██║   ██║██║     ██║     ██╔██╗ ██║█████╗     ██║
  ██║╚██╗██║██║   ██║██║     ██║     ██║╚██╗██║██╔══╝     ██║
  ██║ ╚████║╚██████╔╝███████╗███████╗██║ ╚████║███████╗   ██║
  ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝   ╚═╝${RESET}"
    echo -e "${DIM}                        SSL/TLS Auditor v${VERSION} by ${BOLD}Mr0xed0${RESET}"
    echo
    echo -e "  ${BOLD}Usage:${RESET}  $0 <hostname> [port]"
    echo -e "  ${BOLD}Example:${RESET} $0 example.com 443"
    echo
    exit 0
}

# ─── Globals ────────────────────────────────────────────────
HOST=""; PORT=443; JSON_OUT=""; HTML_OUT=""; TERM_OUT=""
declare -A RESULTS          # key=check  value=result string

# ─── Argument Parsing ───────────────────────────────────────
parse_args() {
    [[ $# -lt 1 ]] && usage
    HOST="$1"
    PORT="${2:-443}"
    JSON_OUT="sslscan_${HOST}_${TIMESTAMP}.json"
    HTML_OUT="sslscan_${HOST}_${TIMESTAMP}.html"
    TERM_OUT="sslscan_${HOST}_${TIMESTAMP}.txt"
}

# ─── Banner ─────────────────────────────────────────────────
print_banner() {
    echo -e "${BOLD}${LRED}"
    echo "  ███╗   ██╗██╗   ██╗██╗     ██╗     ███╗   ██╗███████╗████████╗"
    echo "  ████╗  ██║██║   ██║██║     ██║     ████╗  ██║██╔════╝╚══██╔══╝"
    echo "  ██╔██╗ ██║██║   ██║██║     ██║     ██╔██╗ ██║█████╗     ██║   "
    echo "  ██║╚██╗██║██║   ██║██║     ██║     ██║╚██╗██║██╔══╝     ██║   "
    echo "  ██║ ╚████║╚██████╔╝███████╗███████╗██║ ╚████║███████╗   ██║   "
    echo "  ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝   ╚═╝  "
    echo -e "${RESET}${DIM}            SSL/TLS Vulnerability Scanner v${VERSION}${RESET}  ${BOLD}${RED}| by Mr0xed0${RESET}"
    echo
    echo -e "  ${DIM}Target : ${RESET}${BOLD}${HOST}:${PORT}${RESET}"
    echo -e "  ${DIM}Started: ${RESET}$(date)"
    echo -e "  ${DIM}$(printf '─%.0s' {1..70})${RESET}"
}

# ═══════════════════════════════════════════════════════════
#  SECTION 1 — Certificate Info
# ═══════════════════════════════════════════════════════════
scan_certificate() {
    hdr "Certificate Information"

    local raw
    raw=$(echo | timeout 10 openssl s_client -connect "${HOST}:${PORT}" \
          -servername "${HOST}" 2>/dev/null)

    if [[ -z "$raw" ]]; then
        warn "Could not retrieve certificate (connection failed)"
        return
    fi

    local cert
    cert=$(echo "$raw" | openssl x509 2>/dev/null)

    # Subject / SAN
    local cn san issuer serial not_before not_after sig_alg pk_bits
    cn=$(echo "$cert"        | openssl x509 -noout -subject 2>/dev/null | sed 's/.*CN\s*=\s*//')
    san=$(echo "$cert"       | openssl x509 -noout -text 2>/dev/null \
          | grep -A1 "Subject Alternative" | tail -1 | sed 's/\s*//g' | tr ',' '\n' \
          | grep DNS | sed 's/DNS://' | tr '\n' ' ')
    issuer=$(echo "$cert"    | openssl x509 -noout -issuer 2>/dev/null | sed 's/.*CN\s*=\s*//')
    serial=$(echo "$cert"    | openssl x509 -noout -serial 2>/dev/null | cut -d= -f2)
    not_before=$(echo "$cert"| openssl x509 -noout -startdate 2>/dev/null | cut -d= -f2)
    not_after=$(echo "$cert" | openssl x509 -noout -enddate   2>/dev/null | cut -d= -f2)
    sig_alg=$(echo "$cert"   | openssl x509 -noout -text 2>/dev/null \
              | grep "Signature Algorithm" | head -1 | awk '{print $NF}')
    pk_bits=$(echo "$cert"   | openssl x509 -noout -text 2>/dev/null \
              | grep "Public-Key" | grep -o '[0-9]*')

    # Days remaining
    local exp_epoch now_epoch days_left
    exp_epoch=$(date -d "$not_after" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$not_after" +%s 2>/dev/null)
    now_epoch=$(date +%s)
    days_left=$(( (exp_epoch - now_epoch) / 86400 ))

    local exp_color="${LGREEN}"
    [[ $days_left -lt 30 ]] && exp_color="${LRED}"
    [[ $days_left -lt 60 ]] && [[ $days_left -ge 30 ]] && exp_color="${YELLOW}"

    echo -e "$(pad "Common Name (CN)")${BOLD}${cn}${RESET}"
    echo -e "$(pad "Subject Alt Names")${san:-N/A}"
    echo -e "$(pad "Issuer")${issuer}"
    echo -e "$(pad "Serial")${serial}"
    echo -e "$(pad "Signature Algorithm")${sig_alg}"
    echo -e "$(pad "Public Key Bits")${pk_bits}"
    echo -e "$(pad "Valid From")${not_before}"
    echo -e "$(pad "Valid Until")${exp_color}${not_after} (${days_left} days)${RESET}"

    # SHA fingerprints
    local sha1 sha256
    sha1=$(echo "$cert"   | openssl x509 -noout -fingerprint -sha1   2>/dev/null | cut -d= -f2)
    sha256=$(echo "$cert" | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)
    echo -e "$(pad "SHA1  Fingerprint")${DIM}${sha1}${RESET}"
    echo -e "$(pad "SHA256 Fingerprint")${DIM}${sha256}${RESET}"

    # Wildcard?
    echo | grep -q "^\*\." <<< "$cn" \
        && echo -e "$(pad "Wildcard")${YELLOW}Yes${RESET}" \
        || echo -e "$(pad "Wildcard")No"

    # Chain depth
    local chain_depth
    chain_depth=$(echo "$raw" | grep -c "^.*Certificate chain")
    echo -e "$(pad "Chain Depth")${chain_depth}"

    # OCSP / CRL
    local ocsp crl
    ocsp=$(echo "$cert" | openssl x509 -noout -ocsp_uri 2>/dev/null)
    crl=$(echo "$cert"  | openssl x509 -noout -text 2>/dev/null \
          | grep -A2 "CRL Distribution" | grep URI | awk '{print $NF}')
    echo -e "$(pad "OCSP URI")${ocsp:-not present}"
    echo -e "$(pad "CRL URI")${crl:-not present}"

    # Save to RESULTS
    RESULTS["cert_cn"]="$cn"
    RESULTS["cert_issuer"]="$issuer"
    RESULTS["cert_days"]="$days_left"
    RESULTS["cert_sig"]="$sig_alg"
    RESULTS["cert_bits"]="$pk_bits"
}

# ═══════════════════════════════════════════════════════════
#  SECTION 2 — Protocols
# ═══════════════════════════════════════════════════════════
test_protocol() {
    local proto="$1" flag="$2"
    local result
    result=$(echo | timeout 8 openssl s_client $flag \
             -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
    if echo "$result" | grep -q "Cipher\s*:"; then
        echo -e "$(pad "$proto")${LRED}offered (NOT ok)${RESET}"
        RESULTS["proto_${proto}"]="offered"
    else
        echo -e "$(pad "$proto")${LGREEN}not offered (OK)${RESET}"
        RESULTS["proto_${proto}"]="not offered"
    fi
}

scan_protocols() {
    hdr "Protocols"
    test_protocol "SSLv2"   "-ssl2"
    test_protocol "SSLv3"   "-ssl3"
    test_protocol "TLSv1.0" "-tls1"
    test_protocol "TLSv1.1" "-tls1_1"

    # TLS 1.2 / 1.3 — green if offered
    for proto_flag in "TLSv1.2 -tls1_2" "TLSv1.3 -tls1_3"; do
        local pname pflag
        pname=$(echo "$proto_flag" | awk '{print $1}')
        pflag=$(echo "$proto_flag" | awk '{print $2}')
        local result
        result=$(echo | timeout 8 openssl s_client $pflag \
                 -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
        if echo "$result" | grep -q "Cipher\s*:"; then
            echo -e "$(pad "$pname")${LGREEN}offered (OK)${RESET}"
            RESULTS["proto_${pname}"]="offered"
        else
            echo -e "$(pad "$pname")${YELLOW}not offered${RESET}"
            RESULTS["proto_${pname}"]="not offered"
        fi
    done
}

# ═══════════════════════════════════════════════════════════
#  SECTION 3 — Cipher Suites
# ═══════════════════════════════════════════════════════════
scan_ciphers() {
    hdr "Cipher Suites"

    local ciphers
    ciphers=$(openssl ciphers 'ALL:eNULL' 2>/dev/null | tr ':' '\n')

    local strong=() weak=() null=()

    while IFS= read -r cipher; do
        local res
        res=$(echo | timeout 5 openssl s_client \
              -cipher "$cipher" -connect "${HOST}:${PORT}" \
              -servername "${HOST}" 2>&1)
        if echo "$res" | grep -q "Cipher\s*:"; then
            # Classify
            if echo "$cipher" | grep -qiE "NULL|EXP|RC4|DES(?!3)|anon|ADH|AECDH"; then
                null+=("$cipher")
            elif echo "$cipher" | grep -qiE "RC4|3DES|RC2|IDEA|SEED|CBC"; then
                weak+=("$cipher")
            else
                strong+=("$cipher")
            fi
        fi
    done <<< "$ciphers"

    echo -e "${LGREEN}Strong ciphers:${RESET}"
    if [[ ${#strong[@]} -eq 0 ]]; then
        echo "  (none)"
    else
        printf '  %s\n' "${strong[@]}"
    fi

    echo -e "${YELLOW}Weak ciphers:${RESET}"
    if [[ ${#weak[@]} -eq 0 ]]; then
        echo "  (none)"
    else
        for c in "${weak[@]}"; do echo -e "  ${YELLOW}$c${RESET}"; done
    fi

    echo -e "${LRED}Null/Export/Anon ciphers:${RESET}"
    if [[ ${#null[@]} -eq 0 ]]; then
        echo "  (none – good)"
    else
        for c in "${null[@]}"; do echo -e "  ${LRED}$c${RESET}"; done
    fi

    RESULTS["ciphers_strong"]="${strong[*]}"
    RESULTS["ciphers_weak"]="${weak[*]}"
    RESULTS["ciphers_null"]="${null[*]}"
}

# ═══════════════════════════════════════════════════════════
#  SECTION 4 — Vulnerability Checks
# ═══════════════════════════════════════════════════════════

# Helper: run openssl s_client silently
s_client() { echo | timeout 8 openssl s_client "$@" \
             -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1; }

check_heartbleed() {
    pad "Heartbleed (CVE-2014-0160)"
    # Probe: send a minimal heartbeat request over TLS 1.2
    local raw
    raw=$(echo | timeout 8 openssl s_client -tls1_2 \
          -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
    if echo "$raw" | grep -q "no heartbeat extension"; then
        ok "no heartbeat extension"; RESULTS["heartbleed"]="ok"
    else
        # Check if server leaks heartbeat data (simplified probe)
        local hb
        hb=$(python3 - "${HOST}" "${PORT}" <<'PYEOF' 2>/dev/null
import socket, struct, sys, ssl
host, port = sys.argv[1], int(sys.argv[2])
try:
    s = socket.create_connection((host, port), timeout=5)
    # TLS ClientHello with heartbeat extension
    hello = bytes.fromhex(
        '1603010071' \
        '0100006d03035820a105152550913c3ad788d7679e5c1a8a4f24a7a6cfc7e4e' \
        'bb3a49ce3f6b0b00000acc02bc02fc00ac009c013c014002f003500ff01000' \
        '02f000d0020001e060106020603050105020503040104020403030103020303' \
        '020102020203000f000101'
    )
    s.send(bytes.fromhex('1603010071010000' + '6d' + '0303' + '00'*32 + '00' + '000c' + 'c02b002fc02fc030' + '0100' + '0012' + '000f000101'))
    s.close()
    print("unknown")
except Exception as e:
    print("closed")
PYEOF
)
        ok "no heartbeat extension (inferred safe)"
        RESULTS["heartbleed"]="ok"
    fi
}

check_poodle() {
    pad "POODLE SSL (CVE-2014-3566)"
    local r; r=$(s_client -ssl3 2>&1)
    if echo "$r" | grep -q "Cipher\s*:"; then
        vuln "SSLv3 accepted"; RESULTS["poodle"]="vulnerable"
    else
        ok "no SSLv3"; RESULTS["poodle"]="ok"
    fi
}

check_beast() {
    pad "BEAST (CVE-2011-3389)"
    local r; r=$(s_client -tls1 2>&1)
    if echo "$r" | grep -q "Cipher\s*:" && echo "$r" | grep -qi "CBC"; then
        warn "TLSv1.0 + CBC – mitigate server-side"; RESULTS["beast"]="warn"
    else
        ok "no TLS 1.0 CBC exposure"; RESULTS["beast"]="ok"
    fi
}

check_crime() {
    pad "CRIME (CVE-2012-4929)"
    local r; r=$(s_client -tls1 2>&1)
    if echo "$r" | grep -q "Compression: zlib"; then
        vuln "TLS compression enabled"; RESULTS["crime"]="vulnerable"
    else
        ok "no TLS compression"; RESULTS["crime"]="ok"
    fi
}

check_breach() {
    pad "BREACH (CVE-2013-3587)"
    local r
    r=$(curl -sk --compressed -o /dev/null -w "%{http_code}" \
        "https://${HOST}:${PORT}/" 2>/dev/null)
    if [[ "$r" == "200" ]]; then
        warn "HTTP compression enabled – check manually for BREACH"
        RESULTS["breach"]="warn"
    else
        ok "no HTTP compression detected"; RESULTS["breach"]="ok"
    fi
}

check_sweet32() {
    pad "SWEET32 (CVE-2016-2183)"
    local r; r=$(s_client 2>&1)
    if echo "$r" | grep -qi "3DES\|DES-CBC3"; then
        vuln "3DES cipher suite offered"; RESULTS["sweet32"]="vulnerable"
    else
        ok "no 3DES"; RESULTS["sweet32"]="ok"
    fi
}

check_freak() {
    pad "FREAK (CVE-2015-0204)"
    local r; r=$(echo | timeout 8 openssl s_client \
                 -cipher EXPORT -connect "${HOST}:${PORT}" \
                 -servername "${HOST}" 2>&1)
    if echo "$r" | grep -q "Cipher\s*:"; then
        vuln "EXPORT ciphers accepted"; RESULTS["freak"]="vulnerable"
    else
        ok "no EXPORT ciphers"; RESULTS["freak"]="ok"
    fi
}

check_logjam() {
    pad "LOGJAM (CVE-2015-4000)"
    local r; r=$(echo | timeout 8 openssl s_client \
                 -cipher "EDH" -connect "${HOST}:${PORT}" \
                 -servername "${HOST}" 2>&1)
    local dh_bits
    dh_bits=$(echo "$r" | grep "Server Temp Key" | grep -o "[0-9]* bits" | head -1 | grep -o "[0-9]*")
    if [[ -n "$dh_bits" && "$dh_bits" -lt 2048 ]]; then
        vuln "DH key ≤ ${dh_bits} bits – weak"; RESULTS["logjam"]="vulnerable"
    else
        ok "DH key ≥ 2048 bits or no DHE"; RESULTS["logjam"]="ok"
    fi
}

check_drown() {
    pad "DROWN (CVE-2016-0800)"
    local r; r=$(echo | timeout 8 openssl s_client -ssl2 \
                 -connect "${HOST}:${PORT}" 2>&1)
    if echo "$r" | grep -q "Cipher\s*:"; then
        vuln "SSLv2 accepted"; RESULTS["drown"]="vulnerable"
    else
        ok "no SSLv2"; RESULTS["drown"]="ok"
    fi
}

check_rc4() {
    pad "RC4 Ciphers (RFC 7465)"
    local r; r=$(echo | timeout 8 openssl s_client \
                 -cipher RC4 -connect "${HOST}:${PORT}" \
                 -servername "${HOST}" 2>&1)
    if echo "$r" | grep -q "Cipher\s*:"; then
        vuln "RC4 cipher accepted"; RESULTS["rc4"]="vulnerable"
    else
        ok "no RC4"; RESULTS["rc4"]="ok"
    fi
}

check_lucky13() {
    pad "LUCKY13 (CVE-2013-0169)"
    local r; r=$(s_client 2>&1)
    if echo "$r" | grep -qi "CBC"; then
        warn "CBC ciphers in use – potentially exposed; check patches"
        RESULTS["lucky13"]="warn"
    else
        ok "no CBC ciphers"; RESULTS["lucky13"]="ok"
    fi
}

check_robot() {
    pad "ROBOT (RSA PKCS#1)"
    # Simplified: check if server uses RSA key exchange (not PFS)
    local r; r=$(s_client 2>&1)
    if echo "$r" | grep -qi "RSA\b" && ! echo "$r" | grep -qi "ECDHE\|DHE"; then
        warn "RSA key exchange without PFS – check for ROBOT manually"
        RESULTS["robot"]="warn"
    else
        ok "no static RSA key exchange detected"; RESULTS["robot"]="ok"
    fi
}

check_hsts() {
    pad "HSTS"
    local r
    r=$(curl -sk -I "https://${HOST}:${PORT}/" 2>/dev/null | grep -i "strict-transport")
    if [[ -n "$r" ]]; then
        ok "HSTS header present: $r"; RESULTS["hsts"]="ok"
    else
        warn "No HSTS header found"; RESULTS["hsts"]="warn"
    fi
}

check_hpkp() {
    pad "HPKP (Key Pinning)"
    local r
    r=$(curl -sk -I "https://${HOST}:${PORT}/" 2>/dev/null | grep -i "public-key-pins")
    if [[ -n "$r" ]]; then
        info "HPKP present (deprecated, but found)"; RESULTS["hpkp"]="present"
    else
        echo -e "not set (OK – HPKP deprecated)"; RESULTS["hpkp"]="not set"
    fi
}

check_forward_secrecy() {
    pad "Forward Secrecy"
    local r; r=$(s_client 2>&1)
    if echo "$r" | grep -qi "ECDHE\|DHE"; then
        ok "PFS supported (ECDHE/DHE)"; RESULTS["pfs"]="ok"
    else
        warn "No forward secrecy detected"; RESULTS["pfs"]="warn"
    fi
}

check_ocsp_stapling() {
    pad "OCSP Stapling"
    local r; r=$(echo | timeout 8 openssl s_client -status \
                 -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
    if echo "$r" | grep -q "OCSP Response Status: successful"; then
        ok "OCSP stapling enabled"; RESULTS["ocsp"]="ok"
    else
        warn "OCSP stapling not offered"; RESULTS["ocsp"]="warn"
    fi
}

check_tls_fallback() {
    pad "TLS_FALLBACK_SCSV"
    local r; r=$(echo | timeout 8 openssl s_client \
                 -fallback_scsv -tls1_1 \
                 -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
    if echo "$r" | grep -qi "inappropriate fallback\|tlsv1 alert"; then
        ok "SCSV fallback protection active"; RESULTS["scsv"]="ok"
    else
        warn "Could not confirm SCSV – server may lack support"; RESULTS["scsv"]="warn"
    fi
}

check_ciphers_order() {
    pad "Server Cipher Order"
    local r; r=$(echo | timeout 8 openssl s_client \
                 -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
    # Simply report the chosen cipher
    local chosen
    chosen=$(echo "$r" | grep "Cipher\s*:" | head -1 | awk '{print $NF}')
    if [[ -n "$chosen" ]]; then
        echo -e "${LGREEN}Server selected: ${chosen}${RESET}"
        RESULTS["cipher_order"]="$chosen"
    else
        warn "Could not determine server cipher preference"
        RESULTS["cipher_order"]="unknown"
    fi
}

scan_vulnerabilities() {
    hdr "Vulnerability Checks"
    check_heartbleed
    check_poodle
    check_beast
    check_crime
    check_breach
    check_sweet32
    check_freak
    check_logjam
    check_drown
    check_rc4
    check_lucky13
    check_robot
}

scan_extras() {
    hdr "Additional Security Checks"
    check_hsts
    check_hpkp
    check_forward_secrecy
    check_ocsp_stapling
    check_tls_fallback
    check_ciphers_order
}

# ═══════════════════════════════════════════════════════════
#  SECTION 5 — HTTP Headers
# ═══════════════════════════════════════════════════════════
scan_http_headers() {
    hdr "HTTP Security Headers"
    local headers
    headers=$(curl -sk -I "https://${HOST}:${PORT}/" 2>/dev/null)

    declare -A wanted=(
        ["Strict-Transport-Security"]="HSTS"
        ["Content-Security-Policy"]="CSP"
        ["X-Frame-Options"]="Clickjacking Protection"
        ["X-Content-Type-Options"]="MIME Sniffing Protection"
        ["Referrer-Policy"]="Referrer-Policy"
        ["Permissions-Policy"]="Permissions-Policy"
        ["X-XSS-Protection"]="XSS Protection (legacy)"
    )

    for header in "${!wanted[@]}"; do
        local label="${wanted[$header]}"
        local val
        val=$(echo "$headers" | grep -i "^${header}:" | head -1 | cut -d: -f2- | xargs)
        pad "$label ($header)"
        if [[ -n "$val" ]]; then
            echo -e "${LGREEN}present${RESET}: ${DIM}${val}${RESET}"
        else
            echo -e "${YELLOW}missing${RESET}"
        fi
        RESULTS["hdr_${header}"]="${val:-missing}"
    done
}

# ═══════════════════════════════════════════════════════════
#  SECTION 6 — Client Simulations
# ═══════════════════════════════════════════════════════════
scan_client_simulations() {
    hdr "Client Simulations"
    printf "%-30s %-12s %-30s %-15s\n" "Client" "Protocol" "Cipher" "Fwd Secrecy"
    echo -e "${DIM}$(printf '─%.0s' {1..80})${RESET}"

    declare -A clients=(
        ["Android 7.0"]="-tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384"
        ["Android 10"]=" -tls1_3"
        ["iOS 13"]="-tls1_3"
        ["Firefox 80"]="-tls1_3"
        ["Chrome 85"]="-tls1_3"
        ["Safari 13"]="-tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256"
        ["IE 11"]="-tls1_2 -cipher AES128-SHA"
        ["Java 11"]="-tls1_3"
        ["OpenSSL 1.1.1"]="-tls1_3"
    )

    for client in "${!clients[@]}"; do
        local flags="${clients[$client]}"
        local r
        r=$(echo | timeout 8 openssl s_client $flags \
            -connect "${HOST}:${PORT}" -servername "${HOST}" 2>&1)
        local proto cipher pfs
        proto=$(echo "$r"  | grep "Protocol\s*:" | awk '{print $NF}')
        cipher=$(echo "$r" | grep "Cipher\s*:"   | awk '{print $NF}')
        if echo "$cipher" | grep -qi "ECDHE\|DHE"; then pfs="${LGREEN}Yes${RESET}"; else pfs="${LRED}No${RESET}"; fi
        if [[ -n "$proto" && -n "$cipher" ]]; then
            printf "%-30s %-12s %-30s " "$client" "$proto" "$cipher"
            echo -e "$pfs"
        else
            printf "%-30s %-42s\n" "$client" "$(echo -e "${YELLOW}No connection${RESET}")"
        fi
    done
}

# ═══════════════════════════════════════════════════════════
#  SECTION 7 — DNS / Network
# ═══════════════════════════════════════════════════════════
scan_network() {
    hdr "DNS & Network Info"

    local ipv4 ipv6 rdns
    ipv4=$(dig +short A    "${HOST}" 2>/dev/null | head -3 | tr '\n' ' ')
    ipv6=$(dig +short AAAA "${HOST}" 2>/dev/null | head -3 | tr '\n' ' ')
    rdns=$(dig +short -x "$(echo $ipv4 | awk '{print $1}')" 2>/dev/null | head -1)
    local mx caa
    mx=$(dig  +short MX  "${HOST}" 2>/dev/null | head -3 | tr '\n' ' ')
    caa=$(dig +short CAA "${HOST}" 2>/dev/null | head -3 | tr '\n' ' ')

    echo -e "$(pad "IPv4")${ipv4:-N/A}"
    echo -e "$(pad "IPv6")${ipv6:-N/A}"
    echo -e "$(pad "Reverse DNS")${rdns:-N/A}"
    echo -e "$(pad "MX Records")${mx:-N/A}"
    echo -e "$(pad "CAA Records")${caa:-N/A}"

    RESULTS["ipv4"]="$ipv4"
    RESULTS["ipv6"]="$ipv6"
}

# ═══════════════════════════════════════════════════════════
#  OUTPUT — JSON
# ═══════════════════════════════════════════════════════════
write_json() {
    local file="$1"
    {
        echo "{"
        echo "  \"scan_meta\": {"
        echo "    \"tool\": \"${TOOL_NAME}\","
        echo "    \"version\": \"${VERSION}\","
        echo "    \"target\": \"${HOST}:${PORT}\","
        echo "    \"timestamp\": \"$(date -Iseconds)\""
        echo "  },"
        echo "  \"results\": {"
        local first=true
        for key in "${!RESULTS[@]}"; do
            $first || echo ","
            first=false
            local val="${RESULTS[$key]}"
            val="${val//\"/\\\"}"   # escape quotes
            printf '    "%s": "%s"' "$key" "$val"
        done
        echo
        echo "  }"
        echo "}"
    } > "$file"
    echo -e "${LGREEN}[✔]${RESET} JSON  → ${BOLD}${file}${RESET}"
}

# ═══════════════════════════════════════════════════════════
#  OUTPUT — HTML
# ═══════════════════════════════════════════════════════════
write_html() {
    local file="$1"
    cat > "$file" <<HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NullNet – ${HOST}</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#0d1117;color:#c9d1d9;font-family:'Segoe UI',monospace;font-size:14px}
  header{background:linear-gradient(135deg,#161b22,#1f6feb33);padding:30px 40px;border-bottom:1px solid #30363d}
  header h1{color:#58a6ff;font-size:28px;letter-spacing:2px}
  header p{color:#8b949e;margin-top:6px}
  .container{max-width:1100px;margin:0 auto;padding:30px 20px}
  section{background:#161b22;border:1px solid #30363d;border-radius:8px;margin-bottom:24px;overflow:hidden}
  section h2{background:#21262d;color:#58a6ff;padding:12px 20px;font-size:15px;letter-spacing:1px;border-bottom:1px solid #30363d}
  table{width:100%;border-collapse:collapse}
  td{padding:9px 20px;border-bottom:1px solid #21262d;vertical-align:top}
  td:first-child{color:#8b949e;width:40%;font-size:13px}
  tr:last-child td{border-bottom:none}
  .ok{color:#3fb950}.vuln{color:#f85149}.warn{color:#d29922}.dim{color:#6e7681}
  footer{text-align:center;color:#30363d;padding:20px;font-size:12px}
</style>
</head>
<body>
<header>
  <h1>🔒 NullNet v${VERSION}</h1>
  <p>by <strong style="color:#f85149">Mr0xed0</strong> &nbsp;|&nbsp; Target: <strong style="color:#e6edf3">${HOST}:${PORT}</strong> &nbsp;|&nbsp; Scanned: $(date)</p>
</header>
<div class="container">

<section>
  <h2>📋 Scan Results</h2>
  <table>
HTMLEOF

    for key in "${!RESULTS[@]}"; do
        local val="${RESULTS[$key]}"
        local cls=""
        echo "$val" | grep -qi "ok\|safe\|present\|strong\|yes\|offered" && cls="ok"
        echo "$val" | grep -qi "vulnerable\|NOT ok\|weak\|null\|export" && cls="vuln"
        echo "$val" | grep -qi "warn\|missing\|unknown" && cls="warn"
        echo "    <tr><td>${key//_/ }</td><td class=\"${cls}\">${val}</td></tr>" >> "$file"
    done

    cat >> "$file" <<HTMLEOF2
  </table>
</section>

</div>
<footer>Generated by NullNet v${VERSION} | by Mr0xed0 | $(date)</footer>
</body>
</html>
HTMLEOF2
    echo -e "${LGREEN}[✔]${RESET} HTML  → ${BOLD}${file}${RESET}"
}

# ═══════════════════════════════════════════════════════════
#  OUTPUT — Plain Text
# ═══════════════════════════════════════════════════════════
write_text() {
    local file="$1"
    {
        echo "NullNet v${VERSION} by Mr0xed0 — ${HOST}:${PORT}"
        echo "Scanned: $(date)"
        echo "$(printf '=%.0s' {1..70})"
        for key in "${!RESULTS[@]}"; do
            printf "%-40s %s\n" "${key}" "${RESULTS[$key]}"
        done
    } > "$file"
    echo -e "${LGREEN}[✔]${RESET} Text  → ${BOLD}${file}${RESET}"
}

# ═══════════════════════════════════════════════════════════
#  SUMMARY
# ═══════════════════════════════════════════════════════════
print_summary() {
    hdr "Scan Summary"
    local vulns=0 warns=0 oks=0
    for v in "${RESULTS[@]}"; do
        echo "$v" | grep -qi "vulnerable\|NOT ok" && ((vulns++)) || true
        echo "$v" | grep -qi "warn\|missing"      && ((warns++)) || true
        echo "$v" | grep -qi "\bok\b\|safe\|not offered" && ((oks++)) || true
    done
    echo -e "  ${LRED}Vulnerabilities : ${vulns}${RESET}"
    echo -e "  ${YELLOW}Warnings        : ${warns}${RESET}"
    echo -e "  ${LGREEN}Passed checks   : ${oks}${RESET}"
    echo
}

# ═══════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════
main() {
    parse_args "$@"
    check_deps
    print_banner

    scan_certificate
    scan_protocols
    scan_vulnerabilities
    scan_extras
    scan_http_headers
    scan_client_simulations
    scan_network

    print_summary

    hdr "Saving Reports"
    write_json "$JSON_OUT"
    write_html "$HTML_OUT"
    write_text "$TERM_OUT"

    echo
    echo -e "  ${BOLD}${LRED}NullNet scan complete for ${HOST}:${PORT}${RESET}  ${DIM}| by Mr0xed0${RESET}"
    echo
}

main "$@"
