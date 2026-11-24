#!/usr/bin/env bash
# ==============================================================================
# Claude Anti-Ban Network Setup Script for Fresh Linux VPS (Debian / Ubuntu)
# Hardened Production Design:
# 1. Preflight guard: defaults to FRESH VPS only (aborts before any mutation if
#    existing Xray or WARP is detected unless ALLOW_EXISTING=true is explicitly set).
# 2. Pinned, SHA256-verified Xray installer & Xray-core release version
#    (compatible with upstream non-root User=xray systemd unit; no removed -u flag).
# 3. Handles upstream installer's empty {} config.json stub cleanly as a fresh install.
# 4. Least-privilege permissions at creation time:
#    - /usr/local/etc/xray (0750 root:xray) & config.json (0640 root:xray) so the
#      non-root xray service user can read config while blocking world access.
#    - Backups & node metadata strictly 0600 (supports OUTPUT_OWNER for sudo SCP).
# 5. Zero secret exposure in child-process CLI args or error stderr:
#    - Derives X25519 PublicKey via stdin-only openssl pkey (RFC 7748).
#    - Passes sensitive fields to jq via stdin / config file, never CLI --arg.
# 6. Full transactional rollback across config.json, newly added firewall rules,
#    live + persistent sysctl kernel values, and node.json delivery failure.
# 7. First-class NAT VPS metadata: records listen_port, inbound_host, inbound_port,
#    and egress_ip separately (plus backwards-compatible server_ip & port aliases).
# ==============================================================================

set -euo pipefail

# ------------------------------------------------------------------------------
# Parse CLI flags
# ------------------------------------------------------------------------------
PRINT_JSON=false
for arg in "$@"; do
    case "$arg" in
        --print-json)
            PRINT_JSON=true
            ;;
        -h|--help)
            cat << 'USAGE'
Usage: bash vps_setup.sh [--print-json]

Environment variables:
  PORT                 Local VPS listening TCP port for VLESS Reality (default: 24433)
  INBOUND_HOST         External client-facing host/IP for NAT VPS (default: detected egress IP)
  INBOUND_PORT         External client-facing TCP port for NAT VPS (default: PORT)
  EGRESS_IP            Expected outbound public IPv4 (default: auto-detected)
  SNI                  Reality camouflage SNI (default: gateway.icloud.com)
  ALLOW_EXISTING=true  Permit running on a VPS that already has Xray/WARP
  REGENERATE=true      Rotate UUID, Reality keys, and shortId (requires ALLOW_EXISTING=true if existing)
  OUTPUT_FILE          Path for 0600 node metadata JSON (default: /root/claude-antiban-node.json)
  OUTPUT_OWNER         Optional owner for 0600 OUTPUT_FILE (for non-root sudo SCP handoff)
  XRAY_GROUP           Optional service group for 0640 config.json (auto-detected: xray)
  XRAY_VERSION         Pinned Xray-core version (default: v26.11.9)
USAGE
            exit 0
            ;;
        *)
            echo "[ERROR] Unknown argument: $arg" >&2
            exit 1
            ;;
    esac
done

# ------------------------------------------------------------------------------
# Configuration & Pinned Supply Chain Constants
# ------------------------------------------------------------------------------
PORT_INPUT="${PORT:-}"
INBOUND_HOST_INPUT="${INBOUND_HOST:-}"
INBOUND_PORT_INPUT="${INBOUND_PORT:-}"
EGRESS_IP_INPUT="${EGRESS_IP:-${SERVER_IP_OVERRIDE:-}}"
SNI_INPUT="${SNI:-}"
WARP_PORT="${WARP_PORT:-40000}"
ALLOW_EXISTING="${ALLOW_EXISTING:-false}"
REGENERATE="${REGENERATE:-false}"
SKIP_ROOT_CHECK="${SKIP_ROOT_CHECK:-false}"
SKIP_APT="${SKIP_APT:-false}"
SKIP_XRAY_INSTALL="${SKIP_XRAY_INSTALL:-false}"
SKIP_SYSCTL="${SKIP_SYSCTL:-false}"
SKIP_WARP="${SKIP_WARP:-false}"
SKIP_LISTEN_CHECK="${SKIP_LISTEN_CHECK:-false}"

XRAY_BIN="${XRAY_BIN:-/usr/local/bin/xray}"
CONFIG_DIR="${CONFIG_DIR:-/usr/local/etc/xray}"
EXISTING_CONFIG="${CONFIG_DIR}/config.json"
SYSCTL_FILE="${SYSCTL_FILE:-/etc/sysctl.d/99-claude-antiban.conf}"
OUTPUT_FILE="${OUTPUT_FILE:-/root/claude-antiban-node.json}"
OUTPUT_OWNER="${OUTPUT_OWNER:-}"
XRAY_GROUP="${XRAY_GROUP:-}"

# Auto-assign OUTPUT_OWNER to SUDO_USER when writing outside /root under sudo
if [ -z "$OUTPUT_OWNER" ] && [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ] && [[ "$OUTPUT_FILE" != /root/* ]]; then
    OUTPUT_OWNER="$SUDO_USER"
fi

# Pinned official XTLS/Xray-install commit & SHA256 checksum
XRAY_INSTALL_COMMIT="${XRAY_INSTALL_COMMIT:-9d3ad49a3294d4c1d042f1fb6a16360b4d1befd1}"
XRAY_INSTALL_SHA256="${XRAY_INSTALL_SHA256:-91fd40e9b6f222b5819f3ba91f0bfb4bb8c4d425a7c0ffe9d8b155d25ed79609}"
XRAY_INSTALL_URL="${XRAY_INSTALL_URL:-https://raw.githubusercontent.com/XTLS/Xray-install/${XRAY_INSTALL_COMMIT}/install-release.sh}"
XRAY_VERSION="${XRAY_VERSION:-v26.11.9}"

# Color Codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

# Helper: strict IPv4 validator (rejects placeholders like YOUR_VPS_IP or HTML errors)
is_valid_ipv4() {
    local ip="$1"
    if ! [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 1
    fi
    local IFS='.'
    local o1 o2 o3 o4
    read -r o1 o2 o3 o4 <<< "$ip"
    for octet in "$o1" "$o2" "$o3" "$o4"; do
        if [ "$octet" -gt 255 ]; then
            return 1
        fi
    done
    return 0
}

# Helper: validate inbound host (IPv4 or RFC hostname; rejects placeholders/whitespace)
is_valid_host() {
    local h="$1"
    if [ -z "$h" ] || [ "$h" = "YOUR_VPS_IP" ]; then
        return 1
    fi
    if is_valid_ipv4 "$h"; then
        return 0
    fi
    # Valid DNS hostname (no underscores, spaces, or angle brackets)
    if [[ "$h" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$ ]]; then
        return 0
    fi
    return 1
}

# Helper: probe public IPv4 egress via HTTPS endpoints (configurable for tests)
EGRESS_PROBE_URLS="${EGRESS_PROBE_URLS:-https://api.ipify.org https://ipinfo.io/ip https://icanhazip.com}"
detect_public_ipv4() {
    local url candidate
    for url in $EGRESS_PROBE_URLS; do
        candidate=$(curl -fsS -4 -m 5 "$url" 2>/dev/null | tr -d ' \t\r\n' || true)
        if is_valid_ipv4 "$candidate"; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    return 1
}

# Helper: derive X25519 PublicKey from raw base64url PrivateKey via stdin ONLY
# (RFC 7748; zero secrets ever passed in child-process CLI argv!)
derive_public_key_stdin() {
    local priv="$1"
    local b64="${priv//-/+}"
    b64="${b64//_//}"
    case $(( ${#b64} % 4 )) in
        2) b64="${b64}==" ;;
        3) b64="${b64}=" ;;
    esac

    local byte_len
    byte_len=$(printf '%s' "$b64" | openssl base64 -d -A 2>/dev/null | wc -c | tr -d ' ' || true)
    if [ "${byte_len:-0}" -ne 32 ]; then
        return 1
    fi

    # PKCS#8 X25519 header: 302e020100300506032b656e04220420 (octal for POSIX safety)
    local derived
    derived=$({
        printf '\060\056\002\001\000\060\005\006\003\053\145\156\004\042\004\040'
        printf '%s' "$b64" | openssl base64 -d -A 2>/dev/null
    } | openssl pkey -inform DER -pubout -outform DER 2>/dev/null \
      | tail -c 32 \
      | openssl base64 -A 2>/dev/null \
      | tr '+/' '-_' \
      | tr -d '=\r\n' || true)

    if [ -z "$derived" ]; then
        return 1
    fi
    printf '%s' "$derived"
}

# Helper: detect non-root xray service group (must be called AFTER Step 2 installs xray)
detect_xray_group() {
    if [ "$XRAY_GROUP" = "none" ]; then
        printf '%s' ""
        return 0
    fi
    if [ -n "$XRAY_GROUP" ]; then
        printf '%s' "$XRAY_GROUP"
        return 0
    fi
    if command -v getent >/dev/null 2>&1 && getent group xray >/dev/null 2>&1; then
        printf '%s' "xray"
        return 0
    fi
    if [ -f "$EXISTING_CONFIG" ]; then
        local grp
        grp=$(stat -c '%G' "$EXISTING_CONFIG" 2>/dev/null || stat -f '%Sg' "$EXISTING_CONFIG" 2>/dev/null || true)
        if [ -n "$grp" ] && [ "$grp" != "root" ] && [ "$grp" != "wheel" ] && [ "$grp" != "UNKNOWN" ]; then
            printf '%s' "$grp"
            return 0
        fi
    fi
    printf '%s' ""
}

# Helper: apply least-privilege directory & file permissions for Xray config
apply_config_dir_perms() {
    local dir="$1"
    local grp="$2"
    mkdir -p "$dir"
    if [ -n "$grp" ]; then
        if [ "$(id -u)" -eq 0 ]; then
            chown "0:${grp}" "$dir"
            chmod 750 "$dir"
        elif chgrp "$grp" "$dir" 2>/dev/null; then
            chmod 750 "$dir"
        else
            chmod 700 "$dir"
        fi
    else
        chmod 700 "$dir"
    fi
}

apply_config_file_perms() {
    local file="$1"
    local grp="$2"
    if [ -n "$grp" ]; then
        if [ "$(id -u)" -eq 0 ]; then
            chown "0:${grp}" "$file"
            chmod 640 "$file"
        elif chgrp "$grp" "$file" 2>/dev/null; then
            chmod 640 "$file"
        else
            chmod 600 "$file"
        fi
    else
        chmod 600 "$file"
    fi
}

# Helper: atomic write with strict 0600 permissions before content is written
# (Explicit error checks so callers using `if ! ...` always receive accurate rc)
write_secret_file_0600() {
    local target="$1"
    local owner="${2:-}"
    local parent
    parent=$(dirname "$target")
    mkdir -p "$parent" || return 1
    local tmp="${target}.tmp.$$"
    if ! (
        umask 077
        cat > "$tmp"
    ); then
        rm -f "$tmp" 2>/dev/null || true
        return 1
    fi
    if ! chmod 600 "$tmp"; then
        rm -f "$tmp" 2>/dev/null || true
        return 1
    fi
    if [ -n "$owner" ] && [ "$(id -u)" -eq 0 ]; then
        if ! (chown "${owner}:${owner}" "$tmp" 2>/dev/null || chown "${owner}" "$tmp"); then
            rm -f "$tmp" 2>/dev/null || true
            return 1
        fi
    fi
    if ! mv "$tmp" "$target"; then
        rm -f "$tmp" 2>/dev/null || true
        return 1
    fi
    chmod 600 "$target" || return 1
}

# ------------------------------------------------------------------------------
# 0. Strict Preflight Checks (BEFORE ANY SYSTEM MUTATION!)
# ------------------------------------------------------------------------------
if [ "$SKIP_ROOT_CHECK" != "true" ] && [ "$(id -u)" -ne 0 ]; then
    log_error "This script must be run as root (or via sudo)!"
    exit 1
fi

if [ -n "$OUTPUT_OWNER" ] && ! id "$OUTPUT_OWNER" >/dev/null 2>&1; then
    log_error "Invalid OUTPUT_OWNER user: ${OUTPUT_OWNER}"
    exit 1
fi

if [ "$SKIP_APT" != "true" ] && ! command -v apt-get >/dev/null 2>&1; then
    log_error "Unsupported OS: apt-get not found. Only Debian 11+ / Ubuntu 22.04+ are supported."
    exit 1
fi

# Validate port inputs if provided
if [ -n "$PORT_INPUT" ]; then
    if ! [[ "$PORT_INPUT" =~ ^[0-9]+$ ]] || [ "$PORT_INPUT" -lt 1 ] || [ "$PORT_INPUT" -gt 65535 ]; then
        log_error "Invalid PORT: ${PORT_INPUT} (must be 1..65535)"
        exit 1
    fi
fi

if [ -n "$INBOUND_PORT_INPUT" ]; then
    if ! [[ "$INBOUND_PORT_INPUT" =~ ^[0-9]+$ ]] || [ "$INBOUND_PORT_INPUT" -lt 1 ] || [ "$INBOUND_PORT_INPUT" -gt 65535 ]; then
        log_error "Invalid INBOUND_PORT: ${INBOUND_PORT_INPUT} (must be 1..65535)"
        exit 1
    fi
fi

# Resolve & strictly validate outbound EGRESS_IP and client INBOUND_HOST BEFORE ANY SYSTEM MUTATION!
if [ -n "$EGRESS_IP_INPUT" ]; then
    if ! is_valid_ipv4 "$EGRESS_IP_INPUT"; then
        log_error "Invalid EGRESS_IP: '${EGRESS_IP_INPUT}' (must be a valid IPv4 address)."
        exit 1
    fi
    EGRESS_IP="$EGRESS_IP_INPUT"
else
    if ! command -v curl >/dev/null 2>&1; then
        log_error "curl is required to auto-detect public IPv4 (or pass EGRESS_IP=<VPS公网IPv4> explicitly)."
        exit 1
    fi
    if ! EGRESS_IP=$(detect_public_ipv4); then
        log_error "Failed to auto-detect a valid public IPv4 from HTTPS probe endpoints (${EGRESS_PROBE_URLS})."
        log_error "Aborting BEFORE making any changes to the VPS to avoid generating broken configs."
        log_error "Please re-run with an explicit valid IPv4: EGRESS_IP=<VPS公网IPv4> bash vps_setup.sh"
        exit 1
    fi
fi

INBOUND_HOST="${INBOUND_HOST_INPUT:-${EGRESS_IP}}"
if ! is_valid_host "$INBOUND_HOST"; then
    log_error "Invalid INBOUND_HOST: '${INBOUND_HOST}' (must be a valid IPv4 or DNS hostname)."
    exit 1
fi

# Record preexisting config BEFORE Step 2 installer runs (upstream installer creates empty {})
HAD_PREEXISTING_CONFIG=false
if [ -f "$EXISTING_CONFIG" ]; then
    HAD_PREEXISTING_CONFIG=true
fi

# Detect existing Xray or WARP installation before touching anything
EXISTING_DETECTED=()
if [ "$HAD_PREEXISTING_CONFIG" = "true" ]; then
    EXISTING_DETECTED+=("config:${EXISTING_CONFIG}")
fi
if [ -x "$XRAY_BIN" ] && [ "$SKIP_XRAY_INSTALL" != "true" ]; then
    EXISTING_DETECTED+=("binary:${XRAY_BIN}")
fi
if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet xray 2>/dev/null || systemctl is-enabled --quiet xray 2>/dev/null; then
        EXISTING_DETECTED+=("service:xray")
    fi
    if [ "$SKIP_WARP" != "true" ] && (systemctl is-active --quiet warp-svc 2>/dev/null || systemctl is-enabled --quiet warp-svc 2>/dev/null); then
        EXISTING_DETECTED+=("service:warp-svc")
    fi
fi
if [ "$SKIP_WARP" != "true" ] && command -v warp-cli >/dev/null 2>&1; then
    EXISTING_DETECTED+=("binary:warp-cli")
fi

if [ "${#EXISTING_DETECTED[@]}" -gt 0 ] && [ "$ALLOW_EXISTING" != "true" ]; then
    log_error "====================================================================="
    log_error "[ABORT] 检测到当前 VPS 已存在 Xray 或 Cloudflare WARP 环境："
    log_error "        ${EXISTING_DETECTED[*]}"
    log_error "为避免意外中断运行中的服务或覆盖现有配置，本脚本默认仅支持【全新 VPS】。"
    log_error "未对系统做任何修改，已安全退出。"
    log_error "如确认在维护窗口内覆盖更新，或系上次安装失败修复后重试，请设置 ALLOW_EXISTING=true。"
    log_error "如需同时轮换全部节点凭证，请设置 ALLOW_EXISTING=true REGENERATE=true。"
    log_error "====================================================================="
    exit 2
fi

# ------------------------------------------------------------------------------
# 1. Install Essential Dependencies
# ------------------------------------------------------------------------------
if [ "$SKIP_APT" != "true" ]; then
    log_info "Step 1: Installing essential dependencies..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    # Do NOT touch/remove ufw to respect existing firewall choices
    apt-get install -y -qq curl wget jq openssl gnupg lsb-release iptables procps iproute2
else
    log_info "Step 1: Skipping apt-get (SKIP_APT=true)."
fi

# Verify jq & openssl are available
for req_cmd in jq openssl; do
    if ! command -v "$req_cmd" >/dev/null 2>&1; then
        log_error "Required tool missing: ${req_cmd}"
        exit 1
    fi
done

# ------------------------------------------------------------------------------
# 2. Install Pinned, Checksum-Verified Xray-core (Private 0700 Staging Dir)
# ------------------------------------------------------------------------------
INSTALLER_STAGE_DIR=""
TMP_CONFIG=""
cleanup_temp_artifacts() {
    if [ -n "${TMP_CONFIG:-}" ] && [ -f "$TMP_CONFIG" ]; then
        rm -f "$TMP_CONFIG" || true
    fi
    if [ -n "${INSTALLER_STAGE_DIR:-}" ] && [ -d "$INSTALLER_STAGE_DIR" ]; then
        rm -f "${INSTALLER_STAGE_DIR}/install-release.sh" || true
        rmdir "$INSTALLER_STAGE_DIR" 2>/dev/null || true
    fi
}
trap cleanup_temp_artifacts EXIT

XRAY_INSTALLED_BY_US=false
if [ "$SKIP_XRAY_INSTALL" != "true" ]; then
    log_info "Step 2: Downloading pinned Xray installer (commit ${XRAY_INSTALL_COMMIT:0:10}, Xray ${XRAY_VERSION})..."
    INSTALLER_STAGE_DIR=$(umask 077 && mktemp -d "${TMPDIR:-/tmp}/xray-install.XXXXXX")
    chmod 700 "$INSTALLER_STAGE_DIR"
    INSTALLER_TMP="${INSTALLER_STAGE_DIR}/install-release.sh"

    curl -fsSL "$XRAY_INSTALL_URL" -o "$INSTALLER_TMP"
    chmod 600 "$INSTALLER_TMP"

    if command -v sha256sum >/dev/null 2>&1; then
        ACTUAL_SHA256=$(sha256sum "$INSTALLER_TMP" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        ACTUAL_SHA256=$(shasum -a 256 "$INSTALLER_TMP" | awk '{print $1}')
    else
        log_error "Neither sha256sum nor shasum found to verify installer integrity!"
        exit 1
    fi

    if [ "$ACTUAL_SHA256" != "$XRAY_INSTALL_SHA256" ]; then
        log_error "Xray installer SHA256 mismatch!"
        log_error "  Expected: ${XRAY_INSTALL_SHA256}"
        log_error "  Actual  : ${ACTUAL_SHA256}"
        exit 1
    fi
    log_info "Xray installer SHA256 verified."

    # Pinned XTLS/Xray-install removed -u; keep upstream non-root User=xray service unit!
    bash "$INSTALLER_TMP" install --version "$XRAY_VERSION"
    XRAY_INSTALLED_BY_US=true
    rm -f "$INSTALLER_TMP"
    rmdir "$INSTALLER_STAGE_DIR" 2>/dev/null || true
    INSTALLER_STAGE_DIR=""
else
    log_info "Step 2: Skipping Xray binary installation (SKIP_XRAY_INSTALL=true)."
fi

if [ ! -x "$XRAY_BIN" ]; then
    log_error "Xray binary not found or not executable at ${XRAY_BIN}!"
    exit 1
fi

# Detect service group AFTER Step 2 has created the xray user/group
ACTIVE_XRAY_GROUP=$(detect_xray_group)
if [ -n "$ACTIVE_XRAY_GROUP" ]; then
    log_info "Detected Xray service group: ${ACTIVE_XRAY_GROUP} (config.json will use 0640 root:${ACTIVE_XRAY_GROUP})."
else
    log_info "No dedicated Xray service group detected (config.json will use strict 0600)."
fi

# ------------------------------------------------------------------------------
# 3. Configure or Reuse Reality Credentials (Zero Split-Brain!)
# ------------------------------------------------------------------------------
log_info "Step 3: Configuring VLESS Reality credentials and ports..."

UUID=""
PRIVATE_KEY=""
PUBLIC_KEY=""
SHORT_ID=""
PORT=""
SNI=""
EXISTING_CLIENTS=""
EXISTING_SHORT_IDS=""
EXTRA_INBOUNDS=""
REUSED_CREDENTIALS=false

# Upstream XTLS/Xray-install creates an empty "{}" config.json stub on fresh VPS.
# Treat an empty "{}" stub (or absent config) as a fresh install, NEVER as a broken existing node.
IS_EMPTY_STUB=false
if [ -f "$EXISTING_CONFIG" ] && jq -e 'type == "object" and (keys | length == 0)' "$EXISTING_CONFIG" >/dev/null 2>&1; then
    IS_EMPTY_STUB=true
fi

TREAT_AS_EXISTING=false
if [ -f "$EXISTING_CONFIG" ] && [ "$IS_EMPTY_STUB" != "true" ]; then
    TREAT_AS_EXISTING=true
elif [ "$IS_EMPTY_STUB" = "true" ]; then
    log_info "Detected empty '{}' config.json stub (upstream installer default); proceeding as fresh installation."
fi

if [ "$TREAT_AS_EXISTING" = "true" ]; then
    EXTRA_INBOUNDS=$(jq -c '.inbounds[1:] // empty' "$EXISTING_CONFIG" 2>/dev/null || true)
    EXISTING_PORT=$(jq -r '.inbounds[0].port // empty' "$EXISTING_CONFIG" 2>/dev/null || true)
    EXISTING_SNI=$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0] // empty' "$EXISTING_CONFIG" 2>/dev/null || true)

    if [ -n "$EXISTING_PORT" ] && [ -z "$PORT_INPUT" ]; then
        PORT="$EXISTING_PORT"
        log_info "Preserving existing listening port: ${PORT}"
    fi
    if [ -n "$EXISTING_SNI" ] && [ -z "$SNI_INPUT" ]; then
        SNI="$EXISTING_SNI"
        log_info "Preserving existing SNI: ${SNI}"
    fi

    if [ "$REGENERATE" != "true" ]; then
        log_info "Reusing existing Reality credentials from ${EXISTING_CONFIG}..."
        EXISTING_CLIENTS=$(jq -c '.inbounds[0].settings.clients // empty' "$EXISTING_CONFIG" 2>/dev/null || true)
        EXISTING_SHORT_IDS=$(jq -c '.inbounds[0].streamSettings.realitySettings.shortIds // empty' "$EXISTING_CONFIG" 2>/dev/null || true)
        UUID=$(jq -r '.inbounds[0].settings.clients[0].id // empty' "$EXISTING_CONFIG" 2>/dev/null || true)
        PRIVATE_KEY=$(jq -r '.inbounds[0].streamSettings.realitySettings.privateKey // empty' "$EXISTING_CONFIG" 2>/dev/null || true)

        # IMPORTANT: Xray Reality explicitly allows empty string "" as a valid shortId!
        # Check shortIds array existence & length >= 1 rather than non-empty string.
        HAS_SHORT_IDS=false
        if jq -e '.inbounds[0].streamSettings.realitySettings.shortIds | type == "array" and length > 0' "$EXISTING_CONFIG" >/dev/null 2>&1; then
            HAS_SHORT_IDS=true
            SHORT_ID=$(jq -r '.inbounds[0].streamSettings.realitySettings.shortIds[0]' "$EXISTING_CONFIG")
        fi

        if [ -n "$PRIVATE_KEY" ]; then
            PUBLIC_KEY=$(derive_public_key_stdin "$PRIVATE_KEY" || true)
        fi

        # Refuse partial reuse that could cause split-brain between clients/shortIds and privateKey
        if [ -z "$UUID" ] || [ -z "$PRIVATE_KEY" ] || [ -z "$PUBLIC_KEY" ] || [ "$HAS_SHORT_IDS" != "true" ]; then
            log_error "Existing config ${EXISTING_CONFIG} is missing valid Reality credentials (uuid/privateKey/publicKey/shortIds)."
            log_error "Refusing partial regeneration to avoid client/server credential mismatch."
            log_error "Run with ALLOW_EXISTING=true REGENERATE=true to cleanly rotate all credentials."
            exit 1
        fi
        REUSED_CREDENTIALS=true
    else
        log_info "REGENERATE=true: rotating all primary inbound credentials cleanly..."
        EXISTING_CLIENTS=""
        EXISTING_SHORT_IDS=""
    fi
fi

PORT="${PORT:-${PORT_INPUT:-24433}}"
SNI="${SNI:-${SNI_INPUT:-gateway.icloud.com}}"

if [ "$REUSED_CREDENTIALS" != "true" ]; then
    log_info "Generating fresh Xray UUID and X25519 Reality keypair..."
    UUID=$("$XRAY_BIN" uuid)
    SHORT_ID=$(openssl rand -hex 8)

    X25519_OUTPUT=$("$XRAY_BIN" x25519)
    PRIVATE_KEY=$(printf '%s\n' "$X25519_OUTPUT" | grep -iE "(private key|privatekey)" | head -n 1 | awk -F': ' '{print $2}' | tr -d ' \r\n' || true)
    PUBLIC_KEY=$(printf '%s\n' "$X25519_OUTPUT" | grep -iE "(public key|publickey|password)" | head -n 1 | awk -F': ' '{print $2}' | tr -d ' \r\n' || true)

    if [ -z "$PRIVATE_KEY" ] || [ -z "$PUBLIC_KEY" ] || [ -z "$UUID" ] || [ -z "$SHORT_ID" ]; then
        log_error "Failed to generate valid Xray Reality credentials (raw output redacted for security; status: uuid=$([ -n "$UUID" ] && echo ok || echo empty), privateKey=$([ -n "$PRIVATE_KEY" ] && echo ok || echo empty), publicKey=$([ -n "$PUBLIC_KEY" ] && echo ok || echo empty), shortId=$([ -n "$SHORT_ID" ] && echo ok || echo empty))."
        exit 1
    fi
fi

log_info "Reality credentials prepared (reused=${REUSED_CREDENTIALS})."

# ------------------------------------------------------------------------------
# 4. Kernel Tuning (with Persistent + Per-Interface Live Runtime Rollback Snapshot)
# ------------------------------------------------------------------------------
SYSCTL_BACKUP=""
SYSCTL_MODIFIED=false
SYSCTL_BASE_KEYS=(
    "net.ipv4.tcp_keepalive_time"
    "net.ipv4.tcp_keepalive_intvl"
    "net.ipv4.tcp_keepalive_probes"
    "net.core.default_qdisc"
    "net.ipv4.tcp_congestion_control"
)
SYSCTL_SAVED_GLOBAL_IPV6=()
SYSCTL_SAVED_IFACE_IPV6=()
SYSCTL_SAVED_BASE_PAIRS=()

rollback_sysctl() {
    if [ "$SYSCTL_MODIFIED" = "true" ]; then
        if [ -n "$SYSCTL_BACKUP" ] && [ -f "$SYSCTL_BACKUP" ]; then
            cp "$SYSCTL_BACKUP" "$SYSCTL_FILE" || true
        else
            rm -f "$SYSCTL_FILE" || true
        fi
        sysctl --system >/dev/null 2>&1 || true
        # Restore order matters on Linux:
        # 1. Restore all/default disable_ipv6 FIRST (writing all.disable_ipv6 propagates to interfaces)
        # 2. Then restore every specific interface's original disable_ipv6 (lo, eth0, ens3, ...)
        # 3. Restore non-IPv6 TCP keepalive & congestion control values
        local pair
        for pair in "${SYSCTL_SAVED_GLOBAL_IPV6[@]}"; do
            sysctl -w "$pair" >/dev/null 2>&1 || true
        done
        for pair in "${SYSCTL_SAVED_IFACE_IPV6[@]}"; do
            sysctl -w "$pair" >/dev/null 2>&1 || true
        done
        for pair in "${SYSCTL_SAVED_BASE_PAIRS[@]}"; do
            sysctl -w "$pair" >/dev/null 2>&1 || true
        done
        SYSCTL_MODIFIED=false
        log_warn "Rolled back sysctl file (${SYSCTL_FILE}) and restored per-interface & live kernel values."
    fi
}

if [ "$SKIP_SYSCTL" != "true" ]; then
    log_info "Step 4: Tuning Linux Kernel parameters (Anti-leak & Keepalive)..."
    # Snapshot ALL per-interface net.ipv6.conf.*.disable_ipv6 values (all, default, lo, eth0, ens3, ...)
    while IFS= read -r _line; do
        [ -z "$_line" ] && continue
        _k=$(printf '%s' "$_line" | cut -d'=' -f1 | tr -d ' \t')
        _v=$(printf '%s' "$_line" | cut -d'=' -f2- | tr -d ' \t\r')
        [ -z "$_k" ] || [ -z "$_v" ] && continue
        case "$_k" in
            net.ipv6.conf.all.disable_ipv6|net.ipv6.conf.default.disable_ipv6)
                SYSCTL_SAVED_GLOBAL_IPV6+=("${_k}=${_v}")
                ;;
            net.ipv6.conf.*.disable_ipv6)
                SYSCTL_SAVED_IFACE_IPV6+=("${_k}=${_v}")
                ;;
        esac
    done < <(sysctl net.ipv6.conf 2>/dev/null | grep -E '^net\.ipv6\.conf\.[^[:space:]]+\.disable_ipv6[[:space:]]*=' || true)

    # Fallback if sysctl net.ipv6.conf returned nothing: snapshot all/default/lo via sysctl -n
    if [ "${#SYSCTL_SAVED_GLOBAL_IPV6[@]}" -eq 0 ] && [ "${#SYSCTL_SAVED_IFACE_IPV6[@]}" -eq 0 ]; then
        for _k in net.ipv6.conf.all.disable_ipv6 net.ipv6.conf.default.disable_ipv6; do
            _v=$(sysctl -n "$_k" 2>/dev/null || true)
            [ -n "$_v" ] && SYSCTL_SAVED_GLOBAL_IPV6+=("${_k}=${_v}")
        done
        _v=$(sysctl -n net.ipv6.conf.lo.disable_ipv6 2>/dev/null || true)
        [ -n "$_v" ] && SYSCTL_SAVED_IFACE_IPV6+=("net.ipv6.conf.lo.disable_ipv6=${_v}")
    fi

    # Snapshot non-IPv6 live runtime values
    for _k in "${SYSCTL_BASE_KEYS[@]}"; do
        _v=$(sysctl -n "$_k" 2>/dev/null || true)
        if [ -n "$_v" ]; then
            SYSCTL_SAVED_BASE_PAIRS+=("${_k}=${_v}")
        fi
    done

    if [ -f "$SYSCTL_FILE" ]; then
        SYSCTL_BACKUP="${SYSCTL_FILE}.bak.$(date +%s)"
        cp "$SYSCTL_FILE" "$SYSCTL_BACKUP"
    fi
    mkdir -p "$(dirname "$SYSCTL_FILE")"
    cat > "$SYSCTL_FILE" << 'EOF'
# Disable IPv6 to prevent DNS and WebRTC leaks
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1

# TCP Keepalive for long reasoning AI streams (prevent Broken Pipe)
net.ipv4.tcp_keepalive_time = 30
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 3

# Fast BBR Congestion Control (if supported)
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
    SYSCTL_MODIFIED=true
    sysctl --system >/dev/null 2>&1 || true
else
    log_info "Step 4: Skipping sysctl tuning (SKIP_SYSCTL=true)."
fi

# ------------------------------------------------------------------------------
# 5. Install & Configure Cloudflare WARP (Proxy Mode with Graceful Fallback)
# ------------------------------------------------------------------------------
WARP_READY=false
if [ "$SKIP_WARP" != "true" ]; then
    log_info "Step 5: Setting up Cloudflare WARP for Gemini routing..."
    if ! command -v warp-cli >/dev/null 2>&1; then
        curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg 2>/dev/null || true
        echo "deb [arch=amd64 signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/cloudflare-client.list >/dev/null
        apt-get update -qq || true
        apt-get install -y -qq cloudflare-warp || log_warn "Failed to install cloudflare-warp package via apt."
    fi

    if command -v warp-cli >/dev/null 2>&1; then
        systemctl enable --now warp-svc >/dev/null 2>&1 || true
        sleep 2
        warp-cli --accept-tos registration new >/dev/null 2>&1 || warp-cli --accept-tos register >/dev/null 2>&1 || true
        warp-cli --accept-tos mode proxy >/dev/null 2>&1 || true
        warp-cli --accept-tos proxy port "${WARP_PORT}" >/dev/null 2>&1 || true
        warp-cli --accept-tos connect >/dev/null 2>&1 || true

        for _ in 1 2 3 4 5; do
            if curl -s --socks5 "127.0.0.1:${WARP_PORT}" -m 3 https://cloudflare.com/cdn-cgi/trace 2>/dev/null | grep -qE "warp=(on|plus)"; then
                WARP_READY=true
                break
            fi
            sleep 1
        done
    fi
else
    log_info "Step 5: Skipping Cloudflare WARP setup (SKIP_WARP=true)."
fi

GOOGLE_OUTBOUND="warp"
if [ "$WARP_READY" != "true" ]; then
    GOOGLE_OUTBOUND="direct"
    log_warn "Cloudflare WARP proxy on 127.0.0.1:${WARP_PORT} is not ready; Google/Gemini falls back to DIRECT."
else
    log_info "Cloudflare WARP proxy verified active on 127.0.0.1:${WARP_PORT} (Dual-track enabled)."
fi

# ------------------------------------------------------------------------------
# 6. Build & Validate Candidate Xray Configuration (Least-Privilege Permissions)
# ------------------------------------------------------------------------------
log_info "Step 6: Generating and validating candidate Xray server configuration..."

apply_config_dir_perms "$CONFIG_DIR" "$ACTIVE_XRAY_GROUP"
TMP_CONFIG="${CONFIG_DIR}/config.tmp.$$.json"

# Pass sensitive values to jq via stdin ONLY (never CLI --arg!)
if [ "$REUSED_CREDENTIALS" = "true" ] && [ -n "$EXISTING_CLIENTS" ] && [ "$EXISTING_CLIENTS" != "null" ]; then
    CLIENTS_JSON="$EXISTING_CLIENTS"
else
    CLIENTS_JSON=$(printf '%s' "$UUID" | jq -Rsc '[{"id": ., "flow": "xtls-rprx-vision"}]')
fi

if [ "$REUSED_CREDENTIALS" = "true" ] && [ -n "$EXISTING_SHORT_IDS" ] && [ "$EXISTING_SHORT_IDS" != "null" ]; then
    SHORT_IDS_JSON="$EXISTING_SHORT_IDS"
else
    SHORT_IDS_JSON=$(printf '%s' "$SHORT_ID" | jq -Rsc '[.]')
fi

EXTRA_INBOUNDS_SNIPPET=""
if [ -n "$EXTRA_INBOUNDS" ] && [ "$EXTRA_INBOUNDS" != "[]" ] && [ "$EXTRA_INBOUNDS" != "null" ]; then
    STRIPPED=$(printf '%s' "$EXTRA_INBOUNDS" | sed -e 's/^[[:space:]]*\[//' -e 's/\][[:space:]]*$//')
    if [ -n "$STRIPPED" ]; then
        EXTRA_INBOUNDS_SNIPPET=", ${STRIPPED}"
    fi
fi

# Create TMP_CONFIG strictly restricted BEFORE writing privateKey (never world-readable)
CONFIG_UMASK="077"
if [ -n "$ACTIVE_XRAY_GROUP" ]; then
    CONFIG_UMASK="027"
fi

(
    umask "$CONFIG_UMASK"
    cat > "$TMP_CONFIG" << EOF
{
  "log": {
    "loglevel": "warning"
  },
  "policy": {
    "levels": {
      "0": {
        "handshake": 4,
        "connIdle": 1800,
        "uplinkOnly": 2,
        "downlinkOnly": 5,
        "statsUserUplink": false,
        "statsUserDownlink": false,
        "bufferSize": 4
      }
    }
  },
  "inbounds": [
    {
      "port": ${PORT},
      "protocol": "vless",
      "settings": {
        "clients": ${CLIENTS_JSON},
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "sockopt": {
          "tcpKeepAliveInterval": 15
        },
        "realitySettings": {
          "show": false,
          "dest": "${SNI}:443",
          "xver": 0,
          "serverNames": [
            "${SNI}"
          ],
          "privateKey": "${PRIVATE_KEY}",
          "shortIds": ${SHORT_IDS_JSON}
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      }
    }${EXTRA_INBOUNDS_SNIPPET}
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom",
      "settings": {
        "domainStrategy": "UseIPv4"
      },
      "streamSettings": {
        "sockopt": {
          "tcpKeepAliveInterval": 15
        }
      }
    },
    {
      "tag": "warp",
      "protocol": "socks",
      "settings": {
        "servers": [
          {
            "address": "127.0.0.1",
            "port": ${WARP_PORT}
          }
        ]
      }
    },
    {
      "tag": "block",
      "protocol": "blackhole",
      "settings": {}
    }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "port": 443,
        "network": "udp",
        "outboundTag": "block"
      },
      {
        "type": "field",
        "ip": [
          "geoip:private"
        ],
        "outboundTag": "block"
      },
      {
        "type": "field",
        "domain": [
          "geosite:anthropic",
          "geosite:openai",
          "domain:claude.ai",
          "domain:anthropic.com",
          "domain:claudeusercontent.com",
          "domain:withpersona.com",
          "domain:challenges.cloudflare.com",
          "domain:openai.com",
          "domain:chatgpt.com",
          "domain:oaistatic.com",
          "domain:oaiusercontent.com"
        ],
        "outboundTag": "direct"
      },
      {
        "type": "field",
        "domain": [
          "geosite:google",
          "domain:gemini.google.com",
          "domain:aistudio.google.com",
          "domain:generativelanguage.googleapis.com",
          "domain:deepmind.google",
          "domain:deepmind.com",
          "domain:alkalicore-pa.clients6.google.com",
          "domain:alkalimakersuite-pa.clients6.google.com",
          "domain:webchannel-alkalimakersuite-pa.clients6.google.com",
          "domain:robinfrontend-pa.googleapis.com"
        ],
        "outboundTag": "${GOOGLE_OUTBOUND}"
      },
      {
        "type": "field",
        "ip": [
          "geoip:google"
        ],
        "outboundTag": "${GOOGLE_OUTBOUND}"
      },
      {
        "type": "field",
        "network": "tcp,udp",
        "outboundTag": "direct"
      }
    ]
  }
}
EOF
)
apply_config_file_perms "$TMP_CONFIG" "$ACTIVE_XRAY_GROUP"

# Verify non-root xray service account can actually read the candidate config
if [ "$(id -u)" -eq 0 ] && id xray >/dev/null 2>&1; then
    if ! su -s /bin/sh xray -c "test -r '$TMP_CONFIG'" 2>/dev/null; then
        log_error "Non-root service user 'xray' cannot read ${TMP_CONFIG}! Check ${CONFIG_DIR} group ownership."
        rm -f "$TMP_CONFIG"
        rollback_sysctl
        exit 1
    fi
    log_info "Verified: non-root user 'xray' can read candidate config."
fi

# Configuration Pre-flight Validation
log_info "Testing generated configuration syntax with Xray..."
if ! "$XRAY_BIN" run -test -config "$TMP_CONFIG" >/dev/null 2>&1 && ! "$XRAY_BIN" -test -config "$TMP_CONFIG" >/dev/null 2>&1; then
    log_error "Configuration syntax validation FAILED! Aborting update and rolling back."
    "$XRAY_BIN" run -test -config "$TMP_CONFIG" || "$XRAY_BIN" -test -config "$TMP_CONFIG" || true
    rm -f "$TMP_CONFIG"
    rollback_sysctl
    exit 1
fi
log_info "Configuration validation passed."

# ------------------------------------------------------------------------------
# 7. Strict Firewall Enforcement BEFORE Mutating Active config.json (Track for Rollback!)
# ------------------------------------------------------------------------------
FIREWALL_STATUS="none_detected"
FIREWALL_RULE_ADDED=false
FIREWALL_BACKEND=""
FWD_ADDED_PERM=false
FWD_ADDED_RUNTIME=false

rollback_firewall() {
    if [ "$FIREWALL_RULE_ADDED" != "true" ]; then
        return 0
    fi
    case "$FIREWALL_BACKEND" in
        ufw)
            ufw --force delete allow "${PORT}/tcp" >/dev/null 2>&1 || true
            ;;
        firewalld)
            if [ "$FWD_ADDED_PERM" = "true" ]; then
                firewall-cmd --permanent --remove-port="${PORT}/tcp" >/dev/null 2>&1 || true
                FWD_ADDED_PERM=false
            fi
            if [ "$FWD_ADDED_RUNTIME" = "true" ]; then
                firewall-cmd --remove-port="${PORT}/tcp" >/dev/null 2>&1 || true
                FWD_ADDED_RUNTIME=false
            fi
            ;;
        iptables)
            iptables -D INPUT -p tcp --dport "${PORT}" -j ACCEPT >/dev/null 2>&1 || true
            ;;
    esac
    FIREWALL_RULE_ADDED=false
    log_warn "Rolled back newly added ${FIREWALL_BACKEND} firewall rule for TCP port ${PORT}."
}

rollback_pre_deploy() {
    rm -f "$TMP_CONFIG"
    rollback_firewall
    rollback_sysctl
    if [ "$HAD_PREEXISTING_CONFIG" != "true" ] && [ "$IS_EMPTY_STUB" = "true" ] && [ -f "$EXISTING_CONFIG" ]; then
        rm -f "$EXISTING_CONFIG" || true
    fi
    if [ "$XRAY_INSTALLED_BY_US" = "true" ]; then
        log_warn "原 config.json 未被覆盖；修复防火墙后请运行: ALLOW_EXISTING=true bash vps_setup.sh"
    else
        log_warn "已回滚临时文件与 sysctl，原 config.json 保持原样未修改。"
    fi
}

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    log_info "Step 7: Active UFW detected; allowing TCP port ${PORT}..."
    UFW_PREEXISTING=false
    if ufw status 2>/dev/null | grep -qE "(^|[[:space:]])${PORT}/tcp[[:space:]]+ALLOW"; then
        UFW_PREEXISTING=true
    fi
    if ! ufw allow "${PORT}/tcp"; then
        log_error "FAILED to allow port ${PORT}/tcp in UFW! Rolling back before touching active config.json."
        rollback_pre_deploy
        exit 1
    fi
    if [ "$UFW_PREEXISTING" != "true" ]; then
        FIREWALL_RULE_ADDED=true
        FIREWALL_BACKEND="ufw"
    fi
    FIREWALL_STATUS="ufw_allowed"
    log_info "Confirmed: UFW allowed TCP port ${PORT}."
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    log_info "Step 7: Active firewalld detected; allowing TCP port ${PORT}..."
    # Independently check permanent vs runtime rules so rollback ONLY undoes what WE added!
    FWD_HAD_PERM=false
    FWD_HAD_RUNTIME=false
    if firewall-cmd --permanent --query-port="${PORT}/tcp" >/dev/null 2>&1; then
        FWD_HAD_PERM=true
    fi
    if firewall-cmd --query-port="${PORT}/tcp" >/dev/null 2>&1; then
        FWD_HAD_RUNTIME=true
    fi
    if [ "$FWD_HAD_PERM" != "true" ]; then
        if ! firewall-cmd --permanent --add-port="${PORT}/tcp"; then
            log_error "FAILED to add permanent port ${PORT}/tcp in firewalld! Rolling back before touching active config.json."
            rollback_pre_deploy
            exit 1
        fi
        # Record immediately BEFORE reload so a failed reload still rolls back the permanent rule!
        FWD_ADDED_PERM=true
        FIREWALL_RULE_ADDED=true
        FIREWALL_BACKEND="firewalld"
    fi
    if [ "$FWD_HAD_RUNTIME" != "true" ]; then
        if ! firewall-cmd --reload; then
            log_error "FAILED to reload firewalld after configuring port ${PORT}/tcp! Rolling back newly added rules."
            rollback_pre_deploy
            exit 1
        fi
        FWD_ADDED_RUNTIME=true
        FIREWALL_RULE_ADDED=true
        FIREWALL_BACKEND="firewalld"
    fi
    FIREWALL_STATUS="firewalld_allowed"
    log_info "Confirmed: firewalld allowed TCP port ${PORT}."
elif command -v iptables >/dev/null 2>&1; then
    log_info "Step 7: Ensuring iptables accepts TCP port ${PORT}..."
    if ! iptables -C INPUT -p tcp --dport "${PORT}" -j ACCEPT 2>/dev/null; then
        if ! iptables -I INPUT -p tcp --dport "${PORT}" -j ACCEPT; then
            log_error "FAILED to add iptables ACCEPT rule for TCP port ${PORT}! Rolling back before touching active config.json."
            rollback_pre_deploy
            exit 1
        fi
        FIREWALL_RULE_ADDED=true
        FIREWALL_BACKEND="iptables"
    fi
    FIREWALL_STATUS="iptables_allowed"
    log_info "Confirmed: iptables allows TCP port ${PORT}."
fi

# ------------------------------------------------------------------------------
# 8. Atomic Deployment, Service Restart & Local Listening Verification (Full Rollback)
# ------------------------------------------------------------------------------
BACKUP_PATH=""
if [ "$TREAT_AS_EXISTING" = "true" ] && [ -f "$EXISTING_CONFIG" ]; then
    BACKUP_PATH="${CONFIG_DIR}/config.json.bak.$(date +%s)"
    (
        umask 077
        install -m 600 "$EXISTING_CONFIG" "$BACKUP_PATH"
    )
    log_info "Existing configuration backed up (0600) to ${BACKUP_PATH}"
fi

rollback_deployed_config() {
    if [ -n "$BACKUP_PATH" ] && [ -f "$BACKUP_PATH" ]; then
        log_warn "Initiating automatic rollback to previous configuration: ${BACKUP_PATH}..."
        cp "$BACKUP_PATH" "$EXISTING_CONFIG"
        apply_config_file_perms "$EXISTING_CONFIG" "$ACTIVE_XRAY_GROUP"
        systemctl restart xray || true
    else
        rm -f "$EXISTING_CONFIG" || true
        systemctl stop xray >/dev/null 2>&1 || true
    fi
    rollback_firewall
    rollback_sysctl
    log_warn "已完整回滚配置、新增防火墙规则与 sysctl；修复问题后可使用 ALLOW_EXISTING=true bash vps_setup.sh 重试。"
}

# Atomic replacement preserving least-privilege permissions (0640 root:xray or 0600)
mv "$TMP_CONFIG" "$EXISTING_CONFIG"
apply_config_file_perms "$EXISTING_CONFIG" "$ACTIVE_XRAY_GROUP"

log_info "Step 8: Restarting Xray service..."
systemctl enable xray >/dev/null 2>&1 || true

RESTART_OK=true
if ! systemctl restart xray; then
    RESTART_OK=false
fi

sleep 2
if [ "$RESTART_OK" != "true" ] || ! systemctl is-active --quiet xray; then
    log_error "Xray service failed to start/restart after applying new configuration!"
    journalctl -u xray -n 25 --no-pager 2>/dev/null || true
    rollback_deployed_config
    exit 1
fi
log_info "Xray service active!"

if [ "$SKIP_LISTEN_CHECK" != "true" ]; then
    LISTEN_OK=false
    if command -v ss >/dev/null 2>&1 && ss -tln 2>/dev/null | grep -qE "[:.]${PORT}[[:space:]]"; then
        LISTEN_OK=true
    elif command -v netstat >/dev/null 2>&1 && netstat -tln 2>/dev/null | grep -qE "[:.]${PORT}[[:space:]]"; then
        LISTEN_OK=true
    fi
    if [ "$LISTEN_OK" != "true" ]; then
        log_error "Xray does not appear to be listening on TCP port ${PORT}!"
        rollback_deployed_config
        exit 1
    fi
    log_info "Confirmed: Xray is actively listening on TCP port ${PORT}."
fi

# ------------------------------------------------------------------------------
# 9. Derive Delivered Metadata Strictly From Final Active config.json (0600 File)
#    With Transactional Rollback if Node Metadata Delivery Fails!
# ------------------------------------------------------------------------------
FINAL_LISTEN_PORT=$(jq -r '.inbounds[0].port // empty' "$EXISTING_CONFIG")
FINAL_UUID=$(jq -r '.inbounds[0].settings.clients[0].id // empty' "$EXISTING_CONFIG")
FINAL_SNI=$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0] // empty' "$EXISTING_CONFIG")
FINAL_PRIVATE_KEY=$(jq -r '.inbounds[0].streamSettings.realitySettings.privateKey // empty' "$EXISTING_CONFIG")

FINAL_PUBLIC_KEY=""
if [ -n "$FINAL_PRIVATE_KEY" ]; then
    FINAL_PUBLIC_KEY=$(derive_public_key_stdin "$FINAL_PRIVATE_KEY" || true)
fi

if [ -z "$FINAL_LISTEN_PORT" ] || [ -z "$FINAL_UUID" ] || [ -z "$FINAL_SNI" ] || [ -z "$FINAL_PUBLIC_KEY" ]; then
    log_error "Internal consistency check failed when reading final config ${EXISTING_CONFIG}!"
    rollback_deployed_config
    exit 1
fi

FINAL_INBOUND_PORT="${INBOUND_PORT_INPUT:-${FINAL_LISTEN_PORT}}"

# Zero secret exposure in jq argv: read uuid/short_id directly from config.json, pipe public_key on stdin!
# Explicitly record separate listen_port, inbound_host, inbound_port, egress_ip (plus server_ip & port aliases).
METADATA_JSON=$(printf '%s' "$FINAL_PUBLIC_KEY" | jq -Rs \
    --slurpfile cfg "$EXISTING_CONFIG" \
    --arg inbound_host "$INBOUND_HOST" \
    --argjson inbound_port "$FINAL_INBOUND_PORT" \
    --arg egress_ip "$EGRESS_IP" \
    --arg security "reality" \
    --arg fingerprint "chrome" \
    --argjson warp_port "$WARP_PORT" \
    --argjson warp_ready "$WARP_READY" \
    --arg google_outbound "$GOOGLE_OUTBOUND" \
    --arg firewall_status "$FIREWALL_STATUS" \
    '{
      server_ip: $inbound_host,
      port: $inbound_port,
      inbound_host: $inbound_host,
      inbound_port: $inbound_port,
      listen_port: $cfg[0].inbounds[0].port,
      egress_ip: $egress_ip,
      uuid: $cfg[0].inbounds[0].settings.clients[0].id,
      flow: ($cfg[0].inbounds[0].settings.clients[0].flow // "xtls-rprx-vision"),
      security: $security,
      sni: $cfg[0].inbounds[0].streamSettings.realitySettings.serverNames[0],
      public_key: .,
      short_id: $cfg[0].inbounds[0].streamSettings.realitySettings.shortIds[0],
      fingerprint: $fingerprint,
      warp_port: $warp_port,
      warp_ready: $warp_ready,
      google_outbound: $google_outbound,
      firewall_status: $firewall_status
    }')

if ! printf '%s\n' "$METADATA_JSON" | write_secret_file_0600 "$OUTPUT_FILE" "$OUTPUT_OWNER"; then
    log_error "Failed to write node metadata file to ${OUTPUT_FILE}! Rolling back deployed config, firewall rule, and sysctl."
    rollback_deployed_config
    exit 1
fi

echo ""
echo "==================== VPS SETUP COMPLETE ===================="
echo "Inbound Endpoint : ${INBOUND_HOST}:${FINAL_INBOUND_PORT}/tcp"
echo "Local Listen Port: ${FINAL_LISTEN_PORT}/tcp"
echo "Expected Egress  : ${EGRESS_IP}"
echo "SNI              : ${FINAL_SNI}"
echo "Service Group    : ${ACTIVE_XRAY_GROUP:-none (0600)}"
echo "WARP Dual-Track  : ${WARP_READY} (Google outbound: ${GOOGLE_OUTBOUND})"
echo "VPS Firewall     : ${FIREWALL_STATUS}"
echo "Metadata File    : ${OUTPUT_FILE} (permissions: 0600${OUTPUT_OWNER:+, owner: ${OUTPUT_OWNER}})"
echo ""
echo "[NEXT STEP] Copy ${OUTPUT_FILE} securely to your local machine via scp (do NOT paste secrets into chat),"
echo "            then verify inbound TCP port reachability + HTTPS proxy egress from your local machine."
echo "[NOTE]      Cloud provider security groups (AWS/GCP/Aliyun/etc.) are separate from VPS ufw/iptables:"
echo "            ensure TCP port ${FINAL_INBOUND_PORT} (local ${FINAL_LISTEN_PORT}) is open in your cloud console if client reachability fails."

if [ "$PRINT_JSON" = "true" ]; then
    echo ""
    echo "###JSON_OUTPUT_START###"
    printf '%s\n' "$METADATA_JSON"
    echo "###JSON_OUTPUT_END###"
fi
echo "============================================================"
