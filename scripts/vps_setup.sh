#!/usr/bin/env bash
# ==============================================================================
# Claude Anti-Ban Network Setup Script for Fresh Linux VPS (Debian / Ubuntu)
# Hardened Production Design:
# 1. Preflight guard: defaults to FRESH VPS only (aborts before any mutation if
#    existing Xray or WARP is detected unless ALLOW_EXISTING=true is explicitly set).
# 2. Pinned, SHA256-verified Xray installer & Xray-core release version.
# 3. Strict 0600 permissions on config, backups, and node metadata at creation time.
# 4. Zero split-brain credentials: supports valid empty Reality shortId ("") and
#    derives delivered metadata strictly from the final active config.json.
# 5. Loud firewall enforcement (no silent || true swallowing UFW/iptables errors)
#    plus local listening-port check.
# 6. No raw secrets printed to stdout by default (handoff via 0600 file).
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
  PORT                 Listening TCP port for VLESS Reality (default: 24433)
  SNI                  Reality camouflage SNI (default: gateway.icloud.com)
  ALLOW_EXISTING=true  Permit running on a VPS that already has Xray/WARP
  REGENERATE=true      Rotate UUID, Reality keys, and shortId (requires ALLOW_EXISTING=true if existing)
  OUTPUT_FILE          Path for 0600 node metadata JSON (default: /root/claude-antiban-node.json)
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

# Pinned official XTLS/Xray-install commit & SHA256 checksum
XRAY_INSTALL_COMMIT="${XRAY_INSTALL_COMMIT:-9d3ad49a3294d4c1d042f1fb6a16360b4d1befd1}"
XRAY_INSTALL_SHA256="${XRAY_INSTALL_SHA256:-91fd40e9b6f222b5819f3ba91f0bfb4bb8c4d425a7c0ffe9d8b155d25ed79609}"
XRAY_INSTALL_URL="https://raw.githubusercontent.com/XTLS/Xray-install/${XRAY_INSTALL_COMMIT}/install-release.sh"
XRAY_VERSION="${XRAY_VERSION:-v26.11.9}"

# Color Codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

# Helper: derive PublicKey from PrivateKey across legacy & Xray v26+ formats
derive_public_key() {
    local priv="$1"
    local out
    out=$("$XRAY_BIN" x25519 -i "$priv" 2>/dev/null || true)
    echo "$out" | grep -iE "(public key|publickey|password)" | head -n 1 | awk -F': ' '{print $2}' | tr -d ' \r\n'
}

# Helper: atomic write with strict 0600 permissions before content is written
write_secret_file_0600() {
    local target="$1"
    local parent
    parent=$(dirname "$target")
    mkdir -p "$parent"
    local tmp="${target}.tmp.$$"
    (
        umask 077
        cat > "$tmp"
    )
    chmod 600 "$tmp"
    mv "$tmp" "$target"
    chmod 600 "$target"
}

# ------------------------------------------------------------------------------
# 0. Strict Preflight Checks (BEFORE ANY SYSTEM MUTATION!)
# ------------------------------------------------------------------------------
if [ "$SKIP_ROOT_CHECK" != "true" ] && [ "$(id -u)" -ne 0 ]; then
    log_error "This script must be run as root!"
    exit 1
fi

if [ "$SKIP_APT" != "true" ] && ! command -v apt-get >/dev/null 2>&1; then
    log_error "Unsupported OS: apt-get not found. Only Debian 11+ / Ubuntu 22.04+ are supported."
    exit 1
fi

# Detect existing Xray or WARP installation before touching anything
EXISTING_DETECTED=()
if [ -f "$EXISTING_CONFIG" ]; then
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
    log_error "如确认在维护窗口内覆盖更新，请显式设置 ALLOW_EXISTING=true 后重试。"
    log_error "如需同时轮换全部节点凭证，请设置 ALLOW_EXISTING=true REGENERATE=true。"
    log_error "====================================================================="
    exit 2
fi

# Validate port input if provided
if [ -n "$PORT_INPUT" ]; then
    if ! [[ "$PORT_INPUT" =~ ^[0-9]+$ ]] || [ "$PORT_INPUT" -lt 1 ] || [ "$PORT_INPUT" -gt 65535 ]; then
        log_error "Invalid PORT: ${PORT_INPUT} (must be 1..65535)"
        exit 1
    fi
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
# 2. Install Pinned, Checksum-Verified Xray-core
# ------------------------------------------------------------------------------
if [ "$SKIP_XRAY_INSTALL" != "true" ]; then
    log_info "Step 2: Downloading pinned Xray installer (commit ${XRAY_INSTALL_COMMIT:0:10}, Xray ${XRAY_VERSION})..."
    INSTALLER_TMP=$(mktemp /tmp/xray-install.XXXXXX.sh)
    trap 'rm -f "${INSTALLER_TMP:-}" "${TMP_CONFIG:-}"' EXIT

    curl -fsSL "$XRAY_INSTALL_URL" -o "$INSTALLER_TMP"

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

    bash "$INSTALLER_TMP" install -u root --version "$XRAY_VERSION"
    rm -f "$INSTALLER_TMP"
else
    log_info "Step 2: Skipping Xray binary installation (SKIP_XRAY_INSTALL=true)."
    trap 'rm -f "${TMP_CONFIG:-}"' EXIT
fi

if [ ! -x "$XRAY_BIN" ]; then
    log_error "Xray binary not found or not executable at ${XRAY_BIN}!"
    exit 1
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

if [ -f "$EXISTING_CONFIG" ]; then
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
            PUBLIC_KEY=$(derive_public_key "$PRIVATE_KEY")
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
    PRIVATE_KEY=$(echo "$X25519_OUTPUT" | grep -iE "(private key|privatekey)" | head -n 1 | awk -F': ' '{print $2}' | tr -d ' \r\n')
    PUBLIC_KEY=$(echo "$X25519_OUTPUT" | grep -iE "(public key|publickey|password)" | head -n 1 | awk -F': ' '{print $2}' | tr -d ' \r\n')

    if [ -z "$PRIVATE_KEY" ] || [ -z "$PUBLIC_KEY" ] || [ -z "$UUID" ] || [ -z "$SHORT_ID" ]; then
        log_error "Failed to generate valid Xray Reality keys! Output was:"
        echo "${X25519_OUTPUT:-[empty]}" >&2
        exit 1
    fi
fi

log_info "Reality credentials prepared (reused=${REUSED_CREDENTIALS})."

# ------------------------------------------------------------------------------
# 4. Kernel Tuning (with Rollback Backup)
# ------------------------------------------------------------------------------
SYSCTL_BACKUP=""
SYSCTL_MODIFIED=false

rollback_sysctl() {
    if [ "$SYSCTL_MODIFIED" = "true" ]; then
        if [ -n "$SYSCTL_BACKUP" ] && [ -f "$SYSCTL_BACKUP" ]; then
            cp "$SYSCTL_BACKUP" "$SYSCTL_FILE" || true
        else
            rm -f "$SYSCTL_FILE" || true
        fi
        sysctl --system >/dev/null 2>&1 || true
        log_warn "Rolled back sysctl configuration (${SYSCTL_FILE})."
    fi
}

if [ "$SKIP_SYSCTL" != "true" ]; then
    log_info "Step 4: Tuning Linux Kernel parameters (Anti-leak & Keepalive)..."
    if [ -f "$SYSCTL_FILE" ]; then
        SYSCTL_BACKUP="${SYSCTL_FILE}.bak.$(date +%s)"
        cp "$SYSCTL_FILE" "$SYSCTL_BACKUP"
    fi
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

SERVER_IP="${SERVER_IP_OVERRIDE:-$(curl -s -4 -m 5 https://api.ipify.org || curl -s -4 -m 5 https://ipinfo.io/ip || curl -s -4 -m 5 https://icanhazip.com || echo "YOUR_VPS_IP")}"

# ------------------------------------------------------------------------------
# 6. Write (0600), Validate, and Atomically Deploy Xray Configuration
# ------------------------------------------------------------------------------
log_info "Step 6: Generating and validating Xray server configuration..."

mkdir -p "$CONFIG_DIR"
TMP_CONFIG="${CONFIG_DIR}/config.tmp.$$.json"

if [ "$REUSED_CREDENTIALS" = "true" ] && [ -n "$EXISTING_CLIENTS" ] && [ "$EXISTING_CLIENTS" != "null" ]; then
    CLIENTS_JSON="$EXISTING_CLIENTS"
else
    CLIENTS_JSON=$(jq -nc --arg id "$UUID" '[{"id": $id, "flow": "xtls-rprx-vision"}]')
fi

if [ "$REUSED_CREDENTIALS" = "true" ] && [ -n "$EXISTING_SHORT_IDS" ] && [ "$EXISTING_SHORT_IDS" != "null" ]; then
    SHORT_IDS_JSON="$EXISTING_SHORT_IDS"
else
    SHORT_IDS_JSON=$(jq -nc --arg sid "$SHORT_ID" '[$sid]')
fi

EXTRA_INBOUNDS_SNIPPET=""
if [ -n "$EXTRA_INBOUNDS" ] && [ "$EXTRA_INBOUNDS" != "[]" ] && [ "$EXTRA_INBOUNDS" != "null" ]; then
    STRIPPED=$(echo "$EXTRA_INBOUNDS" | sed -e 's/^[[:space:]]*\[//' -e 's/\][[:space:]]*$//')
    if [ -n "$STRIPPED" ]; then
        EXTRA_INBOUNDS_SNIPPET=", ${STRIPPED}"
    fi
fi

# Create TMP_CONFIG strictly with 0600 permissions BEFORE writing privateKey
(
    umask 077
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
chmod 600 "$TMP_CONFIG"

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

# Backup existing configuration with strict 0600 permissions at creation time
BACKUP_PATH=""
if [ -f "$EXISTING_CONFIG" ]; then
    BACKUP_PATH="${CONFIG_DIR}/config.json.bak.$(date +%s)"
    install -m 600 "$EXISTING_CONFIG" "$BACKUP_PATH"
    log_info "Existing configuration backed up (0600) to ${BACKUP_PATH}"
fi

# Atomic replacement preserving 0600 permissions
mv "$TMP_CONFIG" "$EXISTING_CONFIG"
chmod 600 "$EXISTING_CONFIG"

# Restart Xray with Rollback Protection
log_info "Restarting Xray service..."
systemctl enable xray >/dev/null 2>&1 || true

RESTART_OK=true
if ! systemctl restart xray; then
    RESTART_OK=false
fi

sleep 2
if [ "$RESTART_OK" != "true" ] || ! systemctl is-active --quiet xray; then
    log_error "Xray service failed to start/restart after applying new configuration!"
    journalctl -u xray -n 25 --no-pager 2>/dev/null || true
    if [ -n "$BACKUP_PATH" ] && [ -f "$BACKUP_PATH" ]; then
        log_warn "Initiating automatic rollback to previous configuration: ${BACKUP_PATH}..."
        install -m 600 "$BACKUP_PATH" "$EXISTING_CONFIG"
        systemctl restart xray || true
    else
        rm -f "$EXISTING_CONFIG"
        rollback_sysctl
    fi
    exit 1
fi
log_info "Xray service active!"

# ------------------------------------------------------------------------------
# 7. Strict Firewall Enforcement & Local Port Binding Verification (NO || true!)
# ------------------------------------------------------------------------------
FIREWALL_STATUS="none_detected"
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    log_info "Active UFW detected; allowing TCP port ${PORT}..."
    if ! ufw allow "${PORT}/tcp"; then
        log_error "FAILED to allow port ${PORT}/tcp in UFW! Aborting instead of reporting false success."
        exit 1
    fi
    FIREWALL_STATUS="ufw_allowed"
    log_info "Confirmed: UFW allowed TCP port ${PORT}."
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    log_info "Active firewalld detected; allowing TCP port ${PORT}..."
    if ! firewall-cmd --permanent --add-port="${PORT}/tcp" || ! firewall-cmd --reload; then
        log_error "FAILED to allow port ${PORT}/tcp in firewalld!"
        exit 1
    fi
    FIREWALL_STATUS="firewalld_allowed"
    log_info "Confirmed: firewalld allowed TCP port ${PORT}."
elif command -v iptables >/dev/null 2>&1; then
    log_info "Ensuring iptables accepts TCP port ${PORT}..."
    if ! iptables -C INPUT -p tcp --dport "${PORT}" -j ACCEPT 2>/dev/null; then
        if ! iptables -I INPUT -p tcp --dport "${PORT}" -j ACCEPT; then
            log_error "FAILED to add iptables ACCEPT rule for TCP port ${PORT}!"
            exit 1
        fi
    fi
    FIREWALL_STATUS="iptables_allowed"
    log_info "Confirmed: iptables allows TCP port ${PORT}."
fi

if [ "$SKIP_LISTEN_CHECK" != "true" ]; then
    LISTEN_OK=false
    if command -v ss >/dev/null 2>&1 && ss -tln 2>/dev/null | grep -qE "[:.]${PORT}[[:space:]]"; then
        LISTEN_OK=true
    elif command -v netstat >/dev/null 2>&1 && netstat -tln 2>/dev/null | grep -qE "[:.]${PORT}[[:space:]]"; then
        LISTEN_OK=true
    fi
    if [ "$LISTEN_OK" != "true" ]; then
        log_error "Xray does not appear to be listening on TCP port ${PORT}!"
        exit 1
    fi
    log_info "Confirmed: Xray is actively listening on TCP port ${PORT}."
fi

# ------------------------------------------------------------------------------
# 8. Derive Delivered Metadata Strictly From Final Active config.json (0600 File)
# ------------------------------------------------------------------------------
FINAL_PORT=$(jq -r '.inbounds[0].port' "$EXISTING_CONFIG")
FINAL_UUID=$(jq -r '.inbounds[0].settings.clients[0].id' "$EXISTING_CONFIG")
FINAL_FLOW=$(jq -r '.inbounds[0].settings.clients[0].flow // "xtls-rprx-vision"' "$EXISTING_CONFIG")
FINAL_SNI=$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0]' "$EXISTING_CONFIG")
FINAL_PRIVATE_KEY=$(jq -r '.inbounds[0].streamSettings.realitySettings.privateKey' "$EXISTING_CONFIG")
FINAL_SHORT_ID=$(jq -r '.inbounds[0].streamSettings.realitySettings.shortIds[0]' "$EXISTING_CONFIG")
FINAL_PUBLIC_KEY=$(derive_public_key "$FINAL_PRIVATE_KEY")

if [ -z "$FINAL_PORT" ] || [ -z "$FINAL_UUID" ] || [ -z "$FINAL_SNI" ] || [ -z "$FINAL_PUBLIC_KEY" ]; then
    log_error "Internal consistency check failed when reading final config ${EXISTING_CONFIG}!"
    exit 1
fi

METADATA_JSON=$(jq -n \
    --arg server_ip "$SERVER_IP" \
    --argjson port "$FINAL_PORT" \
    --arg uuid "$FINAL_UUID" \
    --arg flow "$FINAL_FLOW" \
    --arg security "reality" \
    --arg sni "$FINAL_SNI" \
    --arg public_key "$FINAL_PUBLIC_KEY" \
    --arg short_id "$FINAL_SHORT_ID" \
    --arg fingerprint "chrome" \
    --argjson warp_port "$WARP_PORT" \
    --argjson warp_ready "$WARP_READY" \
    --arg google_outbound "$GOOGLE_OUTBOUND" \
    --arg firewall_status "$FIREWALL_STATUS" \
    '{
      server_ip: $server_ip,
      port: $port,
      uuid: $uuid,
      flow: $flow,
      security: $security,
      sni: $sni,
      public_key: $public_key,
      short_id: $short_id,
      fingerprint: $fingerprint,
      warp_port: $warp_port,
      warp_ready: $warp_ready,
      google_outbound: $google_outbound,
      firewall_status: $firewall_status
    }')

printf '%s\n' "$METADATA_JSON" | write_secret_file_0600 "$OUTPUT_FILE"

echo ""
echo "==================== VPS SETUP COMPLETE ===================="
echo "Server IP        : ${SERVER_IP}"
echo "Listening Port   : ${FINAL_PORT}/tcp"
echo "SNI              : ${FINAL_SNI}"
echo "WARP Dual-Track  : ${WARP_READY} (Google outbound: ${GOOGLE_OUTBOUND})"
echo "VPS Firewall     : ${FIREWALL_STATUS}"
echo "Metadata File    : ${OUTPUT_FILE} (permissions: 0600)"
echo ""
echo "[NEXT STEP] Copy ${OUTPUT_FILE} securely to your local machine via scp (do NOT paste secrets into chat),"
echo "            then verify inbound TCP port reachability + proxy egress from your local machine."
echo "[NOTE]      Cloud provider security groups (AWS/GCP/Aliyun/etc.) are separate from VPS ufw/iptables:"
echo "            ensure TCP port ${FINAL_PORT} is open in your cloud console if client reachability fails."

if [ "$PRINT_JSON" = "true" ]; then
    echo ""
    echo "###JSON_OUTPUT_START###"
    printf '%s\n' "$METADATA_JSON"
    echo "###JSON_OUTPUT_END###"
fi
echo "============================================================"
