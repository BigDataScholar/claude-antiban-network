#!/usr/bin/env bash
# ==============================================================================
# Claude Anti-Ban Network Setup Script for Linux VPS (Debian / Ubuntu)
# Features:
# 1. Official Xray-core with VLESS Reality (XTLS-rprx-vision + Chrome Fingerprint)
# 2. Cloudflare WARP Socks5 Local Proxy for Google / Gemini bypass
# 3. Dual-track Xray routing: Claude/OpenAI -> Native Residential IP; Google -> WARP
# 4. Kernel tuning: TCP Keepalive (30s) + Disable IPv6 leak prevention
# 5. Non-interactive or interactive execution with clean JSON output
# ==============================================================================

set -euo pipefail

# User-supplied or environment parameters (empty if not specified)
PORT_INPUT="${PORT:-}"
SNI_INPUT="${SNI:-}"
WARP_PORT="40000"
REGENERATE="${REGENERATE:-false}"

# Color Codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

if [ "$(id -u)" -ne 0 ]; then
    log_error "This script must be run as root!"
    exit 1
fi

log_info "Step 1: Installing essential dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
# NOTE: Do NOT remove ufw (no ufw- syntax) to respect user's firewall configuration
apt-get install -y -qq curl wget jq openssl gnupg lsb-release iptables procps || true

# ------------------------------------------------------------------------------
# 2. Install Official Xray-core
# ------------------------------------------------------------------------------
log_info "Step 2: Installing / Updating official Xray-core..."
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u root

if [ ! -f /usr/local/bin/xray ]; then
    log_error "Xray binary not found at /usr/local/bin/xray! Installation failed."
    exit 1
fi

# ------------------------------------------------------------------------------
# 3. Generate or Reuse Reality Keys and Configuration Parameters
# ------------------------------------------------------------------------------
log_info "Step 3: Configuring VLESS Reality credentials and ports..."

EXISTING_CONFIG="/usr/local/etc/xray/config.json"
UUID=""
PRIVATE_KEY=""
PUBLIC_KEY=""
SHORT_ID=""
PORT=""
SNI=""
EXISTING_CLIENTS=""
EXISTING_SHORT_IDS=""
EXTRA_INBOUNDS=""

# Check if valid existing credentials and custom parameters can be reused
if [ "$REGENERATE" != "true" ] && [ -f "$EXISTING_CONFIG" ]; then
    log_info "Found existing Xray configuration. Checking for reusable parameters..."
    EXISTING_PORT=$(jq -r '.inbounds[0].port // empty' "$EXISTING_CONFIG" 2>/dev/null || true)
    EXISTING_SNI=$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0] // empty' "$EXISTING_CONFIG" 2>/dev/null || true)
    EXISTING_CLIENTS=$(jq -c '.inbounds[0].settings.clients // empty' "$EXISTING_CONFIG" 2>/dev/null || true)
    EXISTING_SHORT_IDS=$(jq -c '.inbounds[0].streamSettings.realitySettings.shortIds // empty' "$EXISTING_CONFIG" 2>/dev/null || true)
    EXTRA_INBOUNDS=$(jq -c '.inbounds[1:] // empty' "$EXISTING_CONFIG" 2>/dev/null || true)
    UUID=$(jq -r '.inbounds[0].settings.clients[0].id // empty' "$EXISTING_CONFIG" 2>/dev/null || true)
    PRIVATE_KEY=$(jq -r '.inbounds[0].streamSettings.realitySettings.privateKey // empty' "$EXISTING_CONFIG" 2>/dev/null || true)
    SHORT_ID=$(jq -r '.inbounds[0].streamSettings.realitySettings.shortIds[0] // empty' "$EXISTING_CONFIG" 2>/dev/null || true)
    
    # Preserve existing port if user didn't explicitly override it
    if [ -n "$EXISTING_PORT" ] && [ -z "$PORT_INPUT" ]; then
        PORT="$EXISTING_PORT"
        log_info "Preserving existing listening port: ${PORT}"
    fi
    # Preserve existing SNI if user didn't explicitly override it
    if [ -n "$EXISTING_SNI" ] && [ -z "$SNI_INPUT" ]; then
        SNI="$EXISTING_SNI"
        log_info "Preserving existing SNI: ${SNI}"
    fi

    if [ -n "$PRIVATE_KEY" ]; then
        # Derive Public Key from Private Key using Xray
        # In modern Xray versions, xray x25519 -i <privkey> outputs Password (PublicKey): <pubkey>
        DERIVED_OUT=$(/usr/local/bin/xray x25519 -i "$PRIVATE_KEY" 2>/dev/null || true)
        PUBLIC_KEY=$(echo "$DERIVED_OUT" | grep -iE "(public key|publickey|password)" | awk -F': ' '{print $2}' | tr -d ' \r\n' || true)
    fi
fi

# Fallback to defaults or user inputs if not preserved
PORT="${PORT:-${PORT_INPUT:-24433}}"
SNI="${SNI:-${SNI_INPUT:-gateway.icloud.com}}"

# Generate fresh credentials if not found or regeneration requested
if [ -z "$UUID" ] || [ -z "$PRIVATE_KEY" ] || [ -z "$PUBLIC_KEY" ] || [ -z "$SHORT_ID" ]; then
    log_info "Generating new Xray UUID and X25519 Reality keypair..."
    UUID=$(/usr/local/bin/xray uuid)
    SHORT_ID=$(openssl rand -hex 8)
    
    X25519_OUTPUT=$(/usr/local/bin/xray x25519)
    
    # Robust parsing compatible with both legacy and v26+ Xray output formats:
    # Legacy:
    #   Private key: <key>
    #   Public key: <key>
    # Modern (v26.10+):
    #   PrivateKey: <key>
    #   Password (PublicKey): <key>
    PRIVATE_KEY=$(echo "$X25519_OUTPUT" | grep -iE "(private key|privatekey)" | head -n 1 | awk -F': ' '{print $2}' | tr -d ' \r\n')
    PUBLIC_KEY=$(echo "$X25519_OUTPUT" | grep -iE "(public key|publickey|password)" | head -n 1 | awk -F': ' '{print $2}' | tr -d ' \r\n')
fi

# Validation Gate: Ensure keys are valid non-empty strings
if [ -z "$PRIVATE_KEY" ] || [ -z "$PUBLIC_KEY" ] || [ -z "$UUID" ] || [ -z "$SHORT_ID" ]; then
    log_error "Failed to obtain valid Xray Reality keys! Output was:"
    echo "${X25519_OUTPUT:-[empty]}"
    exit 1
fi

log_info "Reality Keys verified successfully."

# ------------------------------------------------------------------------------
# 4. Kernel Tuning: Disable IPv6 & Enable TCP Keepalive
# ------------------------------------------------------------------------------
log_info "Step 4: Tuning Linux Kernel parameters (Anti-leak & Keepalive)..."

cat > /etc/sysctl.d/99-claude-antiban.conf << 'EOF'
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

sysctl --system >/dev/null 2>&1 || true

# ------------------------------------------------------------------------------
# 5. Install & Configure Cloudflare WARP (in Proxy Mode)
# ------------------------------------------------------------------------------
log_info "Step 5: Setting up Cloudflare WARP for Gemini routing..."

WARP_READY=false
if ! command -v warp-cli &> /dev/null; then
    curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg 2>/dev/null || true
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/cloudflare-client.list >/dev/null
    apt-get update -qq || true
    apt-get install -y -qq cloudflare-warp || log_warn "Failed to install cloudflare-warp package via apt."
fi

if command -v warp-cli &> /dev/null; then
    systemctl enable --now warp-svc >/dev/null 2>&1 || true
    sleep 2

    # Register and set to proxy mode
    warp-cli --accept-tos registration new >/dev/null 2>&1 || warp-cli --accept-tos register >/dev/null 2>&1 || true
    warp-cli --accept-tos mode proxy >/dev/null 2>&1 || true
    warp-cli --accept-tos proxy port ${WARP_PORT} >/dev/null 2>&1 || true
    warp-cli --accept-tos connect >/dev/null 2>&1 || true

    # Test WARP local proxy connectivity with retry
    for i in {1..5}; do
        if curl -s --socks5 "127.0.0.1:${WARP_PORT}" -m 3 https://cloudflare.com/cdn-cgi/trace 2>/dev/null | grep -qE "warp=(on|plus)"; then
            WARP_READY=true
            log_info "Cloudflare WARP proxy verified active on 127.0.0.1:${WARP_PORT}"
            break
        fi
        sleep 1
    done
fi

GOOGLE_OUTBOUND="warp"
if [ "$WARP_READY" != "true" ]; then
    GOOGLE_OUTBOUND="direct"
    log_warn "====================================================================="
    log_warn "[WARNING] Cloudflare WARP proxy on 127.0.0.1:${WARP_PORT} is not ready or failed to install."
    log_warn "To prevent blackholing traffic, Google/Gemini routing has fallen back to DIRECT (Native IP)."
    log_warn "Claude and OpenAI will work normally on Native IP. Gemini may face ZZ geo-block until WARP is active."
    log_warn "====================================================================="
else
    log_info "Cloudflare WARP proxy verified active on 127.0.0.1:${WARP_PORT} (Dual-track routing enabled)."
fi

# Detect Public IPv4
SERVER_IP=$(curl -s -4 -m 5 https://api.ipify.org || curl -s -4 -m 5 https://ipinfo.io/ip || curl -s -4 -m 5 https://icanhazip.com || echo "YOUR_VPS_IP")

# ------------------------------------------------------------------------------
# 6. Write, Validate and Deploy Xray Configuration
# ------------------------------------------------------------------------------
log_info "Step 6: Generating and validating Xray server configuration..."

mkdir -p /usr/local/etc/xray/
TMP_CONFIG="/usr/local/etc/xray/config.tmp.$$.json"

if [ -n "$EXISTING_CLIENTS" ] && [ "$EXISTING_CLIENTS" != "null" ]; then
    CLIENTS_JSON="$EXISTING_CLIENTS"
else
    CLIENTS_JSON="[{\"id\": \"${UUID}\", \"flow\": \"xtls-rprx-vision\"}]"
fi

if [ -n "$EXISTING_SHORT_IDS" ] && [ "$EXISTING_SHORT_IDS" != "null" ]; then
    SHORT_IDS_JSON="$EXISTING_SHORT_IDS"
else
    SHORT_IDS_JSON="[\"${SHORT_ID}\"]"
fi

EXTRA_INBOUNDS_SNIPPET=""
if [ -n "$EXTRA_INBOUNDS" ] && [ "$EXTRA_INBOUNDS" != "[]" ] && [ "$EXTRA_INBOUNDS" != "null" ]; then
    STRIPPED=$(echo "$EXTRA_INBOUNDS" | sed -e 's/^[[:space:]]*\[//' -e 's/\][[:space:]]*$//')
    if [ -n "$STRIPPED" ]; then
        EXTRA_INBOUNDS_SNIPPET=", ${STRIPPED}"
    fi
fi

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
          "domain:claude.ai",
          "domain:anthropic.com",
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
          "domain:generativelanguage.googleapis.com"
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

# Configuration Pre-flight Validation
log_info "Testing generated configuration syntax with Xray..."
if ! /usr/local/bin/xray run -test -config "$TMP_CONFIG" >/dev/null 2>&1 && ! /usr/local/bin/xray -test -config "$TMP_CONFIG" >/dev/null 2>&1; then
    log_error "Configuration syntax validation FAILED! Aborting update to protect running service."
    /usr/local/bin/xray run -test -config "$TMP_CONFIG" || /usr/local/bin/xray -test -config "$TMP_CONFIG" || true
    rm -f "$TMP_CONFIG"
    exit 1
fi
log_info "Configuration validation passed."

# Backup existing configuration
BACKUP_PATH=""
if [ -f "$EXISTING_CONFIG" ]; then
    BACKUP_PATH="/usr/local/etc/xray/config.json.bak.$(date +%s)"
    cp "$EXISTING_CONFIG" "$BACKUP_PATH"
    log_info "Existing configuration backed up to ${BACKUP_PATH}"
fi

# Atomic replacement
mv "$TMP_CONFIG" "$EXISTING_CONFIG"

# Restart Xray with Rollback Protection
log_info "Restarting Xray service..."
systemctl enable xray >/dev/null 2>&1 || true

RESTART_OK=true
if ! systemctl restart xray; then
    RESTART_OK=false
fi

# Verify Xray is running
sleep 2
if [ "$RESTART_OK" != "true" ] || ! systemctl is-active --quiet xray; then
    log_error "Xray service failed to start/restart after applying new configuration!"
    journalctl -u xray -n 25 --no-pager || true
    if [ -n "$BACKUP_PATH" ] && [ -f "$BACKUP_PATH" ]; then
        log_warn "Initiating automatic rollback to previous configuration: ${BACKUP_PATH}..."
        cp "$BACKUP_PATH" "$EXISTING_CONFIG"
        systemctl restart xray || true
        if systemctl is-active --quiet xray; then
            log_info "Rollback SUCCESSFUL! Previous running service has been restored."
        else
            log_error "Rollback failed. Please check Xray systemd logs manually."
        fi
    fi
    exit 1
fi
log_info "Xray service successfully started and active!"

# Firewall rules: support both iptables and ufw safely
if command -v ufw &> /dev/null && ufw status | grep -q "Status: active"; then
    ufw allow "${PORT}/tcp" >/dev/null 2>&1 || true
    log_info "Allowed port ${PORT}/tcp in UFW firewall."
elif command -v iptables &> /dev/null; then
    iptables -I INPUT -p tcp --dport "${PORT}" -j ACCEPT || true
fi

# ------------------------------------------------------------------------------
# 7. Output Result Metadata in JSON
# ------------------------------------------------------------------------------
echo ""
echo "==================== SETUP COMPLETE ===================="
echo "Below is the machine-readable node configuration JSON:"
echo ""

cat << JSON_OUTPUT
###JSON_OUTPUT_START###
{
  "server_ip": "${SERVER_IP}",
  "port": ${PORT},
  "uuid": "${UUID}",
  "flow": "xtls-rprx-vision",
  "security": "reality",
  "sni": "${SNI}",
  "public_key": "${PUBLIC_KEY}",
  "short_id": "${SHORT_ID}",
  "fingerprint": "chrome",
  "warp_port": ${WARP_PORT},
  "warp_ready": ${WARP_READY},
  "google_outbound": "${GOOGLE_OUTBOUND}"
}
###JSON_OUTPUT_END###
JSON_OUTPUT

echo ""
echo "Share this JSON with the Agent or your client config generator."
echo "========================================================"
