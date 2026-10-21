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

# Default Parameters
PORT="${PORT:-24433}"
SNI="${SNI:-gateway.icloud.com}"
WARP_PORT="40000"

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

log_info "Step 1: Installing dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl wget jq openssl gnupg lsb-release iptables procps ufw- || true

# ------------------------------------------------------------------------------
# 2. Kernel Tuning: Disable IPv6 & Enable TCP Keepalive
# ------------------------------------------------------------------------------
log_info "Step 2: Tuning Linux Kernel parameters (Anti-leak & Keepalive)..."

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
# 3. Install Official Xray-core
# ------------------------------------------------------------------------------
log_info "Step 3: Installing official Xray-core..."
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u root

# ------------------------------------------------------------------------------
# 4. Install & Configure Cloudflare WARP (in Proxy Mode)
# ------------------------------------------------------------------------------
log_info "Step 4: Setting up Cloudflare WARP for Gemini routing..."

if ! command -v warp-cli &> /dev/null; then
    curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/cloudflare-client.list
    apt-get update -qq
    apt-get install -y -qq cloudflare-warp
fi

# Ensure warp-svc is running
systemctl enable --now warp-svc >/dev/null 2>&1 || true
sleep 3

# Register and set to proxy mode
warp-cli --accept-tos registration new >/dev/null 2>&1 || warp-cli --accept-tos register >/dev/null 2>&1 || true
warp-cli --accept-tos mode proxy >/dev/null 2>&1 || true
warp-cli --accept-tos proxy port ${WARP_PORT} >/dev/null 2>&1 || true
warp-cli --accept-tos connect >/dev/null 2>&1 || true

# Test WARP local proxy
sleep 2
WARP_TEST=$(curl -s --socks5 "127.0.0.1:${WARP_PORT}" https://cloudflare.com/cdn-cgi/trace 2>/dev/null | grep -E "warp=on|warp=plus" || true)
if [ -n "$WARP_TEST" ]; then
    log_info "Cloudflare WARP proxy active on 127.0.0.1:${WARP_PORT}"
else
    log_warn "WARP is connecting. It will auto-reconnect if needed."
fi

# ------------------------------------------------------------------------------
# 5. Generate Reality Keys and Credentials
# ------------------------------------------------------------------------------
log_info "Step 5: Generating VLESS Reality credentials..."

UUID=$(/usr/local/bin/xray uuid)
X25519_OUTPUT=$(/usr/local/bin/xray x25519)
PRIVATE_KEY=$(echo "$X25519_OUTPUT" | grep -i "private key" | awk '{print $3}')
PUBLIC_KEY=$(echo "$X25519_OUTPUT" | grep -i "public key" | awk '{print $3}')
SHORT_ID=$(openssl rand -hex 8)

# Detect Public IPv4
SERVER_IP=$(curl -s -4 https://api.ipify.org || curl -s -4 https://ipinfo.io/ip || curl -s -4 https://icanhazip.com || echo "YOUR_VPS_IP")

# ------------------------------------------------------------------------------
# 6. Write Xray Configuration (/usr/local/etc/xray/config.json)
# ------------------------------------------------------------------------------
log_info "Step 6: Writing Xray server configuration with dual-track routing..."

mkdir -p /usr/local/etc/xray/

cat > /usr/local/etc/xray/config.json << EOF
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
        "clients": [
          {
            "id": "${UUID}",
            "flow": "xtls-rprx-vision"
          }
        ],
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
          "shortIds": [
            "${SHORT_ID}"
          ]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      }
    }
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
        "outboundTag": "warp"
      },
      {
        "type": "field",
        "ip": [
          "geoip:google"
        ],
        "outboundTag": "warp"
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

# Restart Xray
systemctl enable xray >/dev/null 2>&1 || true
systemctl restart xray

# Verify Xray is running
sleep 2
if systemctl is-active --quiet xray; then
    log_info "Xray service successfully started!"
else
    log_error "Xray failed to start! Checking logs..."
    journalctl -u xray -n 20 --no-pager
    exit 1
fi

# Ensure port is open in iptables
if command -v iptables &> /dev/null; then
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
  "warp_port": ${WARP_PORT}
}
###JSON_OUTPUT_END###
JSON_OUTPUT

echo ""
echo "Share this JSON with the Agent or your client config generator."
echo "========================================================"
