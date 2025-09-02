#!/usr/bin/env bash
# install-v2ray-webhook.sh (revised)
# Usage example:
# sudo ./install-v2ray-webhook.sh \
#   --webhook-url "https://n8n.example/webhook/receive" \
#   --webhook-user "botuser" --webhook-pass "botpass" \
#   --domain "s1.oiix.ir" --cf-zone-id "ZONEID" --cf-api-token "CFTOKEN" \
#   --cf-proxied "false" --port 16823
set -euo pipefail

# -------- defaults ----------
WEBHOOK_URL=""
WEBHOOK_USER=""
WEBHOOK_PASS=""
WEBHOOK_SECRET=""    # optional header token legacy
DOMAIN=""
CF_ZONE_ID=""
CF_API_TOKEN=""
CF_PROXIED="false"
PORT="16823"
RUN_ID=""
MODE="auto"   # auto | simple | stealth
DEPS="curl wget unzip ca-certificates python3 jq openssl socat"
ACME_SH="/root/.acme.sh/acme.sh"

# -------- parse args ----------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --webhook-url) WEBHOOK_URL="$2"; shift 2;;
    --webhook-user) WEBHOOK_USER="$2"; shift 2;;
    --webhook-pass) WEBHOOK_PASS="$2"; shift 2;;
    --webhook-secret) WEBHOOK_SECRET="$2"; shift 2;;
    --domain) DOMAIN="$2"; shift 2;;
    --cf-zone-id) CF_ZONE_ID="$2"; shift 2;;
    --cf-api-token) CF_API_TOKEN="$2"; shift 2;;
    --cf-proxied) CF_PROXIED="$2"; shift 2;;
    --port) PORT="$2"; shift 2;;
    --run-id) RUN_ID="$2"; shift 2;;
    --mode) MODE="$2"; shift 2;; # auto/simple/stealth
    -h|--help) echo "Usage: $0 --webhook-url <url> [--webhook-user user --webhook-pass pass] [--domain ...]"; exit 0;;
    *) echo "Unknown arg: $1"; exit 2;;
  esac
done

if [ -z "$WEBHOOK_URL" ]; then
  echo "ERROR: --webhook-url is required"; exit 1
fi
if [ "$EUID" -ne 0 ]; then echo "ERROR: run as root"; exit 1; fi
if [ -z "$RUN_ID" ]; then RUN_ID="$(date +%s)-$RANDOM"; fi
HOSTNAME="$(hostname -f 2>/dev/null || hostname)"

# -------- helper: send log to webhook ----------
send_log(){
  local STATUS="$1"; local STEP="$2"; local MESSAGE="$3"
  local TS="$(date -u +%FT%TZ)"
  PAYLOAD="$(python3 - <<PY
import json,sys
print(json.dumps({
  "run_id":"$RUN_ID",
  "host":"$HOSTNAME",
  "status":"$STATUS",
  "step":"$STEP",
  "message":"$MESSAGE",
  "timestamp":"$TS",
  "port":"$PORT",
  "domain":"$DOMAIN"
}))
PY
)"
  # choose curl auth
  if [ -n "$WEBHOOK_USER" ] && [ -n "$WEBHOOK_PASS" ]; then
    curl -sS -u "$WEBHOOK_USER:$WEBHOOK_PASS" -X POST "$WEBHOOK_URL" -H "Content-Type: application/json" -d "$PAYLOAD" || echo "WARN: webhook POST failed"
  elif [ -n "$WEBHOOK_SECRET" ]; then
    curl -sS -X POST "$WEBHOOK_URL" -H "Content-Type: application/json" -H "X-Setup-Token: $WEBHOOK_SECRET" -d "$PAYLOAD" || echo "WARN: webhook POST failed"
  else
    curl -sS -X POST "$WEBHOOK_URL" -H "Content-Type: application/json" -d "$PAYLOAD" || echo "WARN: webhook POST failed"
  fi
  echo "[$TS] [$STATUS] step=$STEP: $MESSAGE"
}

# error trap to report failure
on_error(){
  local rc=$?
  send_log "error" "fatal" "Script exited with code $rc"
  exit $rc
}
trap on_error ERR

send_log "starting" "0" "Setup started (run_id=$RUN_ID)"

# ---------- configure IP forwarding and routing ----------
send_log "step" "0.5" "Configuring IP forwarding and routing for VPN traffic"
# Enable IP forwarding
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
echo 'net.ipv6.conf.all.forwarding=1' >> /etc/sysctl.conf
sysctl -p

# Clear existing rules
iptables -F
iptables -t nat -F
iptables -X 2>/dev/null || true

# Configure NAT and forwarding rules
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -o ens3 -j MASQUERADE  # common interface name
iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -j ACCEPT
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport ${PORT} -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT

# Make iptables rules persistent
if command -v iptables-save >/dev/null 2>&1; then
  iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
fi

send_log "step" "0.5" "IP forwarding and NAT configured"

# ---------- install deps ----------
send_log "step" "1" "Updating packages and installing prerequisites"
apt-get update -y
apt-get install -y $DEPS || { send_log "error" "1" "Failed to install packages"; exit 1; }

# ---------- install v2ray using fhs-install (official) ----------
send_log "step" "2" "Installing v2ray (fhs-install-v2ray)"
bash <(curl -fsSL https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh) || { send_log "error" "2" "v2ray install failed"; exit 1; }

# ---------- create uuid ----------
UUID="$(cat /proc/sys/kernel/random/uuid)"
send_log "step" "3" "Generated UUID"

# ---------- obtain cert if domain+CF provided and mode requires stealth ----------
CERT_KEY_PATH=""
CERT_FULLCHAIN_PATH=""
if [ "$MODE" = "auto" ] || [ "$MODE" = "stealth" ]; then
  if [ -n "$DOMAIN" ] && [ -n "$CF_API_TOKEN" ]; then
    send_log "step" "4" "Attempting to obtain TLS cert with acme.sh using Cloudflare DNS"
    # install acme.sh if missing
    if [ ! -x "$ACME_SH" ]; then
      curl -sSfL https://get.acme.sh | sh || { send_log "error" "4" "acme.sh install failed"; }
    fi
    export CF_Token="$CF_API_TOKEN"
    export CF_Zone="$CF_ZONE_ID"
    # issue cert (dns)
    /root/.acme.sh/acme.sh --issue --dns dns_cf -d "$DOMAIN" --yes-I-know-dns-manual-mode || {
      # try with default installation path
      /root/.acme.sh/acme.sh --issue --dns dns_cf -d "$DOMAIN" || send_log "step" "4" "acme.sh issue may have failed; continuing in non-TLS mode"
    }
    # install cert to /etc/ssl/v2ray-<runid> if exists
    if /root/.acme.sh/acme.sh --list | grep -q "$DOMAIN"; then
      mkdir -p /etc/ssl/v2ray-$RUN_ID
      /root/.acme.sh/acme.sh --installcert -d "$DOMAIN" \
        --fullchain-file /etc/ssl/v2ray-$RUN_ID/fullchain.pem \
        --key-file /etc/ssl/v2ray-$RUN_ID/key.pem || send_log "step" "4" "acme.sh installcert failed"
      CERT_FULLCHAIN_PATH="/etc/ssl/v2ray-$RUN_ID/fullchain.pem"
      CERT_KEY_PATH="/etc/ssl/v2ray-$RUN_ID/key.pem"
      send_log "step" "4" "Certificate installed: $CERT_FULLCHAIN_PATH"
    else
      send_log "step" "4" "Certificate not issued; will fall back to non-TLS config"
      CERT_FULLCHAIN_PATH=""; CERT_KEY_PATH=""
    fi
  else
    send_log "step" "4" "Skipping cert issuance (DOMAIN or CF_API_TOKEN missing)"
  fi
fi

# ---------- write v2ray config ----------
CONFIG_PATH="/usr/local/etc/v2ray/config.json"
send_log "step" "5" "Writing v2ray config to $CONFIG_PATH"

# Create log directory
mkdir -p /var/log/v2ray
chown nobody:nogroup /var/log/v2ray 2>/dev/null || true

# Backup existing config if exists
if [ -f "$CONFIG_PATH" ]; then
  cp "$CONFIG_PATH" "${CONFIG_PATH}.backup.$(date +%s)" || true
fi

# Create config directory if not exists
mkdir -p "$(dirname "$CONFIG_PATH")"

if [ -n "$CERT_FULLCHAIN_PATH" ] && [ -n "$CERT_KEY_PATH" ] && [ -f "$CERT_FULLCHAIN_PATH" ] && [ -f "$CERT_KEY_PATH" ]; then
  # stealth: vless over websocket + tls (server uses provided cert)
  cat > "$CONFIG_PATH" <<EOF
{
  "log": {"access": "/var/log/v2ray/access.log","error": "/var/log/v2ray/error.log","loglevel": "warning"},
  "inbounds": [{
    "port": ${PORT},
    "protocol": "vless",
    "settings": {
      "clients": [{"id":"${UUID}","level":0,"email":"mehranmarandi90@gmail.com"}],
      "decryption":"none"
    },
    "streamSettings": {
      "network": "ws",
      "security": "tls",
      "tlsSettings": {
        "certificates": [{"certificateFile":"${CERT_FULLCHAIN_PATH}","keyFile":"${CERT_KEY_PATH}"}]
      },
      "wsSettings": { "path": "/" }
    }
  }],
  "outbounds": [{"protocol":"freedom","settings":{},"tag":"direct"}],
  "routing": {
    "rules": [{"type": "field","outboundTag": "direct","network": "tcp,udp"}]
  }
}
EOF
  USED_MODE="stealth (vless+ws+tls)"
  CONNECTION_TYPE="vless"
  SECURITY="tls"
  NETWORK="ws"
  PATH="/"
else
  # simple: vless tcp no-tls (fallback)
  cat > "$CONFIG_PATH" <<EOF
{
  "log": {"access": "/var/log/v2ray/access.log","error": "/var/log/v2ray/error.log","loglevel": "warning"},
  "inbounds": [{
    "port": ${PORT},
    "protocol": "vless",
    "settings": {
      "clients": [{"id":"${UUID}","level":0,"email":"mehranmarandi90@gmail.com"}],
      "decryption":"none"
    },
    "streamSettings": {
      "network": "tcp",
      "security": "none"
    }
  }],
  "outbounds": [{"protocol":"freedom","settings":{},"tag":"direct"}],
  "routing": {
    "rules": [{"type": "field","outboundTag": "direct","network": "tcp,udp"}]
  }
}
EOF
  USED_MODE="simple (vless+tcp+none)"
  CONNECTION_TYPE="vless"
  SECURITY="none"
  NETWORK="tcp"
  PATH=""
fi

# Validate config file was written
if [ ! -f "$CONFIG_PATH" ]; then
  send_log "error" "5" "Config file was not created at $CONFIG_PATH"
  exit 1
fi

send_log "step" "6" "Config written (mode: $USED_MODE)"

# ---------- enable & start service ----------
send_log "step" "7" "Enabling and starting v2ray service"

# Check if v2ray binary exists
if [ ! -f "/usr/local/bin/v2ray" ]; then
  send_log "error" "7" "v2ray binary not found at /usr/local/bin/v2ray"
  exit 1
fi

# Reload systemd and enable service
systemctl daemon-reload || { send_log "error" "7" "Failed to reload systemd daemon"; exit 1; }
systemctl enable v2ray || { send_log "error" "7" "Failed to enable v2ray service"; exit 1; }

# Start service
systemctl start v2ray || { 
  send_log "error" "7" "Failed to start v2ray service"
  # Show service status for debugging
  systemctl status v2ray || true
  journalctl -u v2ray --no-pager -n 20 || true
  exit 1
}

sleep 5

# Check service status
if ! systemctl is-active --quiet v2ray; then
  send_log "error" "7" "v2ray service is not running after start attempt"
  systemctl status v2ray || true
  journalctl -u v2ray --no-pager -n 20 || true
  exit 1
fi

# verify listening
RETRIES=0
while [ $RETRIES -lt 10 ]; do
  if ss -ltnp 2>/dev/null | grep -q ":${PORT}[[:space:]]" || netstat -ltn 2>/dev/null | grep -q ":${PORT}[[:space:]]"; then
    send_log "step" "8" "v2ray is listening on port ${PORT}"
    break
  else
    RETRIES=$((RETRIES + 1))
    if [ $RETRIES -eq 10 ]; then
      send_log "error" "8" "Service not listening on port ${PORT} after 10 attempts"
      # Debug information
      ss -ltnp 2>/dev/null || netstat -ltn 2>/dev/null || true
      systemctl status v2ray || true
      exit 1
    fi
    sleep 2
  fi
done

# ---------- firewall: try ufw or iptables fallback ----------
send_log "step" "9" "Configuring firewall (allow port ${PORT})"
if command -v ufw >/dev/null 2>&1; then
  ufw allow "${PORT}/tcp" || send_log "step" "9" "ufw allow failed (maybe ufw inactive)"
  ufw allow ssh || true
else
  # add a basic iptables accept rule (non-persistent)
  iptables -I INPUT -p tcp --dport "$PORT" -j ACCEPT || send_log "step" "9" "iptables rule add failed"
fi

# ---------- detect public IP ----------
send_log "step" "10" "Detecting public IP"
MYIP=""
IP_SERVICES=("https://ipv4.icanhazip.com" "https://ifconfig.me" "https://api.ipify.org" "https://checkip.amazonaws.com")

for service in "${IP_SERVICES[@]}"; do
  MYIP="$(curl -s --max-time 10 "$service" | tr -d '\n\r' || true)"
  if [[ "$MYIP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    send_log "step" "10" "Public IP detected: ${MYIP}"
    break
  fi
done

if [ -z "$MYIP" ]; then
  send_log "error" "10" "Failed to detect public IP"
  exit 1
fi

# ---------- update Cloudflare DNS if requested ----------
if [ -n "$DOMAIN" ] && [ -n "$CF_ZONE_ID" ] && [ -n "$CF_API_TOKEN" ]; then
  send_log "step" "11" "Updating Cloudflare DNS for ${DOMAIN} (proxied=${CF_PROXIED})"
  GET_REC="$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records?name=${DOMAIN}" \
    -H "Authorization: Bearer ${CF_API_TOKEN}" -H "Content-Type: application/json")"
  RECORD_ID="$(echo "$GET_REC" | jq -r '.result[0].id // empty')"
  if [ -n "$RECORD_ID" ]; then
    curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records/${RECORD_ID}" \
      -H "Authorization: Bearer ${CF_API_TOKEN}" -H "Content-Type: application/json" \
      --data "{\"type\":\"A\",\"name\":\"${DOMAIN}\",\"content\":\"${MYIP}\",\"ttl\":120,\"proxied\":${CF_PROXIED}}" >/dev/null || send_log "error" "11" "Cloudflare update PUT failed"
    send_log "step" "11" "Updated existing record id=${RECORD_ID}"
  else
    curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records" \
      -H "Authorization: Bearer ${CF_API_TOKEN}" -H "Content-Type: application/json" \
      --data "{\"type\":\"A\",\"name\":\"${DOMAIN}\",\"content\":\"${MYIP}\",\"ttl\":120,\"proxied\":${CF_PROXIED}}" >/dev/null || send_log "error" "11" "Cloudflare create POST failed"
    send_log "step" "11" "Created A record ${DOMAIN} -> ${MYIP}"
  fi
else
  send_log "step" "11" "Skipping Cloudflare update (domain/zone/token missing)"
fi

# ---------- generate connection strings ----------
send_log "step" "12" "Generating connection strings"

# Determine server address
if [ -n "$DOMAIN" ]; then
  SERVER_ADDR="$DOMAIN"
else
  SERVER_ADDR="$MYIP"
fi

# Generate VLESS connection string
if [ "$SECURITY" = "tls" ]; then
  # VLESS with TLS (WebSocket)
  VLESS_STRING="vless://${UUID}@${SERVER_ADDR}:${PORT}?type=ws&security=tls&path=%2F#V2Ray-${RUN_ID}"
else
  # VLESS without TLS (TCP)
  VLESS_STRING="vless://${UUID}@${SERVER_ADDR}:${PORT}?type=tcp&security=none#V2Ray-${RUN_ID}"
fi

# Generate VMess connection string (alternative format)
VMESS_CONFIG=""
if command -v python3 >/dev/null 2>&1; then
  VMESS_CONFIG="$(python3 - 2>/dev/null <<PY || echo ""
import json, base64
try:
    config = {
        "v": "2",
        "ps": "V2Ray-${RUN_ID}",
        "add": "${SERVER_ADDR}",
        "port": "${PORT}",
        "id": "${UUID}",
        "aid": "0",
        "net": "${NETWORK}",
        "type": "none",
        "host": "${SERVER_ADDR}" if "${DOMAIN}" else "",
        "path": "${PATH}",
        "tls": "${SECURITY}"
    }
    vmess_json = json.dumps(config, separators=(',', ':'))
    vmess_b64 = base64.b64encode(vmess_json.encode()).decode()
    print("vmess://" + vmess_b64)
except:
    print("")
PY
)"
fi

send_log "step" "12" "Connection strings generated"

# ---------- write client info file ----------
CLIENT_FILE="/root/vpn-client-${RUN_ID}.json"
send_log "step" "13" "Writing client info file"

if command -v python3 >/dev/null 2>&1; then
  python3 - 2>/dev/null <<PY > "${CLIENT_FILE}" || {
    send_log "error" "13" "Failed to write client info file"
    exit 1
  }
import json
try:
    obj = {
        "run_id":"${RUN_ID}",
        "host":"${HOSTNAME}",
        "ip":"${MYIP}",
        "port":"${PORT}",
        "uuid":"${UUID}",
        "mode":"${USED_MODE}",
        "domain":"${DOMAIN}",
        "cert_fullchain":"${CERT_FULLCHAIN_PATH}",
        "cert_key":"${CERT_KEY_PATH}",
        "vless_string":"${VLESS_STRING}",
        "vmess_string":"${VMESS_CONFIG}",
        "server_address":"${SERVER_ADDR}",
        "security":"${SECURITY}",
        "network":"${NETWORK}",
        "path":"${PATH}"
    }
    print(json.dumps(obj, indent=2))
except Exception as e:
    print("{\"error\": \"Failed to generate JSON\"}")
PY
else
  # Fallback without Python
  cat > "${CLIENT_FILE}" <<EOF
{
  "run_id": "${RUN_ID}",
  "host": "${HOSTNAME}",
  "ip": "${MYIP}",
  "port": "${PORT}",
  "uuid": "${UUID}",
  "mode": "${USED_MODE}",
  "vless_string": "${VLESS_STRING}"
}
EOF
fi

chmod 600 "${CLIENT_FILE}"
send_log "step" "13" "Client info written to ${CLIENT_FILE}"

# ---------- test v2ray service ----------
send_log "step" "14" "Testing v2ray service status"
if systemctl is-active --quiet v2ray; then
  send_log "step" "14" "v2ray service is active and running"
else
  send_log "error" "14" "v2ray service is not running properly"
  systemctl status v2ray || true
fi

# ---------- final webhook with connection strings ----------
send_log "step" "15" "Preparing final webhook payload"

if command -v python3 >/dev/null 2>&1; then
  FINAL_PAYLOAD="$(python3 - 2>/dev/null <<PY || echo ""
if command -v python3 >/dev/null 2>&1; then
  FINAL_PAYLOAD="$(python3 - 2>/dev/null <<PY || echo ""
import json
try:
    print(json.dumps({
        "run_id":"$RUN_ID",
        "host":"$HOSTNAME", 
        "status":"finished",
        "message":"Installation finished successfully",
        "timestamp":"$(date -u +%FT%TZ)",
        "ip":"$MYIP",
        "port":"$PORT",
        "uuid":"$UUID",
        "domain":"$DOMAIN",
        "mode":"$USED_MODE",
        "vless_connection":"$VLESS_STRING",
        "vmess_connection":"$VMESS_CONFIG",
        "server_address":"$SERVER_ADDR",
        "security":"$SECURITY",
        "network":"$NETWORK"
    }))
except:
    print("{\"status\":\"error\",\"message\":\"Failed to generate payload\"}")
PY
)"
else
  # Fallback payload without Python
  FINAL_PAYLOAD="{\"run_id\":\"$RUN_ID\",\"status\":\"finished\",\"message\":\"Installation completed\",\"ip\":\"$MYIP\",\"port\":\"$PORT\",\"uuid\":\"$UUID\",\"vless_connection\":\"$VLESS_STRING\"}"
fi

send_log "step" "15" "Sending final webhook notification"

if [ -n "$WEBHOOK_USER" ] && [ -n "$WEBHOOK_PASS" ]; then
  curl -sS -u "$WEBHOOK_USER:$WEBHOOK_PASS" -X POST "$WEBHOOK_URL" -H "Content-Type: application/json" -d "$FINAL_PAYLOAD" || echo "WARN: final webhook POST failed"
elif [ -n "$WEBHOOK_SECRET" ]; then
  curl -sS -X POST "$WEBHOOK_URL" -H "Content-Type: application/json" -H "X-Setup-Token: $WEBHOOK_SECRET" -d "$FINAL_PAYLOAD" || echo "WARN: final webhook POST failed"
else
  curl -sS -X POST "$WEBHOOK_URL" -H "Content-Type: application/json" -d "$FINAL_PAYLOAD" || echo "WARN: final webhook POST failed"
fi

echo "=== DONE ==="
echo "UUID: ${UUID}"
echo "PORT: ${PORT}"
echo "IP: ${MYIP}"
echo "Domain: ${DOMAIN}"
echo "Client file: ${CLIENT_FILE}"
echo ""
echo "=== CONNECTION STRINGS ==="
echo "VLESS: ${VLESS_STRING}"
echo "VMess: ${VMESS_CONFIG}"
echo ""
echo "Copy one of the above connection strings to your V2Ray client."
