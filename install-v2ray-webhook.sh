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

# ---------- obtain cert if domain provided and mode requires stealth ----------
CERT_KEY_PATH=""
CERT_FULLCHAIN_PATH=""
CERT_SUCCESS="false"

if [ "$MODE" = "auto" ] || [ "$MODE" = "stealth" ]; then
  if [ -n "$DOMAIN" ]; then
    send_log "step" "4" "Attempting to obtain TLS cert with acme.sh using HTTP-01 challenge"
    
    # install acme.sh if missing
    if [ ! -x "$ACME_SH" ]; then
      curl -sSfL https://get.acme.sh | sh || { 
        send_log "step" "4" "acme.sh install failed, falling back to non-TLS"
        CERT_SUCCESS="false"
      }
    fi
    
    # Only proceed if acme.sh is available
    if [ -x "$ACME_SH" ]; then
      # Stop any service using port 80
      systemctl stop apache2 2>/dev/null || true
      systemctl stop nginx 2>/dev/null || true
      pkill -f "python.*SimpleHTTP" 2>/dev/null || true
      
      # Issue cert using standalone mode (acme.sh handles the web server)
      $ACME_SH --issue -d "$DOMAIN" --standalone --httpport 80 --force && CERT_SUCCESS="true" || {
        send_log "step" "4" "HTTP-01 challenge failed, falling back to non-TLS"
        CERT_SUCCESS="false"
      }
      
      # Install cert if successful
      if [ "$CERT_SUCCESS" = "true" ]; then
        mkdir -p /etc/ssl/v2ray-$RUN_ID
        $ACME_SH --installcert -d "$DOMAIN" \
          --fullchain-file /etc/ssl/v2ray-$RUN_ID/fullchain.pem \
          --key-file /etc/ssl/v2ray-$RUN_ID/key.pem && {
          CERT_FULLCHAIN_PATH="/etc/ssl/v2ray-$RUN_ID/fullchain.pem"
          CERT_KEY_PATH="/etc/ssl/v2ray-$RUN_ID/key.pem"
          send_log "step" "4" "Certificate successfully installed: $CERT_FULLCHAIN_PATH"
        } || {
          send_log "step" "4" "Certificate install failed, falling back to non-TLS"
          CERT_SUCCESS="false"
          CERT_FULLCHAIN_PATH=""
          CERT_KEY_PATH=""
        }
      fi
      
      # Verify certificate files exist and are readable
      if [ "$CERT_SUCCESS" = "true" ]; then
        if [ ! -f "$CERT_FULLCHAIN_PATH" ] || [ ! -f "$CERT_KEY_PATH" ]; then
          send_log "step" "4" "Certificate files not found, falling back to non-TLS"
          CERT_SUCCESS="false"
          CERT_FULLCHAIN_PATH=""
          CERT_KEY_PATH=""
        fi
      fi
    else
      send_log "step" "4" "acme.sh not available, falling back to non-TLS"
      CERT_SUCCESS="false"
    fi
  else
    send_log "step" "4" "Skipping cert issuance (DOMAIN not provided)"
    CERT_SUCCESS="false"
  fi
else
  send_log "step" "4" "Skipping cert issuance (mode is simple)"
  CERT_SUCCESS="false"
fi

# ---------- write v2ray config ----------
CONFIG_PATH="/usr/local/etc/v2ray/config.json"
send_log "step" "5" "Writing v2ray config to $CONFIG_PATH"

# Create log directory
mkdir -p /var/log/v2ray

if [ "$CERT_SUCCESS" = "true" ] && [ -n "$CERT_FULLCHAIN_PATH" ] && [ -n "$CERT_KEY_PATH" ]; then
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
  "outbounds": [{"protocol":"freedom"}]
}
EOF
  USED_MODE="stealth (vless+ws+tls)"
  send_log "step" "5" "Config written with TLS enabled (mode: $USED_MODE)"
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
  "outbounds": [{"protocol":"freedom"}]
}
EOF
  USED_MODE="simple (vless+tcp+none)"
  send_log "step" "5" "Config written without TLS (mode: $USED_MODE)"
fi

send_log "step" "6" "Config written (mode: $USED_MODE)"

# ---------- enable & start service ----------
send_log "step" "7" "Enabling and starting v2ray service"
systemctl daemon-reload
systemctl enable --now v2ray || { send_log "error" "7" "Failed to start v2ray"; }

sleep 2
# verify listening
if ss -ltnp 2>/dev/null | grep -q ":${PORT}[[:space:]]"; then
  send_log "step" "8" "v2ray is listening on port ${PORT}"
else
  send_log "error" "8" "Service not listening on port ${PORT}"
fi

# ---------- firewall: try ufw or iptables fallback ----------
send_log "step" "9" "Configuring firewall (allow port ${PORT})"
ufw allow 80/tcp
ufw allow 443/tcp
if command -v ufw >/dev/null 2>&1; then
  ufw allow "${PORT}/tcp" || send_log "step" "9" "ufw allow failed (maybe ufw inactive)"
else
  # add a basic iptables accept rule (non-persistent)
  iptables -I INPUT -p tcp --dport "$PORT" -j ACCEPT || send_log "step" "9" "iptables rule add failed"
fi
# add iptables rules
iptables -I INPUT -p tcp --dport 80 -j ACCEPT
iptables -I INPUT -p tcp --dport 443 -j ACCEPT
iptables -I INPUT -p tcp --dport "$PORT" -j ACCEPT || send_log "step" "9" "iptables INPUT rule add failed"
iptables -t nat -C POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || \
  iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -C FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
  iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -C FORWARD -s 0.0.0.0/0 -j ACCEPT 2>/dev/null || \
  iptables -A FORWARD -s 0.0.0.0/0 -j ACCEPT
# enable ip_forward
sysctl -w net.ipv4.ip_forward=1 >/dev/null
grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

# ---------- detect public IP ----------
MYIP="$(curl -s https://ipv4.icanhazip.com | tr -d '\n' || true)"
send_log "step" "10" "Public IP detected: ${MYIP}"

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

# ---------- write client info file ----------
CLIENT_FILE="/root/vpn-client-${RUN_ID}.json"
ADDR="${DOMAIN:-$MYIP}"
if [[ "$USED_MODE" == stealth* ]]; then
  SCHEME="vless://${UUID}@${ADDR}:${PORT}?type=ws&encryption=none&security=tls&host=${DOMAIN}&path=/#${HOSTNAME}"
else
  SCHEME="vless://${UUID}@${ADDR}:${PORT}?type=tcp&encryption=none#${HOSTNAME}"
fi

send_log "step" "11" "${SCHEME}"

python3 - <<PY > "${CLIENT_FILE}"
import json
obj = {
  "run_id":"${RUN_ID}",
  "host":"${HOSTNAME}",
  "ip":"${MYIP}",
  "port":"${PORT}",
  "uuid":"${UUID}",
  "mode":"${USED_MODE}",
  "domain":"${DOMAIN}",
  "cert_fullchain":"${CERT_FULLCHAIN_PATH}",
  "cert_key":"${CERT_KEY_PATH}"
}
print(json.dumps(obj, indent=2))
PY
chmod 600 "${CLIENT_FILE}"
send_log "step" "12" "Wrote client info to ${CLIENT_FILE}"

# ---------- final webhook ----------
FINAL_PAYLOAD="$(python3 - <<PY
import json
print(json.dumps({
  "run_id":"$RUN_ID",
  "host":"$HOSTNAME",
  "status":"finished",
  "message":"Installation finished $SCHEME",
  "timestamp":"$(date -u +%FT%TZ)",
  "ip":"$MYIP",
  "port":"$PORT",
  "uuid":"$UUID",
  "domain":"$DOMAIN",
  "mode":"$USED_MODE",
  "vless_link":"$SCHEME"
}))
PY
)"
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
echo "Client file: ${CLIENT_FILE}"
