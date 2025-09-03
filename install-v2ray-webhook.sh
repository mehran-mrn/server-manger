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
CF_ACCOUNT_ID=""
CF_API_TOKEN=""
CF_PROXIED="false"
PORT="16823"
RUN_ID=""
MODE="auto"   # auto | simple | stealth
DEPS="cron wget iptables ufw unzip ca-certificates python3 jq openssl socat"
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
    --cf-account-id) CF_ACCOUNT_ID="$2"; shift 2;;
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

# ---------- firewall: try ufw or iptables fallback ----------
send_log "step" "4" "Configuring firewall (allow port ${PORT})"
if command -v ufw >/dev/null 2>&1; then
  ufw allow "${PORT}/tcp" || send_log "step" "4" "ufw allow failed (maybe ufw inactive)"
  ufw allow "80/tcp" || send_log "step" "4" "ufw allow failed port 80 (maybe ufw inactive)"
  ufw allow "443/tcp" || send_log "step" "4" "ufw allow failed port 443 (maybe ufw inactive)"
  ufw reload
else
  # add a basic iptables accept rule (non-persistent)
  iptables -I INPUT -p tcp --dport "$PORT" -j ACCEPT || send_log "step" "4" "iptables rule add failed"
  iptables -I INPUT -p tcp --dport 80 -j ACCEPT || send_log "step" "4" "iptables rule port 80 add failed"
  iptables -I INPUT -p tcp --dport 443 -j ACCEPT || send_log "step" "4" "iptables rule port 443 add failed"
fi
# add iptables rules
PUB_IFACE=$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++){if($i=="dev"){print $(i+1)}}}')
echo "Public interface: $PUB_IFACE"

iptables -I INPUT -p tcp --dport "$PORT" -j ACCEPT || send_log "step" "4" "iptables INPUT rule add failed"
iptables -t nat -C POSTROUTING -o "$PUB_IFACE" -j MASQUERADE 2>/dev/null || \
  iptables -t nat -A POSTROUTING -o "$PUB_IFACE" -j MASQUERADE
iptables -C FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
  iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -C FORWARD -s 0.0.0.0/0 -j ACCEPT 2>/dev/null || \
  iptables -A FORWARD -s 0.0.0.0/0 -j ACCEPT
# enable ip_forward
sysctl -w net.ipv4.ip_forward=1 >/dev/null
grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

# ---------- obtain cert if domain+CF provided and mode requires stealth ----------
CERT_KEY_PATH=""
CERT_FULLCHAIN_PATH=""
CERT_ISSUED=0

if [ "$MODE" = "auto" ] || [ "$MODE" = "stealth" ]; then
  if [ -n "$DOMAIN" ] && [ -n "$CF_API_TOKEN" ]; then
    send_log "step" "5" "Attempting to obtain TLS cert with acme.sh using Cloudflare DNS"
    # install acme.sh if missing
    if [ ! -x "$ACME_SH" ]; then
      curl -sSfL https://get.acme.sh | sh || { send_log "error" "4" "acme.sh install failed"; }
    fi
    export CF_Token="$CF_API_TOKEN"
    export CF_Account_ID="$CF_ACCOUNT_ID"
    export CF_Zone_ID="$CF_ZONE_ID"
    # issue cert (dns)
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    /root/.acme.sh/acme.sh --register-account -m mehranmarandi90@gmail.com
    /root/.acme.sh/acme.sh --issue --dns dns_cf -d "$DOMAIN" --keylength ec-256 && CERT_ISSUED=1 || {
      # try with default installation path
      /root/.acme.sh/acme.sh --issue --dns dns_cf -d "$DOMAIN" || send_log "step" "5" "acme.sh issue may have failed; continuing in non-TLS mode"
    }
    # install cert to /etc/ssl/v2ray-<runid> if exists
    if [ "$CERT_ISSUED" -eq 1 ] && /root/.acme.sh/acme.sh --list | grep -q "$DOMAIN"; then
      rm -rf /etc/ssl/v2ray-$RUN_ID
      mkdir -p /etc/ssl/v2ray-$RUN_ID
      
      /root/.acme.sh/acme.sh --installcert -d "$DOMAIN" \
        --fullchain-file /etc/ssl/v2ray-$RUN_ID/fullchain.pem \
        --key-file /etc/ssl/v2ray-$RUN_ID/key.pem || send_log "step" "5" "acme.sh installcert failed"
        
      # check if cert files actually exist
      if [ -f "/etc/ssl/v2ray-$RUN_ID/fullchain.pem" ] && [ -f "/etc/ssl/v2ray-$RUN_ID/key.pem" ]; then
        CERT_FULLCHAIN_PATH="/etc/ssl/v2ray-$RUN_ID/fullchain.pem"
        CERT_KEY_PATH="/etc/ssl/v2ray-$RUN_ID/key.pem"
        send_log "step" "5" "Certificate installed: $CERT_FULLCHAIN_PATH"
      else
        CERT_FULLCHAIN_PATH=""
        CERT_KEY_PATH=""
        send_log "step" "5" "Certificate issuance failed; no cert files found"
      fi
      
    else
      send_log "step" "5" "Certificate not issued; will fall back to non-TLS config"
      CERT_FULLCHAIN_PATH=""
      CERT_KEY_PATH=""
    fi
  else
    send_log "step" "5" "Skipping cert issuance (DOMAIN or CF_API_TOKEN missing)"
  fi
fi

# ---------- write v2ray config ----------
CONFIG_PATH="/usr/local/etc/v2ray/config.json"
send_log "step" "6" "Writing v2ray config to $CONFIG_PATH"

if [ "$CERT_ISSUED" -eq 1 ] && [ -n "$CERT_FULLCHAIN_PATH" ] && [ -n "$CERT_KEY_PATH" ]; then
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
fi

send_log "step" "7" "Config written (mode: $USED_MODE)"

# ---------- enable & start service ----------
send_log "step" "8" "Enabling and starting v2ray service"
systemctl daemon-reload
systemctl enable --now v2ray || { send_log "error" "7" "Failed to start v2ray"; }

sleep 2
# verify listening
if ss -ltnp 2>/dev/null | grep -q ":${PORT}[[:space:]]"; then
  send_log "step" "9" "v2ray is listening on port ${PORT}"
else
  send_log "error" "9" "Service not listening on port ${PORT}"
fi

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

# ---------- build VLESS connection string ----------
VLESS_URI="vless://${UUID}@${DOMAIN}:${PORT}?type=ws&encryption=none&security=tls&host=${DOMAIN}&path=/#VPN-${RUN_ID}"

send_log "step" "12" "${VLESS_URI}"

# ---------- write client info file ----------
CLIENT_FILE="/root/vpn-client-${RUN_ID}.json"
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
send_log "step" "13" "Wrote client info to ${CLIENT_FILE}"

# ---------- final webhook ----------
FINAL_PAYLOAD="$(python3 - <<PY
import json
print(json.dumps({
  "run_id":"$RUN_ID",
  "host":"$HOSTNAME",
  "status":"finished",
  "message":"Installation finished",
  "timestamp":"$(date -u +%FT%TZ)",
  "ip":"$MYIP",
  "port":"$PORT",
  "uuid":"$UUID",
  "domain":"$DOMAIN",
  "mode":"$USED_MODE"
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
