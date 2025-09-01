#!/usr/bin/env bash
# install-v2ray-webhook.sh
# Usage:
#   sudo ./install-v2ray-webhook.sh --webhook-url "https://your-n8n.example/webhook/receive" \
#       [--webhook-secret SECRET] [--domain example.com] [--cf-zone-id ZONEID] [--cf-api-token TOKEN] [--port 16823] [--run-id ID]
#
# Notes:
#  - Port defaults to 16823 (fixed, as requested).
#  - If --domain and Cloudflare info provided, script will attempt to update A record.
#  - Script will POST JSON logs to WEBHOOK_URL. If WEBHOOK_SECRET set, it will send header X-Setup-Token: <secret>.
#
set -euo pipefail

# --------- parse args ----------
WEBHOOK_URL=""
WEBHOOK_SECRET=""
DOMAIN=""
CF_ZONE_ID=""
CF_API_TOKEN=""
PORT="16823"
RUN_ID=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --webhook-url) WEBHOOK_URL="$2"; shift 2;;
    --webhook-secret) WEBHOOK_SECRET="$2"; shift 2;;
    --domain) DOMAIN="$2"; shift 2;;
    --cf-zone-id) CF_ZONE_ID="$2"; shift 2;;
    --cf-api-token) CF_API_TOKEN="$2"; shift 2;;
    --port) PORT="$2"; shift 2;;
    --run-id) RUN_ID="$2"; shift 2;;
    -h|--help) echo "Usage: $0 --webhook-url <url> [--webhook-secret <secret>] [--domain ...]"; exit 0;;
    *) echo "Unknown arg: $1"; exit 2;;
  esac
done

if [ -z "$WEBHOOK_URL" ]; then
  echo "ERROR: --webhook-url is required"
  exit 1
fi

if [ "$EUID" -ne 0 ]; then
  echo "ERROR: must run as root"
  exit 1
fi

if [ -z "$RUN_ID" ]; then
  RUN_ID="$(date +%s)-$RANDOM"
fi

HOSTNAME="$(hostname -f 2>/dev/null || hostname)"

# --------- helper: send log to webhook (uses python3 to produce safe JSON) ----------
send_log(){
  local STATUS="$1"   # e.g., starting, step, success, error
  local STEP="$2"     # numeric or short name
  local MESSAGE="$3"
  local TS="$(date -u +%FT%TZ)"

  # Build JSON payload using python3 for safe escaping
  PAYLOAD="$(python3 - <<PY
import json,sys
obj = {
  "run_id": "$RUN_ID",
  "host": "$HOSTNAME",
  "status": "$STATUS",
  "step": "$STEP",
  "message": "$MESSAGE",
  "timestamp": "$TS",
  "port": "$PORT",
  "domain": "$DOMAIN"
}
print(json.dumps(obj))
PY
)"
  # send (don't fail the whole script if webhook is unreachable; just warn)
  if [ -n "$WEBHOOK_SECRET" ]; then
    curl -sS -X POST "$WEBHOOK_URL" -H "Content-Type: application/json" -H "X-Setup-Token: $WEBHOOK_SECRET" -d "$PAYLOAD" || echo "WARN: webhook POST failed"
  else
    curl -sS -X POST "$WEBHOOK_URL" -H "Content-Type: application/json" -d "$PAYLOAD" || echo "WARN: webhook POST failed"
  fi

  # also echo locally
  echo "[$TS] [$STATUS] step=$STEP: $MESSAGE"
}

# Start
send_log "starting" "0" "Setup started (run_id=$RUN_ID)"

send_log "step" "1" "Updating package lists and installing prerequisites"
apt-get update -y
DEPS="curl wget unzip ca-certificates python3"
apt-get install -y $DEPS

send_log "step" "2" "Downloading and running official fhs-install-v2ray install-release.sh"
# Using the official fhs-install script from v2fly (non-docker, systemd-friendly)
bash <(curl -fsSL https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh) || {
  send_log "error" "2" "Failed to run install-release.sh"; exit 1;
}
send_log "step" "3" "fhs-install script completed"

# generate UUID for client
UUID="$(cat /proc/sys/kernel/random/uuid)"
send_log "step" "4" "Generated UUID: $UUID"

# Write a minimal v2ray config (VLESS TCP no-TLS on fixed port)
send_log "step" "5" "Writing /usr/local/etc/v2ray/config.json"
cat > /usr/local/etc/v2ray/config.json <<EOF
{
  "log": {
    "access": "/var/log/v2ray/access.log",
    "error": "/var/log/v2ray/error.log",
    "loglevel": "warning"
  },
  "inbounds": [{
    "port": ${PORT},
    "protocol": "vless",
    "settings": {
      "clients": [{ "id": "${UUID}", "level": 0, "email": "user@local" }],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "tcp",
      "security": "none"
    }
  }],
  "outbounds": [{ "protocol": "freedom" }]
}
EOF

send_log "step" "6" "Config file written"

send_log "step" "7" "Enabling and starting v2ray service"
systemctl daemon-reload
systemctl enable --now v2ray || {
  send_log "error" "7" "Failed to start v2ray service"; exit 1;
}
sleep 2

# verify service listening
if ss -ltnp | grep -q ":${PORT}[[:space:]]"; then
  send_log "step" "8" "Service listening on port ${PORT}"
else
  send_log "error" "8" "Service not listening on port ${PORT} -- check logs /var/log/v2ray"
  # proceed but mark as error
fi

# Get public IP
MYIP="$(curl -s https://ipv4.icanhazip.com | tr -d '\n')"
send_log "step" "9" "Detected public IP: $MYIP"

# Optional: update Cloudflare DNS if zone & token given
if [ -n "$DOMAIN" ] && [ -n "$CF_ZONE_ID" ] && [ -n "$CF_API_TOKEN" ]; then
  send_log "step" "10" "Updating Cloudflare DNS for ${DOMAIN}"
  # find record id
  GET_REC="$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records?name=${DOMAIN}" \
    -H "Authorization: Bearer ${CF_API_TOKEN}" -H "Content-Type: application/json")"
  RECORD_ID="$(echo "$GET_REC" | python3 -c "import sys,json; j=json.load(sys.stdin); r=j.get('result'); print(r[0]['id'] if r else '')" 2>/dev/null || true)"
  if [ -n "$RECORD_ID" ]; then
    send_log "step" "11" "Found existing record id=${RECORD_ID}, updating to ${MYIP}"
    curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records/${RECORD_ID}" \
      -H "Authorization: Bearer ${CF_API_TOKEN}" -H "Content-Type: application/json" \
      --data "{\"type\":\"A\",\"name\":\"${DOMAIN}\",\"content\":\"${MYIP}\",\"ttl\":120,\"proxied\":false}" >/dev/null || {
        send_log "error" "11" "Cloudflare update PUT failed"
      }
  else
    send_log "step" "11" "No existing record, creating A record ${DOMAIN} -> ${MYIP}"
    curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records" \
      -H "Authorization: Bearer ${CF_API_TOKEN}" -H "Content-Type: application/json" \
      --data "{\"type\":\"A\",\"name\":\"${DOMAIN}\",\"content\":\"${MYIP}\",\"ttl\":120,\"proxied\":false}" >/dev/null || {
        send_log "error" "11" "Cloudflare create POST failed"
      }
  fi
else
  send_log "step" "10" "Skipping Cloudflare DNS (CF_ZONE_ID or CF_API_TOKEN or DOMAIN missing)"
fi

# Final report
FINAL_PAYLOAD="$(python3 - <<PY
import json
print(json.dumps({
  "run_id": "$RUN_ID",
  "host": "$HOSTNAME",
  "status": "finished",
  "message": "Installation finished",
  "timestamp": "$(date -u +%FT%TZ)",
  "ip": "$MYIP",
  "port": "$PORT",
  "uuid": "$UUID",
  "domain": "$DOMAIN"
}))
PY
)"
# send final
if [ -n "$WEBHOOK_SECRET" ]; then
  curl -sS -X POST "$WEBHOOK_URL" -H "Content-Type: application/json" -H "X-Setup-Token: $WEBHOOK_SECRET" -d "$FINAL_PAYLOAD" || echo "WARN: final webhook POST failed"
else
  curl -sS -X POST "$WEBHOOK_URL" -H "Content-Type: application/json" -d "$FINAL_PAYLOAD" || echo "WARN: final webhook POST failed"
fi

echo "=== DONE ==="
echo "UUID: ${UUID}"
echo "PORT: ${PORT}"
echo "IP: ${MYIP}"
