#!/usr/bin/env bash
# Description: Install 3X-UI with webhook support for n8n integration
# Usage example:
# sudo ./install-3x-ui-webhook.sh \
#   --webhook-url "https://n8n.oiix.ir/webhook/send-simple-message?chatId=90476610" \
#   --webhook-user "vpnBot" --webhook-pass "adI23#@P3ObFe" \
#   --domain "s1.oiix.ir" --cf-zone-id "ZONEID" --cf-api-token "CFTOKEN" \
#   --cf-proxied "false" --port 16823 --panel-port 54321

set -euo pipefail

# -------- defaults ----------
WEBHOOK_URL=""
WEBHOOK_USER=""
WEBHOOK_PASS=""
WEBHOOK_SECRET=""
DOMAIN=""
CF_ZONE_ID=""
CF_ACCOUNT_ID=""
CF_API_TOKEN=""
CF_PROXIED="false"
PORT="16823"
PANEL_PORT="54321"
RUN_ID=""
MODE="auto"
DEPS="cron wget iptables ufw unzip ca-certificates python3 jq openssl socat curl certbot python3-certbot-dns-cloudflare sqlite3"
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
    --panel-port) PANEL_PORT="$2"; shift 2;;
    --run-id) RUN_ID="$2"; shift 2;;
    --mode) MODE="$2"; shift 2;;
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

# Generate random username and password for 3X-UI
USERNAME="admin"
PASSWORD="$(openssl rand -hex 12)"

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
  "panel_port":"$PANEL_PORT",
  "domain":"$DOMAIN",
  "username":"$USERNAME",
  "password":"$PASSWORD"
}))
PY
)"
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

# ---------- fix hostname ----------
send_log "step" "1" "Fixing hostname resolution"
echo "127.0.0.1 localhost $HOSTNAME" > /etc/hosts
hostnamectl set-hostname "$HOSTNAME" || send_log "step" "1" "Failed to set hostname, continuing"

# ---------- install deps ----------
send_log "step" "2" "Updating packages and installing prerequisites"
apt-get update -y
apt-get install -y $DEPS || { send_log "error" "2" "Failed to install packages"; exit 1; }

# ---------- install Xray-core ----------
send_log "step" "3" "Installing Xray-core"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install || { send_log "error" "3" "Xray install failed"; exit 1; }

# ---------- install 3X-UI (non-interactive) ----------
send_log "step" "4" "Installing 3X-UI with panel port ${PANEL_PORT}, username ${USERNAME}, password ${PASSWORD}"
{ echo "$PANEL_PORT"; echo "$USERNAME"; echo "$PASSWORD"; } | bash <(curl -Ls https://raw.githubusercontent.com/MHSanaei/3x-ui/master/install.sh) || { send_log "error" "4" "3X-UI install failed"; exit 1; }

# ---------- configure 3X-UI panel settings ----------
send_log "step" "4.5" "Configuring 3X-UI panel settings in database"
DB_PATH="/etc/x-ui/x-ui.db"
if [ -f "$DB_PATH" ]; then
  # Wait for database to be ready
  sleep 2
  
  # Update panel settings in database
  sqlite3 "$DB_PATH" "UPDATE settings SET value='$PANEL_PORT' WHERE key='webPort';" || send_log "step" "4.5" "Failed to update webPort in database"
  sqlite3 "$DB_PATH" "UPDATE settings SET value='$USERNAME' WHERE key='webUsername';" || send_log "step" "4.5" "Failed to update username in database"
  HASHED_PASS="$(python3 - <<PY
    import bcrypt
    pw = b"$PASSWORD"
    print(bcrypt.hashpw(pw, bcrypt.gensalt()).decode())
    PY
    )"
    sqlite3 "$DB_PATH" "UPDATE settings SET value='$HASHED_PASS' WHERE key='webPassword';" || send_log "step" "4.5" "Failed to update password in database"

  # Set other useful defaults
  sqlite3 "$DB_PATH" "UPDATE settings SET value='/' WHERE key='webBasePath';" 2>/dev/null || true
  sqlite3 "$DB_PATH" "UPDATE settings SET value='false' WHERE key='webCertFile';" 2>/dev/null || true
  sqlite3 "$DB_PATH" "UPDATE settings SET value='false' WHERE key='webKeyFile';" 2>/dev/null || true
  
  send_log "step" "4.5" "Updated 3X-UI database settings"
else
  send_log "step" "4.5" "Database not found at $DB_PATH, will configure via config file"
fi

# ---------- firewall: allow panel port and inbound port ----------
send_log "step" "5" "Configuring firewall (allow ports ${PANEL_PORT} and ${PORT})"
if command -v ufw >/dev/null 2>&1; then
  ufw allow "${PANEL_PORT}/tcp" || send_log "step" "5" "ufw allow failed for panel port"
  ufw allow "${PORT}/tcp" || send_log "step" "5" "ufw allow failed for inbound port"
  ufw allow "80/tcp" || send_log "step" "5" "ufw allow failed port 80"
  ufw allow "443/tcp" || send_log "step" "5" "ufw allow failed port 443"
  ufw reload
else
  iptables -I INPUT -p tcp --dport "$PANEL_PORT" -j ACCEPT || send_log "step" "5" "iptables rule add failed for panel"
  iptables -I INPUT -p tcp --dport "$PORT" -j ACCEPT || send_log "step" "5" "iptables rule add failed for inbound"
  iptables -I INPUT -p tcp --dport 80 -j ACCEPT || send_log "step" "5" "iptables rule port 80 add failed"
  iptables -I INPUT -p tcp --dport 443 -j ACCEPT || send_log "step" "5" "iptables rule port 443 add failed"
fi
PUB_IFACE=$(ip route | grep default | head -1 | awk '{print $5}' || echo "eth0")
iptables -t nat -F POSTROUTING 2>/dev/null || true
iptables -F FORWARD 2>/dev/null || true
iptables -A INPUT -i lo -j ACCEPT 2>/dev/null || true
iptables -A OUTPUT -o lo -j ACCEPT 2>/dev/null || true
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT || send_log "step" "5" "iptables FORWARD ESTABLISHED rule failed"
iptables -A FORWARD -i "$PUB_IFACE" -o "$PUB_IFACE" -j ACCEPT || send_log "step" "5" "iptables FORWARD interface rule failed"
iptables -t nat -A POSTROUTING -o "$PUB_IFACE" -j MASQUERADE || send_log "step" "5" "iptables MASQUERADE rule failed"
sysctl -w net.ipv4.ip_forward=1 >/dev/null
echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-3xui.conf
echo "nameserver 8.8.8.8" > /etc/resolv.conf
echo "nameserver 1.1.1.1" >> /etc/resolv.conf
if command -v iptables-save >/dev/null 2>&1; then
  mkdir -p /etc/iptables
  iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
fi

# ---------- obtain cert if domain+CF provided ----------
CERT_KEY_PATH=""
CERT_FULLCHAIN_PATH=""
CERT_ISSUED=0

if [ "$MODE" = "auto" ] || [ "$MODE" = "stealth" ]; then
  if [ -n "$DOMAIN" ] && [ -n "$CF_API_TOKEN" ]; then
    send_log "step" "6" "Attempting to obtain TLS cert with certbot using Cloudflare DNS"
    # Create Cloudflare credentials file
    mkdir -p /root/.cloudflare
    echo "dns_cloudflare_api_token = $CF_API_TOKEN" > /root/.cloudflare/credentials.ini
    chmod 600 /root/.cloudflare/credentials.ini
    # Try certbot
    certbot certonly --dns-cloudflare --dns-cloudflare-credentials /root/.cloudflare/credentials.ini \
      -d "$DOMAIN" --email mehranmarandi90@gmail.com --agree-tos --non-interactive --key-type ecdsa || {
      send_log "step" "6" "certbot failed; falling back to acme.sh"
      if [ ! -x "$ACME_SH" ]; then
        curl -sSfL https://get.acme.sh | sh || { send_log "error" "6" "acme.sh install failed"; }
      fi
      export CF_Token="$CF_API_TOKEN"
      export CF_Account_ID="$CF_ACCOUNT_ID"
      export CF_Zone_ID="$CF_ZONE_ID"
      /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
      /root/.acme.sh/acme.sh --register-account -m mehranmarandi90@gmail.com
      /root/.acme.sh/acme.sh --issue --dns dns_cf -d "$DOMAIN" --keylength ec-256 --debug || {
        send_log "step" "6" "acme.sh issue failed; continuing without TLS cert"
      }
    }
    if [ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
      CERT_ISSUED=1
      CERT_FULLCHAIN_PATH="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
      CERT_KEY_PATH="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
      send_log "step" "6" "Certificate installed via certbot: $CERT_FULLCHAIN_PATH"
    elif /root/.acme.sh/acme.sh --list | grep -q "$DOMAIN"; then
      CERT_ISSUED=1
      rm -rf /etc/ssl/3xui-$RUN_ID
      mkdir -p /etc/ssl/3xui-$RUN_ID
      /root/.acme.sh/acme.sh --installcert -d "$DOMAIN" \
        --fullchain-file /etc/ssl/3xui-$RUN_ID/fullchain.pem \
        --key-file /etc/ssl/3xui-$RUN_ID/key.pem || send_log "step" "6" "acme.sh installcert failed"
      if [ -f "/etc/ssl/3xui-$RUN_ID/fullchain.pem" ] && [ -f "/etc/ssl/3xui-$RUN_ID/key.pem" ]; then
        CERT_FULLCHAIN_PATH="/etc/ssl/3xui-$RUN_ID/fullchain.pem"
        CERT_KEY_PATH="/etc/ssl/3xui-$RUN_ID/key.pem"
        send_log "step" "6" "Certificate installed via acme.sh: $CERT_FULLCHAIN_PATH"
      else
        CERT_FULLCHAIN_PATH=""
        CERT_KEY_PATH=""
        send_log "step" "6" "Certificate issuance failed; no cert files found"
      fi
    else
      send_log "step" "6" "Certificate not issued; panel will run without TLS initially"
    fi
  else
    send_log "step" "6" "Skipping cert issuance (DOMAIN or CF_API_TOKEN missing)"
  fi
fi

# ---------- update certificate settings in database if cert was issued ----------
if [ "$CERT_ISSUED" -eq 1 ] && [ -f "$DB_PATH" ]; then
  send_log "step" "6.5" "Updating certificate settings in database"
  sqlite3 "$DB_PATH" "UPDATE settings SET value='$CERT_FULLCHAIN_PATH' WHERE key='webCertFile';" || send_log "step" "6.5" "Failed to update cert file path"
  sqlite3 "$DB_PATH" "UPDATE settings SET value='$CERT_KEY_PATH' WHERE key='webKeyFile';" || send_log "step" "6.5" "Failed to update key file path"
fi

# ---------- restart 3X-UI service ----------
send_log "step" "7" "Restarting 3X-UI service"
systemctl restart x-ui || { send_log "error" "7" "Failed to restart 3X-UI"; }

# Wait longer for service to start
sleep 5

# Check if service is running
if ! systemctl is-active --quiet x-ui; then
  send_log "step" "7.5" "3X-UI service is not running, checking logs"
  journalctl -u x-ui --no-pager -n 10 || true
  send_log "step" "7.5" "Attempting to start service again"
  systemctl start x-ui || { send_log "error" "7.5" "Failed to start 3X-UI service"; }
  sleep 3
fi

if ss -ltnp 2>/dev/null | grep -q ":${PANEL_PORT}[[:space:]]"; then
  send_log "step" "8" "3X-UI is listening on port ${PANEL_PORT}"
else
  send_log "step" "8" "Service not listening on port ${PANEL_PORT}, checking netstat"
  netstat -tlnp | grep x-ui || netstat -tlnp | grep "${PANEL_PORT}" || send_log "step" "8" "No process found listening on specified port"
  
  # Try to check what port it's actually listening on
  ACTUAL_PORT=$(netstat -tlnp | grep x-ui | awk '{print $4}' | cut -d: -f2 | head -1)
  if [ -n "$ACTUAL_PORT" ]; then
    send_log "step" "8" "3X-UI is actually listening on port ${ACTUAL_PORT}"
  fi
fi

# ---------- detect public IP ----------
MYIP="$(curl -s https://ipv4.icanhazip.com | tr -d '\n' || true)"
send_log "step" "9" "Public IP detected: ${MYIP}"

# ---------- update Cloudflare DNS ----------
if [ -n "$DOMAIN" ] && [ -n "$CF_ZONE_ID" ] && [ -n "$CF_API_TOKEN" ]; then
  send_log "step" "10" "Updating Cloudflare DNS for ${DOMAIN} (proxied=${CF_PROXIED})"
  GET_REC="$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records?name=${DOMAIN}" \
    -H "Authorization: Bearer ${CF_API_TOKEN}" -H "Content-Type: application/json")"
  RECORD_ID="$(echo "$GET_REC" | jq -r '.result[0].id // empty')"
  if [ -n "$RECORD_ID" ]; then
    curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records/${RECORD_ID}" \
      -H "Authorization: Bearer ${CF_API_TOKEN}" -H "Content-Type: application/json" \
      --data "{\"type\":\"A\",\"name\":\"${DOMAIN}\",\"content\":\"${MYIP}\",\"ttl\":120,\"proxied\":${CF_PROXIED}}" >/dev/null || send_log "error" "10" "Cloudflare update PUT failed"
    send_log "step" "10" "Updated existing record id=${RECORD_ID}"
  else
    curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records" \
      -H "Authorization: Bearer ${CF_API_TOKEN}" -H "Content-Type: application/json" \
      --data "{\"type\":\"A\",\"name\":\"${DOMAIN}\",\"content\":\"${MYIP}\",\"ttl\":120,\"proxied\":${CF_PROXIED}}" >/dev/null || send_log "error" "10" "Cloudflare create POST failed"
    send_log "step" "10" "Created A record ${DOMAIN} -> ${MYIP}"
  fi
else
  send_log "step" "10" "Skipping Cloudflare update (domain/zone/token missing)"
fi

# ---------- build panel URL ----------
if [ -n "$DOMAIN" ] && [ "$CERT_ISSUED" -eq 1 ]; then
  PANEL_URL="https://${DOMAIN}:${PANEL_PORT}"
else
  PANEL_URL="http://${MYIP}:${PANEL_PORT}"
fi
send_log "step" "11" "Panel URL: ${PANEL_URL} (login with ${USERNAME}/${PASSWORD})"

# ---------- write client info file ----------
CLIENT_FILE="/root/3xui-client-${RUN_ID}.json"
python3 - <<PY > "${CLIENT_FILE}"
import json
obj = {
  "run_id": "${RUN_ID}",
  "host": "${HOSTNAME}",
  "ip": "${MYIP}",
  "port": "${PORT}",
  "panel_port": "${PANEL_PORT}",
  "mode": "${MODE}",
  "domain": "${DOMAIN}",
  "username": "${USERNAME}",
  "password": "${PASSWORD}",
  "cert_fullchain": "${CERT_FULLCHAIN_PATH}",
  "cert_key": "${CERT_KEY_PATH}"
}
print(json.dumps(obj, indent=2))
PY
chmod 600 "${CLIENT_FILE}"
send_log "step" "12" "Wrote client info to ${CLIENT_FILE}"

# ---------- final webhook ----------
FINAL_PAYLOAD="$(python3 - <<PY
import json
print(json.dumps({
  "run_id": "${RUN_ID}",
  "host": "${HOSTNAME}",
  "status": "finished",
  "message": "Installation finished. Access panel at ${PANEL_URL} with ${USERNAME}/${PASSWORD}. Set up inbounds and TLS in the panel.",
  "timestamp": "$(date -u +%FT%TZ)",
  "ip": "${MYIP}",
  "port": "${PORT}",
  "panel_port": "${PANEL_PORT}",
  "domain": "${DOMAIN}",
  "mode": "${MODE}",
  "username": "${USERNAME}",
  "password": "${PASSWORD}"
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
echo "Panel URL: ${PANEL_URL}"
echo "Username: ${USERNAME}"
echo "Password: ${PASSWORD}"
echo "Inbound Port Suggestion: ${PORT}"
echo "Client file: ${CLIENT_FILE}"

# ---------- final port check ----------
echo ""
echo "=== PORT STATUS CHECK ==="
echo "Checking what ports are listening:"
ss -tlnp | grep -E ":(${PANEL_PORT}|${PORT})" || echo "Neither specified ports are listening"
echo "All listening ports:"
ss -tlnp | grep LISTEN
