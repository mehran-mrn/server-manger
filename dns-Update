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
PANEL_PASS="admin3"
RUN_ID=""
MODE="auto"
DEPS="cron wget iptables ufw unzip ca-certificates python3 jq openssl socat curl certbot python3-certbot-dns-cloudflare sqlite3 apache2-utils"
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
    --panel-pass) PANEL_PASS="$2"; shift 2;;
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
