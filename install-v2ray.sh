#!/usr/bin/env bash
set -euo pipefail

DOMAIN="${1:-}"
CF_ZONE_ID="${2:-}"
CF_API_TOKEN="${3:-}"

if [ "$EUID" -ne 0 ]; then
  echo "Run as root"
  exit 1
fi

# 1. نصب پیش‌نیازها
apt-get update -y
apt-get install -y curl wget unzip ca-certificates socat

# 2. دانلود و اجرای اسکریپت رسمی نصب V2Ray
bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)

# 3. ساخت UUID
UUID=$(cat /proc/sys/kernel/random/uuid)
echo "Generated UUID: $UUID"

# 4. نوشتن config.json ساده (VLESS روی TCP)
cat > /usr/local/etc/v2ray/config.json <<EOF
{
  "inbounds": [{
    "port": 16823,
    "protocol": "vless",
    "settings": {
      "clients": [{ "id": "$UUID", "level": 0, "email": "user@local" }],
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

# 5. فعال‌سازی و راه‌اندازی سرویس
systemctl enable v2ray
systemctl restart v2ray

# 6. آپدیت DNS در Cloudflare (اختیاری)
if [ -n "$DOMAIN" ] && [ -n "$CF_ZONE_ID" ] && [ -n "$CF_API_TOKEN" ]; then
  MYIP=$(curl -s https://ipv4.icanhazip.com | tr -d '\n')
  echo "Updating DNS for $DOMAIN -> $MYIP"
  RECORD_NAME="$DOMAIN"
  GET_REC=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records?name=${RECORD_NAME}" \
    -H "Authorization: Bearer ${CF_API_TOKEN}" -H "Content-Type: application/json")
  RECORD_ID=$(echo "$GET_REC" | grep -oP '"id":"\K[^"]+' | head -n1 || true)
  if [ -n "$RECORD_ID" ]; then
    curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records/${RECORD_ID}" \
      -H "Authorization: Bearer ${CF_API_TOKEN}" -H "Content-Type: application/json" \
      --data "{\"type\":\"A\",\"name\":\"${RECORD_NAME}\",\"content\":\"${MYIP}\",\"ttl\":120,\"proxied\":false}"
  else
    curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records" \
      -H "Authorization: Bearer ${CF_API_TOKEN}" -H "Content-Type: application/json" \
      --data "{\"type\":\"A\",\"name\":\"${RECORD_NAME}\",\"content\":\"${MYIP}\",\"ttl\":120,\"proxied\":false}"
  fi
fi

echo "V2Ray installed and running!"
echo "UUID: $UUID"
echo "Config file: /usr/local/etc/v2ray/config.json"
