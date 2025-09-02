#!/bin/bash
set -euo pipefail

# ==========================
# Config
# ==========================
DOMAIN="$1"
RUN_ID="$(date +%s)"
WS_PATH="/$(tr -dc 'a-z0-9' < /dev/urandom | head -c 8)"
UUID=$(cat /proc/sys/kernel/random/uuid)
EMAIL="admin@${DOMAIN}"

WEBHOOK_URL="${WEBHOOK_URL:-}"

# ==========================
# Helper Functions
# ==========================
notify() {
  local msg="$1"
  echo "$msg"
  if [[ -n "$WEBHOOK_URL" ]]; then
    curl -s -X POST -H 'Content-type: application/json' --data "{\"text\":\"$msg\"}" "$WEBHOOK_URL" || true
  fi
}

random_string() {
  tr -dc 'a-z0-9' < /dev/urandom | head -c "$1"
}

# ==========================
# Detect network interface
# ==========================
IFACE=$(ip route get 1.1.1.1 | awk '{print $5; exit}')
MYIP=$(curl -s ipv4.icanhazip.com)

# ==========================
# Install dependencies
# ==========================
notify "Installing dependencies..."
apt-get update -y
apt-get install -y curl socat software-properties-common iptables-persistent uuid-runtime

# ==========================
# Enable IP forwarding
# ==========================
if ! grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf; then
  echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
  sysctl -p
fi

# ==========================
# Setup iptables
# ==========================
iptables -t nat -C POSTROUTING -o "$IFACE" -j MASQUERADE 2>/dev/null || \
iptables -t nat -A POSTROUTING -o "$IFACE" -j MASQUERADE

iptables-save > /etc/iptables/rules.v4

# ==========================
# Issue SSL certificate
# ==========================
notify "Issuing SSL certificate..."
export CF_Token="$CF_API_TOKEN"
export CF_Account_ID="$CF_ACCOUNT_ID"

curl https://get.acme.sh | sh
~/.acme.sh/acme.sh --register-account -m "$EMAIL"
~/.acme.sh/acme.sh --issue --dns dns_cf -d "$DOMAIN" --server letsencrypt --force
~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" \
  --key-file /etc/ssl/private/${DOMAIN}.key \
  --fullchain-file /etc/ssl/certs/${DOMAIN}.crt --force

# ==========================
# Install V2Ray
# ==========================
notify "Installing V2Ray..."
bash <(curl -Ls https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)

cat >/usr/local/etc/v2ray/config.json <<EOF
{
  "inbounds": [
    {
      "port": 443,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "$UUID",
            "alterId": 0
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "$WS_PATH"
        },
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/ssl/certs/${DOMAIN}.crt",
              "keyFile": "/etc/ssl/private/${DOMAIN}.key"
            }
          ]
        }
      }
    }
  ],
  "outbounds": [
    { "protocol": "freedom" },
    { "protocol": "blackhole", "tag": "blocked" }
  ]
}
EOF

systemctl enable v2ray
systemctl restart v2ray

# ==========================
# Generate client config
# ==========================
CLIENT_CONFIG=$(cat <<EOC
{
  "v": "2",
  "ps": "v2ray-${RUN_ID}",
  "add": "${DOMAIN}",
  "port": "443",
  "id": "${UUID}",
  "aid": "0",
  "net": "ws",
  "type": "none",
  "host": "${DOMAIN}",
  "path": "${WS_PATH}",
  "tls": "tls"
}
EOC
)

CLIENT_JSON_FILE="/root/vpn-client-${RUN_ID}.json"
echo "$CLIENT_CONFIG" > "$CLIENT_JSON_FILE"
chmod 600 "$CLIENT_JSON_FILE"

VMESS_LINK="vmess://$(echo -n "$CLIENT_CONFIG" | base64 -w0)"

notify "V2Ray setup completed.\n\nClient JSON: $CLIENT_JSON_FILE\nVMess: $VMESS_LINK"

# Cleanup: remove client file if you don’t want to keep it
# rm -f "$CLIENT_JSON_FILE"
