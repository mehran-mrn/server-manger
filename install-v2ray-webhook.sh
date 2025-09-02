#!/usr/bin/env bash
# install-v2ray-webhook.sh (improved with execution control)
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
WEBHOOK_SECRET=""
DOMAIN=""
CF_ZONE_ID=""
CF_API_TOKEN=""
CF_PROXIED="false"
PORT="16823"
RUN_ID=""
MODE="auto"
DEPS="curl wget unzip ca-certificates python3 jq openssl socat"
ACME_SH="/root/.acme.sh/acme.sh"

# Lock file for step ordering
LOCK_FILE="/tmp/v2ray-install-${RANDOM}.lock"
STEP_COUNTER=0

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

# -------- helper: controlled step execution ----------
execute_step() {
    local step_name="$1"
    local step_func="$2"
    local max_retries="${3:-3}"
    local retry_delay="${4:-2}"
    
    # Ensure steps run in order
    (
        flock -x 200
        STEP_COUNTER=$((STEP_COUNTER + 1))
        echo "[$STEP_COUNTER] Starting: $step_name"
        
        local attempt=1
        while [ $attempt -le $max_retries ]; do
            if $step_func; then
                echo "[$STEP_COUNTER] Completed: $step_name"
                return 0
            else
                echo "[$STEP_COUNTER] Attempt $attempt failed: $step_name"
                if [ $attempt -lt $max_retries ]; then
                    echo "[$STEP_COUNTER] Retrying in ${retry_delay}s..."
                    sleep $retry_delay
                fi
                attempt=$((attempt + 1))
            fi
        done
        
        echo "[$STEP_COUNTER] FAILED after $max_retries attempts: $step_name"
        return 1
        
    ) 200>"$LOCK_FILE"
}

# -------- helper: synchronized send log to webhook ----------
send_log(){
    local STATUS="$1"; local STEP="$2"; local MESSAGE="$3"
    local TS="$(date -u +%FT%TZ)"
    
    # Use lock to ensure logs are sent in order
    (
        flock -x 201
        
        local PAYLOAD="$(python3 - <<PY
import json,sys
print(json.dumps({
  "run_id":"$RUN_ID",
  "host":"$HOSTNAME",
  "status":"$STATUS",
  "step":"$STEP",
  "message":"$MESSAGE",
  "timestamp":"$TS",
  "port":"$PORT",
  "domain":"$DOMAIN",
  "sequence":$STEP_COUNTER
}))
PY
)"
        
        # Send webhook with retry mechanism
        local webhook_success=false
        for i in {1..3}; do
            if [ -n "$WEBHOOK_USER" ] && [ -n "$WEBHOOK_PASS" ]; then
                if curl -sS --connect-timeout 10 --max-time 30 -u "$WEBHOOK_USER:$WEBHOOK_PASS" -X POST "$WEBHOOK_URL" -H "Content-Type: application/json" -d "$PAYLOAD"; then
                    webhook_success=true
                    break
                fi
            elif [ -n "$WEBHOOK_SECRET" ]; then
                if curl -sS --connect-timeout 10 --max-time 30 -X POST "$WEBHOOK_URL" -H "Content-Type: application/json" -H "X-Setup-Token: $WEBHOOK_SECRET" -d "$PAYLOAD"; then
                    webhook_success=true
                    break
                fi
            else
                if curl -sS --connect-timeout 10 --max-time 30 -X POST "$WEBHOOK_URL" -H "Content-Type: application/json" -d "$PAYLOAD"; then
                    webhook_success=true
                    break
                fi
            fi
            echo "WARN: webhook attempt $i failed, retrying..."
            sleep 2
        done
        
        if [ "$webhook_success" = false ]; then
            echo "ERROR: webhook failed after 3 attempts"
        fi
        
        echo "[$TS] [$STATUS] step=$STEP: $MESSAGE"
        
    ) 201>"${LOCK_FILE}.webhook"
}

# Error trap with proper cleanup
on_error(){
    local rc=$?
    local line_no=$1
    send_log "error" "fatal" "Script failed at line $line_no with exit code $rc"
    cleanup
    exit $rc
}
trap 'on_error $LINENO' ERR

# Cleanup function
cleanup() {
    rm -f "$LOCK_FILE" "${LOCK_FILE}.webhook" 2>/dev/null || true
}
trap cleanup EXIT

# -------- step functions ----------
step_init() {
    send_log "starting" "0" "Setup started (run_id=$RUN_ID)"
    return 0
}

step_install_deps() {
    send_log "step" "1" "Updating packages and installing prerequisites"
    apt-get update -y && apt-get install -y $DEPS
}

step_install_v2ray() {
    send_log "step" "2" "Installing v2ray (fhs-install-v2ray)"
    bash <(curl -fsSL https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
}

step_generate_uuid() {
    UUID="$(cat /proc/sys/kernel/random/uuid)"
    send_log "step" "3" "Generated UUID: ${UUID:0:8}..."
    return 0
}

step_configure_firewall() {
    send_log "step" "4" "Configuring firewall (allow ports 80, 443, 22, ${PORT})"
    
    # UFW configuration
    if command -v ufw >/dev/null 2>&1; then
        ufw allow 80/tcp || true
        ufw allow 443/tcp || true
        ufw allow 22/tcp || true
        ufw allow "${PORT}/tcp" || true
        ufw --force enable || true
        ufw reload || true
    fi
    
    # IPTables rules
    iptables -I INPUT -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null || true
    iptables -I INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
    iptables -I INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
    
    # NAT and forwarding rules
    iptables -t nat -C POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || true
    iptables -C FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    iptables -C FORWARD -s 0.0.0.0/0 -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -s 0.0.0.0/0 -j ACCEPT 2>/dev/null || true
    
    # Enable IP forwarding
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    
    return 0
}

step_obtain_certificate() {
    CERT_KEY_PATH=""
    CERT_FULLCHAIN_PATH=""
    CERT_SUCCESS="false"
    
    if [ "$MODE" = "auto" ] || [ "$MODE" = "stealth" ]; then
        if [ -n "$DOMAIN" ]; then
            send_log "step" "5" "Attempting to obtain TLS cert with acme.sh"
            
            # Install acme.sh if missing
            if [ ! -x "$ACME_SH" ]; then
                curl -sSfL https://get.acme.sh | sh || {
                    send_log "step" "5" "acme.sh install failed, falling back to non-TLS"
                    return 0
                }
            fi
            
            # Only proceed if acme.sh is available
            if [ -x "$ACME_SH" ]; then
                # Stop services using port 80
                systemctl stop apache2 2>/dev/null || true
                systemctl stop nginx 2>/dev/null || true
                pkill -f "python.*SimpleHTTP" 2>/dev/null || true
                
                # Wait for port to be free
                sleep 3
                
                # Register account and issue certificate
                $ACME_SH --register-account -m mehranmarandi90@gmail.com --server https://acme-v02.api.letsencrypt.org/directory || true
                
                if $ACME_SH --issue -d "$DOMAIN" --standalone --httpport 80 --force --server https://acme-v02.api.letsencrypt.org/directory; then
                    # Install certificate
                    mkdir -p /etc/ssl/v2ray-$RUN_ID
                    if $ACME_SH --installcert -d "$DOMAIN" \
                        --fullchain-file /etc/ssl/v2ray-$RUN_ID/fullchain.pem \
                        --key-file /etc/ssl/v2ray-$RUN_ID/key.pem; then
                        
                        CERT_FULLCHAIN_PATH="/etc/ssl/v2ray-$RUN_ID/fullchain.pem"
                        CERT_KEY_PATH="/etc/ssl/v2ray-$RUN_ID/key.pem"
                        
                        # Verify files exist
                        if [ -f "$CERT_FULLCHAIN_PATH" ] && [ -f "$CERT_KEY_PATH" ]; then
                            CERT_SUCCESS="true"
                            send_log "step" "5" "Certificate successfully obtained and installed"
                        fi
                    fi
                fi
            fi
        else
            send_log "step" "5" "Skipping cert issuance (DOMAIN not provided)"
        fi
    else
        send_log "step" "5" "Skipping cert issuance (mode is simple)"
    fi
    
    if [ "$CERT_SUCCESS" = "false" ]; then
        send_log "step" "5" "Certificate issuance failed or skipped, using non-TLS mode"
    fi
    
    return 0
}

step_write_config() {
    CONFIG_PATH="/usr/local/etc/v2ray/config.json"
    send_log "step" "6" "Writing v2ray config to $CONFIG_PATH"
    
    # Create log directory
    mkdir -p /var/log/v2ray
    
    if [ "$CERT_SUCCESS" = "true" ] && [ -n "$CERT_FULLCHAIN_PATH" ] && [ -n "$CERT_KEY_PATH" ]; then
        # TLS configuration
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
        send_log "step" "6" "Config written with TLS enabled"
    else
        # Non-TLS configuration
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
        send_log "step" "6" "Config written without TLS"
    fi
    
    return 0
}

step_start_service() {
    send_log "step" "7" "Enabling and starting v2ray service"
    systemctl daemon-reload
    systemctl enable v2ray
    systemctl start v2ray
    
    # Wait for service to start
    sleep 3
    
    # Verify service is running
    if systemctl is-active --quiet v2ray; then
        send_log "step" "7" "v2ray service started successfully"
    else
        send_log "error" "7" "v2ray service failed to start"
        return 1
    fi
    
    return 0
}

step_verify_listening() {
    send_log "step" "8" "Verifying v2ray is listening on port ${PORT}"
    
    # Wait a bit more for the port to be available
    sleep 5
    
    local attempts=0
    while [ $attempts -lt 10 ]; do
        if ss -ltnp 2>/dev/null | grep -q ":${PORT}[[:space:]]"; then
            send_log "step" "8" "v2ray is listening on port ${PORT}"
            return 0
        fi
        attempts=$((attempts + 1))
        sleep 2
    done
    
    send_log "error" "8" "Service not listening on port ${PORT} after 20 seconds"
    return 1
}

step_detect_ip() {
    send_log "step" "9" "Detecting public IP address"
    MYIP="$(curl -s --connect-timeout 10 --max-time 20 https://ipv4.icanhazip.com | tr -d '\n' || 
             curl -s --connect-timeout 10 --max-time 20 https://api.ipify.org || 
             curl -s --connect-timeout 10 --max-time 20 https://checkip.amazonaws.com | tr -d '\n' || true)"
    
    if [ -z "$MYIP" ]; then
        send_log "error" "9" "Failed to detect public IP"
        return 1
    fi
    
    send_log "step" "9" "Public IP detected: ${MYIP}"
    return 0
}

step_update_cloudflare() {
    if [ -n "$DOMAIN" ] && [ -n "$CF_ZONE_ID" ] && [ -n "$CF_API_TOKEN" ]; then
        send_log "step" "10" "Updating Cloudflare DNS for ${DOMAIN} (proxied=${CF_PROXIED})"
        
        GET_REC="$(curl -s --connect-timeout 15 --max-time 30 -X GET "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records?name=${DOMAIN}" \
            -H "Authorization: Bearer ${CF_API_TOKEN}" -H "Content-Type: application/json")"
        
        RECORD_ID="$(echo "$GET_REC" | jq -r '.result[0].id // empty')"
        
        if [ -n "$RECORD_ID" ] && [ "$RECORD_ID" != "null" ]; then
            curl -s --connect-timeout 15 --max-time 30 -X PUT "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records/${RECORD_ID}" \
                -H "Authorization: Bearer ${CF_API_TOKEN}" -H "Content-Type: application/json" \
                --data "{\"type\":\"A\",\"name\":\"${DOMAIN}\",\"content\":\"${MYIP}\",\"ttl\":120,\"proxied\":${CF_PROXIED}}" >/dev/null
            send_log "step" "10" "Updated existing DNS record"
        else
            curl -s --connect-timeout 15 --max-time 30 -X POST "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records" \
                -H "Authorization: Bearer ${CF_API_TOKEN}" -H "Content-Type: application/json" \
                --data "{\"type\":\"A\",\"name\":\"${DOMAIN}\",\"content\":\"${MYIP}\",\"ttl\":120,\"proxied\":${CF_PROXIED}}" >/dev/null
            send_log "step" "10" "Created new DNS record"
        fi
    else
        send_log "step" "10" "Skipping Cloudflare update (domain/zone/token missing)"
    fi
    
    return 0
}

step_generate_client_info() {
    CLIENT_FILE="/root/vpn-client-${RUN_ID}.json"
    ADDR="${DOMAIN:-$MYIP}"
    
    if [[ "$USED_MODE" == stealth* ]]; then
        SCHEME="vless://${UUID}@${ADDR}:${PORT}?type=ws&encryption=none&security=tls&host=${DOMAIN}&path=/#${HOSTNAME}"
    else
        SCHEME="vless://${UUID}@${ADDR}:${PORT}?type=tcp&encryption=none#${HOSTNAME}"
    fi
    
    send_log "step" "11" "Generated connection: ${SCHEME}"
    
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
  "cert_key":"${CERT_KEY_PATH}",
  "vless_link":"${SCHEME}"
}
print(json.dumps(obj, indent=2))
PY
    
    chmod 600 "${CLIENT_FILE}"
    send_log "step" "12" "Client info saved to ${CLIENT_FILE}"
    return 0
}

step_send_final_webhook() {
    local FINAL_PAYLOAD="$(python3 - <<PY
import json
print(json.dumps({
  "run_id":"$RUN_ID",
  "host":"$HOSTNAME",
  "status":"finished",
  "message":"Installation completed successfully",
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

    # Send final webhook with retries
    local webhook_success=false
    for i in {1..3}; do
        if [ -n "$WEBHOOK_USER" ] && [ -n "$WEBHOOK_PASS" ]; then
            if curl -sS --connect-timeout 10 --max-time 30 -u "$WEBHOOK_USER:$WEBHOOK_PASS" -X POST "$WEBHOOK_URL" -H "Content-Type: application/json" -d "$FINAL_PAYLOAD"; then
                webhook_success=true
                break
            fi
        elif [ -n "$WEBHOOK_SECRET" ]; then
            if curl -sS --connect-timeout 10 --max-time 30 -X POST "$WEBHOOK_URL" -H "Content-Type: application/json" -H "X-Setup-Token: $WEBHOOK_SECRET" -d "$FINAL_PAYLOAD"; then
                webhook_success=true
                break
            fi
        else
            if curl -sS --connect-timeout 10 --max-time 30 -X POST "$WEBHOOK_URL" -H "Content-Type: application/json" -d "$FINAL_PAYLOAD"; then
                webhook_success=true
                break
            fi
        fi
        sleep 2
    done
    
    return 0
}

# -------- main execution ----------
echo "Starting V2Ray installation with controlled execution..."

# Execute steps in order with proper control
execute_step "Initialize" step_init
execute_step "Install Dependencies" step_install_deps
execute_step "Install V2Ray" step_install_v2ray
execute_step "Generate UUID" step_generate_uuid
execute_step "Configure Firewall" step_configure_firewall
execute_step "Obtain Certificate" step_obtain_certificate
execute_step "Write Configuration" step_write_config
execute_step "Start Service" step_start_service
execute_step "Verify Listening" step_verify_listening
execute_step "Detect Public IP" step_detect_ip
execute_step "Update Cloudflare DNS" step_update_cloudflare
execute_step "Generate Client Info" step_generate_client_info
execute_step "Send Final Webhook" step_send_final_webhook

echo "=== INSTALLATION COMPLETED ==="
echo "UUID: ${UUID}"
echo "PORT: ${PORT}"
echo "IP: ${MYIP}"
echo "MODE: ${USED_MODE}"
echo "Client file: ${CLIENT_FILE:-/root/vpn-client-${RUN_ID}.json}"
