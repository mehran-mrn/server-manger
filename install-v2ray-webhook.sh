#!/usr/bin/env bash
# install-v2ray-webhook.sh (fixed version)
# Usage example:
# sudo ./install-v2ray-webhook.sh \
#   --webhook-url "https://n8n.example/webhook/receive" \
#   --webhook-user "botuser" --webhook-pass "botpass" \
#   --domain "s1.oiix.ir" --cf-zone-id "ZONEID" --cf-api-token "CFTOKEN" \
#   --cf-proxied "false" --port 16823

# Prevent interactive prompts and fix terminal issues
export DEBIAN_FRONTEND=noninteractive
export APT_LISTCHANGES_FRONTEND=none
export TERM=linux

# Strict error handling
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
DEPS="curl wget unzip ca-certificates python3 jq openssl socat cron iptables"
ACME_SH="/root/.acme.sh/acme.sh"

# Initialize certificate variables to avoid unbound variable errors
CERT_KEY_PATH=""
CERT_FULLCHAIN_PATH=""
CERT_SUCCESS="false"
UUID=""
USED_MODE="simple"
MYIP=""
SCHEME=""
CLIENT_FILE=""

# Lock files for synchronization
LOCK_FILE="/tmp/v2ray-install-$$.lock"
WEBHOOK_LOCK="/tmp/v2ray-webhook-$$.lock"
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

# Validation
if [ -z "$WEBHOOK_URL" ]; then
  echo "ERROR: --webhook-url is required"; exit 1
fi
if [ "$EUID" -ne 0 ]; then echo "ERROR: run as root"; exit 1; fi
if [ -z "$RUN_ID" ]; then RUN_ID="$(date +%s)-$$"; fi

# Fix hostname resolution issue
HOSTNAME="$(hostname 2>/dev/null || echo "server-$$")"
if ! grep -q "127.0.0.1.*$HOSTNAME" /etc/hosts; then
    echo "127.0.0.1 $HOSTNAME" >> /etc/hosts
fi

# -------- helper: send log to webhook ----------
send_log(){
    local STATUS="$1"; local STEP="$2"; local MESSAGE="$3"
    local TS="$(date -u +%FT%TZ)"
    
    # Use lock to ensure logs are sent in order
    (
        flock -x 200
        
        STEP_COUNTER=$((STEP_COUNTER + 1))
        
        local PAYLOAD
        PAYLOAD="$(python3 - <<PY
import json
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
                if curl -sS --connect-timeout 15 --max-time 45 -u "$WEBHOOK_USER:$WEBHOOK_PASS" -X POST "$WEBHOOK_URL" -H "Content-Type: application/json" -d "$PAYLOAD" >/dev/null 2>&1; then
                    webhook_success=true
                    break
                fi
            elif [ -n "$WEBHOOK_SECRET" ]; then
                if curl -sS --connect-timeout 15 --max-time 45 -X POST "$WEBHOOK_URL" -H "Content-Type: application/json" -H "X-Setup-Token: $WEBHOOK_SECRET" -d "$PAYLOAD" >/dev/null 2>&1; then
                    webhook_success=true
                    break
                fi
            else
                if curl -sS --connect-timeout 15 --max-time 45 -X POST "$WEBHOOK_URL" -H "Content-Type: application/json" -d "$PAYLOAD" >/dev/null 2>&1; then
                    webhook_success=true
                    break
                fi
            fi
            
            if [ $i -lt 3 ]; then
                sleep 2
            fi
        done
        
        echo "[$TS] [$STATUS] step=$STEP: $MESSAGE"
        
        if [ "$webhook_success" = false ]; then
            echo "WARN: webhook failed after 3 attempts"
        fi
        
    ) 200>"$WEBHOOK_LOCK"
}

# Error trap with proper cleanup
on_error(){
    local rc=$?
    local line_no=${1:-"unknown"}
    send_log "error" "fatal" "Script failed at line $line_no with exit code $rc" || true
    cleanup
    exit $rc
}
trap 'on_error $LINENO' ERR

# Cleanup function
cleanup() {
    rm -f "$LOCK_FILE" "$WEBHOOK_LOCK" 2>/dev/null || true
}
trap cleanup EXIT

# -------- execution wrapper ----------
execute_step() {
    local step_name="$1"
    local step_func="$2"
    
    (
        flock -x 201
        echo "Starting: $step_name"
        
        if $step_func; then
            echo "Completed: $step_name"
            return 0
        else
            echo "Failed: $step_name"
            return 1
        fi
        
    ) 201>"$LOCK_FILE"
}

# -------- step functions ----------
step_init() {
    send_log "starting" "init" "Setup started (run_id=$RUN_ID, hostname=$HOSTNAME)"
    return 0
}

step_system_prepare() {
    send_log "step" "system" "Preparing system environment"
    
    # Update package cache
    apt-get update -y >/dev/null 2>&1
    
    # Install dependencies with retry
    for i in {1..3}; do
        if apt-get install -y $DEPS >/dev/null 2>&1; then
            send_log "step" "system" "System packages installed successfully"
            return 0
        fi
        if [ $i -lt 3 ]; then
            sleep 5
            apt-get update -y >/dev/null 2>&1
        fi
    done
    
    send_log "error" "system" "Failed to install system packages after 3 attempts"
    return 1
}

step_install_v2ray() {
    send_log "step" "v2ray" "Installing v2ray (fhs-install-v2ray)"
    
    for i in {1..3}; do
        if bash <(curl -fsSL https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh) >/dev/null 2>&1; then
            send_log "step" "v2ray" "v2ray installed successfully"
            return 0
        fi
        if [ $i -lt 3 ]; then
            sleep 5
        fi
    done
    
    send_log "error" "v2ray" "Failed to install v2ray after 3 attempts"
    return 1
}

step_generate_uuid() {
    UUID="$(cat /proc/sys/kernel/random/uuid)"
    send_log "step" "uuid" "Generated UUID: ${UUID:0:8}...${UUID: -4}"
    return 0
}

step_configure_firewall() {
    send_log "step" "firewall" "Configuring firewall rules"
    
    # Configure UFW if available
    if command -v ufw >/dev/null 2>&1; then
        ufw --force reset >/dev/null 2>&1 || true
        ufw allow 22/tcp >/dev/null 2>&1 || true
        ufw allow 80/tcp >/dev/null 2>&1 || true
        ufw allow 443/tcp >/dev/null 2>&1 || true
        ufw allow "${PORT}/tcp" >/dev/null 2>&1 || true
        echo "y" | ufw enable >/dev/null 2>&1 || true
    fi
    
    # Configure iptables
    iptables -I INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || true
    iptables -I INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
    iptables -I INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
    iptables -I INPUT -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null || true
    
    # Enable IP forwarding
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi
    
    send_log "step" "firewall" "Firewall configured (allowed ports: 22, 80, 443, $PORT)"
    return 0
}

step_handle_certificate() {
    CERT_SUCCESS="false"
    
    if [ "$MODE" = "auto" ] || [ "$MODE" = "stealth" ]; then
        if [ -n "$DOMAIN" ]; then
            send_log "step" "cert" "Checking certificate requirements for domain: $DOMAIN"
            
            # Check rate limit first by trying to get existing cert info
            if [ -d "/root/.acme.sh/${DOMAIN}_ecc" ]; then
                CERT_FULLCHAIN_PATH="/root/.acme.sh/${DOMAIN}_ecc/fullchain.cer"
                CERT_KEY_PATH="/root/.acme.sh/${DOMAIN}_ecc/${DOMAIN}.key"
                
                if [ -f "$CERT_FULLCHAIN_PATH" ] && [ -f "$CERT_KEY_PATH" ]; then
                    # Check if cert is still valid (more than 7 days)
                    if openssl x509 -in "$CERT_FULLCHAIN_PATH" -noout -checkend 604800 2>/dev/null; then
                        CERT_SUCCESS="true"
                        send_log "step" "cert" "Using existing valid certificate"
                        return 0
                    fi
                fi
            fi
            
            # Try to get new certificate if no valid one exists
            send_log "step" "cert" "Attempting to obtain new TLS certificate"
            
            # Install acme.sh if not present
            if [ ! -x "$ACME_SH" ]; then
                if curl -sSfL https://get.acme.sh | sh >/dev/null 2>&1; then
                    send_log "step" "cert" "acme.sh installed"
                else
                    send_log "step" "cert" "Failed to install acme.sh, skipping TLS"
                    return 0
                fi
            fi
            
            # Only try if acme.sh is available
            if [ -x "$ACME_SH" ]; then
                # Stop services that might use port 80
                systemctl stop apache2 2>/dev/null || true
                systemctl stop nginx 2>/dev/null || true
                systemctl stop lighttpd 2>/dev/null || true
                pkill -f ":80" 2>/dev/null || true
                
                sleep 5
                
                # Try to issue certificate (suppress rate limit errors)
                if $ACME_SH --issue -d "$DOMAIN" --standalone --httpport 80 --server https://acme-v02.api.letsencrypt.org/directory >/dev/null 2>&1; then
                    CERT_FULLCHAIN_PATH="/root/.acme.sh/${DOMAIN}_ecc/fullchain.cer"
                    CERT_KEY_PATH="/root/.acme.sh/${DOMAIN}_ecc/${DOMAIN}.key"
                    
                    if [ -f "$CERT_FULLCHAIN_PATH" ] && [ -f "$CERT_KEY_PATH" ]; then
                        CERT_SUCCESS="true"
                        send_log "step" "cert" "New certificate obtained successfully"
                    fi
                else
                    send_log "step" "cert" "Certificate issuance failed (likely rate limited), continuing without TLS"
                fi
            fi
        else
            send_log "step" "cert" "No domain provided, skipping certificate"
        fi
    else
        send_log "step" "cert" "Mode is simple, skipping certificate"
    fi
    
    if [ "$CERT_SUCCESS" = "false" ]; then
        CERT_FULLCHAIN_PATH=""
        CERT_KEY_PATH=""
        send_log "step" "cert" "Will use non-TLS configuration"
    fi
    
    return 0
}

step_write_config() {
    local CONFIG_PATH="/usr/local/etc/v2ray/config.json"
    send_log "step" "config" "Writing v2ray configuration"
    
    # Create directories
    mkdir -p /var/log/v2ray
    mkdir -p "$(dirname "$CONFIG_PATH")"
    
    # Determine configuration type
    if [ "$CERT_SUCCESS" = "true" ] && [ -n "$CERT_FULLCHAIN_PATH" ] && [ -n "$CERT_KEY_PATH" ]; then
        USED_MODE="stealth (vless+ws+tls)"
        
        cat > "$CONFIG_PATH" <<EOF
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
      "clients": [{"id":"${UUID}","level":0,"email":"client@example.com"}],
      "decryption":"none"
    },
    "streamSettings": {
      "network": "ws",
      "security": "tls",
      "tlsSettings": {
        "certificates": [{
          "certificateFile": "${CERT_FULLCHAIN_PATH}",
          "keyFile": "${CERT_KEY_PATH}"
        }]
      },
      "wsSettings": { "path": "/" }
    }
  }],
  "outbounds": [{"protocol":"freedom"}]
}
EOF
        send_log "step" "config" "Configuration written with TLS support"
    else
        USED_MODE="simple (vless+tcp+none)"
        
        cat > "$CONFIG_PATH" <<EOF
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
      "clients": [{"id":"${UUID}","level":0,"email":"client@example.com"}],
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
        send_log "step" "config" "Configuration written without TLS (fallback mode)"
    fi
    
    return 0
}

step_start_service() {
    send_log "step" "service" "Starting v2ray service"
    
    systemctl daemon-reload >/dev/null 2>&1
    systemctl enable v2ray >/dev/null 2>&1
    
    for i in {1..3}; do
        if systemctl start v2ray >/dev/null 2>&1 && sleep 3 && systemctl is-active --quiet v2ray; then
            send_log "step" "service" "v2ray service started successfully"
            
            # Verify port is listening
            local attempts=0
            while [ $attempts -lt 10 ]; do
                if ss -ltnp 2>/dev/null | grep -q ":${PORT}[[:space:]]"; then
                    send_log "step" "service" "v2ray is listening on port $PORT"
                    return 0
                fi
                attempts=$((attempts + 1))
                sleep 2
            done
            
            send_log "error" "service" "Service started but not listening on port $PORT"
            return 1
        fi
        
        if [ $i -lt 3 ]; then
            systemctl stop v2ray >/dev/null 2>&1 || true
            sleep 5
        fi
    done
    
    send_log "error" "service" "Failed to start v2ray service after 3 attempts"
    return 1
}

step_network_setup() {
    send_log "step" "network" "Setting up network configuration"
    
    # Get public IP
    for i in {1..3}; do
        MYIP="$(curl -s --connect-timeout 10 --max-time 20 https://ipv4.icanhazip.com 2>/dev/null | tr -d '\n' || 
                curl -s --connect-timeout 10 --max-time 20 https://api.ipify.org 2>/dev/null || 
                curl -s --connect-timeout 10 --max-time 20 https://checkip.amazonaws.com 2>/dev/null | tr -d '\n' || true)"
        
        if [ -n "$MYIP" ]; then
            send_log "step" "network" "Public IP detected: $MYIP"
            break
        fi
        
        if [ $i -lt 3 ]; then
            sleep 5
        fi
    done
    
    if [ -z "$MYIP" ]; then
        send_log "error" "network" "Failed to detect public IP address"
        return 1
    fi
    
    return 0
}

step_cloudflare_dns() {
    if [ -n "$DOMAIN" ] && [ -n "$CF_ZONE_ID" ] && [ -n "$CF_API_TOKEN" ]; then
        send_log "step" "dns" "Updating Cloudflare DNS record for $DOMAIN"
        
        # Get existing record
        local GET_REC
        GET_REC="$(curl -s --connect-timeout 15 --max-time 30 \
            -X GET "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records?name=${DOMAIN}" \
            -H "Authorization: Bearer ${CF_API_TOKEN}" \
            -H "Content-Type: application/json" 2>/dev/null)" || true
        
        local RECORD_ID
        RECORD_ID="$(echo "$GET_REC" | jq -r '.result[0].id // empty' 2>/dev/null || true)"
        
        if [ -n "$RECORD_ID" ] && [ "$RECORD_ID" != "null" ] && [ "$RECORD_ID" != "empty" ]; then
            # Update existing record
            if curl -s --connect-timeout 15 --max-time 30 \
                -X PUT "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records/${RECORD_ID}" \
                -H "Authorization: Bearer ${CF_API_TOKEN}" \
                -H "Content-Type: application/json" \
                --data "{\"type\":\"A\",\"name\":\"${DOMAIN}\",\"content\":\"${MYIP}\",\"ttl\":120,\"proxied\":${CF_PROXIED}}" \
                >/dev/null 2>&1; then
                send_log "step" "dns" "Updated existing DNS record: $DOMAIN -> $MYIP"
            else
                send_log "step" "dns" "Failed to update DNS record"
            fi
        else
            # Create new record
            if curl -s --connect-timeout 15 --max-time 30 \
                -X POST "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records" \
                -H "Authorization: Bearer ${CF_API_TOKEN}" \
                -H "Content-Type: application/json" \
                --data "{\"type\":\"A\",\"name\":\"${DOMAIN}\",\"content\":\"${MYIP}\",\"ttl\":120,\"proxied\":${CF_PROXIED}}" \
                >/dev/null 2>&1; then
                send_log "step" "dns" "Created new DNS record: $DOMAIN -> $MYIP"
            else
                send_log "step" "dns" "Failed to create DNS record"
            fi
        fi
    else
        send_log "step" "dns" "Skipping Cloudflare DNS (parameters missing)"
    fi
    
    return 0
}

step_finalize() {
    send_log "step" "finalize" "Finalizing installation"
    
    # Generate connection details
    local ADDR="${DOMAIN:-$MYIP}"
    if [[ "$USED_MODE" == *"tls"* ]]; then
        SCHEME="vless://${UUID}@${ADDR}:${PORT}?type=ws&encryption=none&security=tls&host=${DOMAIN}&path=/#${HOSTNAME}"
    else
        SCHEME="vless://${UUID}@${ADDR}:${PORT}?type=tcp&encryption=none#${HOSTNAME}"
    fi
    
    # Create client info file
    CLIENT_FILE="/root/vpn-client-${RUN_ID}.json"
    python3 - <<PY > "${CLIENT_FILE}"
import json
obj = {
  "run_id": "$RUN_ID",
  "host": "$HOSTNAME",
  "ip": "$MYIP",
  "port": "$PORT",
  "uuid": "$UUID",
  "mode": "$USED_MODE",
  "domain": "$DOMAIN",
  "vless_link": "$SCHEME",
  "timestamp": "$(date -u +%FT%TZ)"
}
print(json.dumps(obj, indent=2))
PY
    
    chmod 600 "$CLIENT_FILE"
    send_log "step" "finalize" "Client configuration saved to $CLIENT_FILE"
    
    # Send final status
    send_log "finished" "complete" "Installation completed successfully - $SCHEME"
    
    return 0
}

# -------- main execution ----------
echo "Starting V2Ray installation with improved error handling..."

# Execute all steps
execute_step "Initialize" step_init
execute_step "Prepare System" step_system_prepare  
execute_step "Install V2Ray" step_install_v2ray
execute_step "Generate UUID" step_generate_uuid
execute_step "Configure Firewall" step_configure_firewall
execute_step "Handle Certificate" step_handle_certificate
execute_step "Write Configuration" step_write_config
execute_step "Start Service" step_start_service
execute_step "Setup Network" step_network_setup
execute_step "Update DNS" step_cloudflare_dns
execute_step "Finalize" step_finalize

echo ""
echo "=== INSTALLATION COMPLETED ==="
echo "UUID: ${UUID}"
echo "PORT: ${PORT}"
echo "MODE: ${USED_MODE}"
echo "IP: ${MYIP}"
echo "CONNECTION: ${SCHEME}"
echo "CONFIG FILE: ${CLIENT_FILE}"
echo ""
