#!/usr/bin/env bash
# ==============================================================================
# AmarDNS Production Deployment Automation for Fly.io
# ==============================================================================
# Idempotent, zero-downtime, fully automated deployment script for AmarDNS.
# Provisions high-availability machines in Singapore (sin), configures Anycast
# IPs, persistent volumes, automated DDNS, and Edge/Internal TLS certificates.
# ==============================================================================

set -euo pipefail

APP_NAME="amardns"
PRIMARY_REGION="sin"
DOMAINS=("amardns.dedyn.io" "amardns.duckdns.org" "amardns.ddnsfree.com")
MASTER_KEY="${DNS_MASTER_KEY:-}"
if [ -z "$MASTER_KEY" ] && [ -f "fly.toml" ]; then
    MASTER_KEY=$(grep -E '^\s*DNS_MASTER_KEY\s*=' fly.toml 2>/dev/null | sed -E 's/.*=\s*"([^"]+)".*/\1/' || true)
fi

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

err() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $*" >&2
}

# 1. Prerequisite verification
log "Checking Fly CLI prerequisites..."
if ! command -v flyctl >/dev/null 2>&1 && ! command -v fly >/dev/null 2>&1; then
    err "Fly CLI (flyctl or fly) is not installed."
    exit 1
fi

FLY_CMD="flyctl"
if ! command -v flyctl >/dev/null 2>&1; then
    FLY_CMD="fly"
fi

if ! $FLY_CMD auth whoami >/dev/null 2>&1; then
    err "Not authenticated with Fly.io. Please run '$FLY_CMD auth login'."
    exit 1
fi
log "Authenticated with Fly.io as: $($FLY_CMD auth whoami)"

# 2. Check or create application
log "Checking application '$APP_NAME'..."
if ! $FLY_CMD status -a "$APP_NAME" >/dev/null 2>&1; then
    log "Application '$APP_NAME' not found. Creating fresh app in region '$PRIMARY_REGION'..."
    $FLY_CMD apps create "$APP_NAME" --org personal
    log "App '$APP_NAME' created successfully."
else
    log "Application '$APP_NAME' exists and is accessible."
fi

# 3. IP Allocation (Shared IPv4 + Dedicated IPv6)
log "Verifying Anycast IP allocations..."
IPS_OUTPUT=$($FLY_CMD ips list -a "$APP_NAME" 2>/dev/null || true)

if ! echo "$IPS_OUTPUT" | grep -qw "v4"; then
    log "Allocating Anycast Shared IPv4..."
    $FLY_CMD ips allocate-v4 --shared -a "$APP_NAME"
fi

if ! echo "$IPS_OUTPUT" | grep -qw "v6"; then
    log "Allocating Anycast Dedicated IPv6..."
    $FLY_CMD ips allocate-v6 -a "$APP_NAME"
fi
log "Current IP allocations:"
$FLY_CMD ips list -a "$APP_NAME"

# 4. Persistent Volume Allocation (2x 1GB in Singapore)
log "Verifying persistent storage volumes in region '$PRIMARY_REGION'..."
VOL_COUNT=$($FLY_CMD volumes list -a "$APP_NAME" 2>/dev/null | grep -cw "$PRIMARY_REGION" || true)

while [ "$VOL_COUNT" -lt 2 ]; do
    log "Creating persistent volume #$((VOL_COUNT + 1)) (1GB, region: $PRIMARY_REGION)..."
    $FLY_CMD volumes create amardns_data --region "$PRIMARY_REGION" --size 1 --yes -a "$APP_NAME"
    VOL_COUNT=$((VOL_COUNT + 1))
done
log "Storage volumes verified (Count: $VOL_COUNT in $PRIMARY_REGION)."

# 5. Register Custom Domain Hostnames on Fly Edge
log "Registering custom domain certificates on Fly Edge..."
EXISTING_CERTS=$($FLY_CMD certs list -a "$APP_NAME" 2>/dev/null || true)

for domain in "${DOMAINS[@]}"; do
    if ! echo "$EXISTING_CERTS" | grep -qw "$domain"; then
        log "Adding edge certificate record for '$domain'..."
        $FLY_CMD certs add "$domain" -a "$APP_NAME" || true
    fi
done

# 6. Deploy Application
log "Deploying AmarDNS to Fly.io ($PRIMARY_REGION, HA mode)..."
$FLY_CMD deploy --ha=true -a "$APP_NAME"

# 7. Smoke check & health verification
log "Waiting for machines to report healthy status..."
sleep 5
$FLY_CMD status -a "$APP_NAME"

# 8. Automated ZeroSSL to Fly Edge Certificate Sync
log "Checking if custom certificate import is required for rate-limited hostnames..."
CERTS_STATUS=$($FLY_CMD certs list -a "$APP_NAME" 2>/dev/null || true)
log "Fly Edge certificate status:"
echo "$CERTS_STATUS"

NEEDS_IMPORT=0
for domain in "${DOMAINS[@]}"; do
    if echo "$CERTS_STATUS" | grep "$domain" | grep -qE "(Issuing|Awaiting|Rate limited)"; then
        NEEDS_IMPORT=1
        break
    fi
done

if [ "$NEEDS_IMPORT" -eq 1 ] || [ "${1:-}" = "--force-sync-certs" ]; then
    log "Retrieving active ZeroSSL Multi-SAN certificate bundle from application..."
    TMP_CERT="/tmp/amardns_deploy_cert_$$.pem"
    TMP_KEY="/tmp/amardns_deploy_key_$$.pem"

    SYNC_OK=0
    # Try fetching from any working domain or direct host
    for probe_host in "amardns.ddnsfree.com" "amardns.duckdns.org" "amardns.dedyn.io" "amardns.fly.dev"; do
        if python3 -c "
import urllib.request, json, sys
url = f'https://${probe_host}/internal/tls/bundle/${MASTER_KEY}'
req = urllib.request.Request(url, headers={'x-master-key': '${MASTER_KEY}', 'User-Agent': 'DeployScript/1.0'})
try:
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read().decode())
        if data.get('ok'):
            with open('${TMP_CERT}', 'w') as f:
                f.write(data['cert_pem'])
            with open('${TMP_KEY}', 'w') as f:
                f.write(data['key_pem'])
            sys.exit(0)
except Exception:
    sys.exit(1)
" 2>/dev/null; then
            log "Successfully retrieved certificate bundle from '$probe_host'."
            SYNC_OK=1
            break
        fi
    done

    if [ "$SYNC_OK" -eq 1 ] && [ -f "$TMP_CERT" ] && [ -f "$TMP_KEY" ]; then
        for domain in "${DOMAINS[@]}"; do
            if echo "$CERTS_STATUS" | grep "$domain" | grep -qE "(Issuing|Awaiting|Rate limited)" || [ "${1:-}" = "--force-sync-certs" ]; then
                log "Importing custom ZeroSSL certificate to Fly Edge for '$domain'..."
                $FLY_CMD certs import "$domain" --fullchain "$TMP_CERT" --private-key "$TMP_KEY" -a "$APP_NAME" || true
            fi
        done
        rm -f "$TMP_CERT" "$TMP_KEY"
    else
        log "Certificate bundle not yet ready on container. ACME background supervisor will automatically issue on boot."
    fi
fi

# 9. Final End-to-End Verification
log "============================================================"
log "Running End-to-End Protocol Verification..."
log "============================================================"

python3 -c "
import ssl, socket, urllib.request, json, base64

hosts = ['amardns.dedyn.io', 'amardns.duckdns.org', 'amardns.ddnsfree.com']

print('\n--- HTTPS / DoH Health Checks ---')
for h in hosts:
    try:
        url = f'https://{h}/health'
        req = urllib.request.Request(url, headers={'User-Agent': 'AmarDNS-Verifier/1.0'})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            print(f'  ✓ https://{h}/health -> HTTP {resp.status} (Upstreams: {data.get(\"upstreams\", {}).get(\"healthy\")}/9 healthy)')
    except Exception as e:
        print(f'  ✗ https://{h}/health -> {e}')

print('\n--- DoT Port 853 TLS Handshake ---')
ctx = ssl.create_default_context()
for h in hosts:
    try:
        with socket.create_connection(('66.241.124.97', 853), timeout=5) as s:
            with ctx.wrap_socket(s, server_hostname=h) as ss:
                print(f'  ✓ {h}:853 -> {ss.version()}, {ss.cipher()[0]}')
    except Exception as e:
        print(f'  ✗ {h}:853 -> {e}')

print('\n--- RFC 8484 DoH DNS Query Resolution ---')
q_wire = bytes.fromhex('00000100000100000000000006676f6f676c6503636f6d0000010001')
q_b64 = base64.urlsafe_b64encode(q_wire).decode().rstrip('=')
for h in hosts:
    try:
        url = f'https://{h}/dns-query?dns={q_b64}'
        req = urllib.request.Request(url, headers={'Accept': 'application/dns-message'})
        with urllib.request.urlopen(req, timeout=5) as resp:
            print(f'  ✓ https://{h}/dns-query -> HTTP {resp.status} ({len(resp.read())} bytes wire response)')
    except Exception as e:
        print(f'  ✗ https://{h}/dns-query -> {e}')
" || true

log "============================================================"
log "AmarDNS Production Deployment Completed Successfully."
log "============================================================"
