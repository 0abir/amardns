#!/usr/bin/env bash
set -euo pipefail

APP_NAME="${1:-amardns}"
ORG_NAME="${2:-personal}"
PRIMARY_REGION="sin"
SECONDARY_REGION="fra"

echo "=== Starting Zero-Touch Fresh Deployment for '${APP_NAME}' ==="

# 1. Destroy existing app if it exists
if flyctl apps list | grep -qw "${APP_NAME}"; then
  echo "[1/6] Destroying existing application '${APP_NAME}'..."
  flyctl apps destroy "${APP_NAME}" --yes
else
  echo "[1/6] No existing application '${APP_NAME}' found. Proceeding with fresh creation."
fi

# 2. Create fresh app
echo "[2/6] Creating fresh application '${APP_NAME}' under org '${ORG_NAME}'..."
flyctl apps create "${APP_NAME}" --org "${ORG_NAME}"

# 3. Allocate Dedicated IPv6 and Shared IPv4
echo "[3/6] Allocating Dedicated Anycast IPv6 and Shared IPv4..."
flyctl ips allocate-v6 --app "${APP_NAME}"
flyctl ips allocate-v4 --shared --app "${APP_NAME}"

# 4. Provision persistent storage volumes
echo "[4/6] Creating persistent storage volumes in regions: ${PRIMARY_REGION}, ${SECONDARY_REGION}..."
flyctl volumes create amardns_data --region "${PRIMARY_REGION}" --size 1 --yes --app "${APP_NAME}"
flyctl volumes create amardns_data --region "${SECONDARY_REGION}" --size 1 --yes --app "${APP_NAME}"

# 5. Deploy application to primary region
echo "[5/7] Building and deploying application to primary region (${PRIMARY_REGION})..."
flyctl deploy --ha=false --remote-only --yes --app "${APP_NAME}"

# 5b. Scale to exactly 1 machine in sin and 1 machine in fra (attaches pre-created 1GB volume in fra)
echo "[6/7] Scaling to 1 machine in ${PRIMARY_REGION} and 1 machine in ${SECONDARY_REGION} (2GB total storage)..."
flyctl scale count 2 --region "${PRIMARY_REGION},${SECONDARY_REGION}" --max-per-region 1 --yes --app "${APP_NAME}"

# 6. Import custom certificates to Fly Edge
echo "[7/7] Importing and verifying TLS certificates on Fly Edge..."
if [[ -f "certs/cert.pem" && -f "certs/key.pem" ]]; then
  for domain in "amardns.dedyn.io" "amardns.duckdns.org" "amardns.ddnsfree.com"; do
    echo "  -> Importing certificate for '${domain}'..."
    flyctl certs import "${domain}" --app "${APP_NAME}" --fullchain "certs/cert.pem" --private-key "certs/key.pem" || true
  done
fi

echo "=== Fresh Deployment Completed Successfully ==="
flyctl status --app "${APP_NAME}"
