#!/usr/bin/env bash
set -euo pipefail

APP_NAME="${1:-amardns}"
ORG_NAME="${2:-personal}"
PRIMARY_REGION="sin"
SECONDARY_REGION="fra"

echo "=== Starting Zero-Touch Fresh Deployment for '${APP_NAME}' ==="

# 1. Destroy existing app if it exists
if flyctl apps list | grep -qw "${APP_NAME}"; then
  echo "[1/7] Destroying existing application '${APP_NAME}'..."
  flyctl apps destroy "${APP_NAME}" --yes
else
  echo "[1/7] No existing application '${APP_NAME}' found. Proceeding with fresh creation."
fi

# 2. Create fresh app
echo "[2/7] Creating fresh application '${APP_NAME}' under org '${ORG_NAME}'..."
flyctl apps create "${APP_NAME}" --org "${ORG_NAME}"

# 3. Allocate Dedicated IPv6 and Shared IPv4 (prioritizing 0, then 5)
echo "[3/7] Allocating Dedicated Anycast IPv6..."
flyctl ips allocate-v6 --app "${APP_NAME}"

get_shared_ip() {
  flyctl ips list --json --app "${APP_NAME}" | python3 -c "import sys, json; ips = json.load(sys.stdin); print(next((i['Address'] for i in ips if i.get('Type') == 'shared_v4'), ''))"
}

echo "Allocating Shared IPv4 (prioritizing ending with 0, or ending with 5)..."
FOUND_IP=""
EXISTING_IP=$(get_shared_ip)
if [ -n "${EXISTING_IP}" ]; then
  EXISTING_DIGIT="${EXISTING_IP: -1}"
  if [ "${EXISTING_DIGIT}" = "0" ]; then
    echo "  -> Existing shared IP already satisfies priority target (ends in 0): ${EXISTING_IP}"
    FOUND_IP="${EXISTING_IP}"
  else
    echo "  -> Releasing existing non-priority IP: ${EXISTING_IP}"
    flyctl ips release "${EXISTING_IP}" --app "${APP_NAME}" || true
    sleep 1
  fi
fi

if [ -z "${FOUND_IP}" ]; then
  for attempt in $(seq 1 20); do
    echo "  -> IP allocation attempt ${attempt}/20 (seeking ending in 0)..."
    flyctl ips allocate-v4 --shared --app "${APP_NAME}"
    CURRENT_IP=$(get_shared_ip)
    LAST_DIGIT="${CURRENT_IP: -1}"
    echo "     Allocated shared IP: ${CURRENT_IP} (ends in '${LAST_DIGIT}')"
    if [ "${LAST_DIGIT}" = "0" ]; then
      echo "  -> SUCCESS: Priority target achieved! IPv4 ends in 0: ${CURRENT_IP}"
      FOUND_IP="${CURRENT_IP}"
      break
    fi
    flyctl ips release "${CURRENT_IP}" --app "${APP_NAME}"
    sleep 1
  done
fi

if [ -z "${FOUND_IP}" ]; then
  echo "  -> Priority 0 not acquired after 20 attempts. Seeking either 0 or 5..."
  for attempt in $(seq 21 40); do
    echo "  -> IP allocation attempt ${attempt}/40 (seeking 0 or 5)..."
    flyctl ips allocate-v4 --shared --app "${APP_NAME}"
    CURRENT_IP=$(get_shared_ip)
    LAST_DIGIT="${CURRENT_IP: -1}"
    echo "     Allocated shared IP: ${CURRENT_IP} (ends in '${LAST_DIGIT}')"
    if [ "${LAST_DIGIT}" = "0" ] || [ "${LAST_DIGIT}" = "5" ]; then
      echo "  -> SUCCESS: Qualified IPv4 achieved! ${CURRENT_IP}"
      FOUND_IP="${CURRENT_IP}"
      break
    fi
    flyctl ips release "${CURRENT_IP}" --app "${APP_NAME}"
    sleep 1
  done
fi

# 4. Provision persistent storage volumes
echo "[4/7] Creating persistent storage volumes in regions: ${PRIMARY_REGION}, ${SECONDARY_REGION}..."
flyctl volumes create amardns_data --region "${PRIMARY_REGION}" --size 1 --yes --app "${APP_NAME}"
flyctl volumes create amardns_data --region "${SECONDARY_REGION}" --size 1 --yes --app "${APP_NAME}"

# 5. Deploy application to primary region
echo "[5/7] Building and deploying application to primary region (${PRIMARY_REGION})..."
flyctl deploy --ha=false --remote-only --yes --app "${APP_NAME}"

# 6. Clone to secondary region (Frankfurt)
echo "[6/7] Attaching pre-provisioned 1GB volume in ${SECONDARY_REGION} and cloning machine..."
PRIMARY_ID=$(flyctl machines list --app "${APP_NAME}" --json | grep -o '"id":"[^"]*' | head -n1 | cut -d'"' -f4)
FRA_VOL_ID=$(flyctl volumes list --app "${APP_NAME}" | grep "${SECONDARY_REGION}" | awk '{print $1}')
flyctl machine clone "${PRIMARY_ID}" --region "${SECONDARY_REGION}" --attach-volume "${FRA_VOL_ID}:/data" --app "${APP_NAME}"

# 6. Import custom certificates to Fly Edge
echo "[7/7] Importing and verifying TLS certificates on Fly Edge..."
if [[ -f "certs/cert.pem" && -f "certs/key.pem" ]]; then
  DOMAINS=$(openssl x509 -in certs/cert.pem -text -noout | grep -A1 "Subject Alternative Name:" | tail -n1 | tr ',' '\n' | grep "DNS:" | sed 's/.*DNS://' | tr -d ' ')
  for domain in $DOMAINS; do
    echo "  -> Importing certificate for '${domain}'..."
    flyctl certs import "${domain}" --app "${APP_NAME}" --fullchain "certs/cert.pem" --private-key "certs/key.pem" || true
  done
fi

echo "=== Fresh Deployment Completed Successfully ==="
flyctl status --app "${APP_NAME}"
