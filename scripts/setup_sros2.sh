#!/usr/bin/env bash
# SecureNav-NEXUS: SROS2 keystore, PKI, governance + permissions generation.
# Usage: ./scripts/setup_sros2.sh [keystore_dir]
set -euo pipefail

KEYSTORE="${1:-$(pwd)/keystore}"
SECRETS_DIR="$(pwd)/secrets"
ENCLAVES=(/nexus/nav2 /nexus/vision /nexus/brain /nexus/ids /nexus/hsm)
POLICY_DIR="$(pwd)/security"

log() { printf '[sros2] %s\n' "$*"; }
command -v ros2 >/dev/null || { log "ros2 not found. Source /opt/ros/iron/setup.bash first."; exit 1; }

umask 077
mkdir -p "$KEYSTORE" "$SECRETS_DIR"

if [[ ! -d "$KEYSTORE/public" ]]; then
  log "Creating keystore at $KEYSTORE"
  ros2 security create_keystore "$KEYSTORE"
fi

for enclave in "${ENCLAVES[@]}"; do
  if [[ -d "$KEYSTORE/enclaves${enclave}" ]]; then
    log "Enclave $enclave exists, skipping"
    continue
  fi
  log "Creating enclave $enclave"
  ros2 security create_enclave "$KEYSTORE" "$enclave"
done

# Overwrite generated governance/permissions with the hardened NEXUS templates, then re-sign
# them with the permissions CA so DDS-Security accepts them.
log "Installing NEXUS governance and permissions templates"
cp "$POLICY_DIR/governance.xml" "$KEYSTORE/governance.xml"
openssl smime -sign -in "$KEYSTORE/governance.xml" \
  -text -out "$KEYSTORE/public/governance.p7s" \
  -signer "$KEYSTORE/public/permissions_ca.cert.pem" \
  -inkey "$KEYSTORE/private/permissions_ca.key.pem"

for enclave in "${ENCLAVES[@]}"; do
  dest="$KEYSTORE/enclaves${enclave}"
  cp "$KEYSTORE/public/governance.p7s" "$dest/governance.p7s"
  name="$(basename "$enclave")"
  python3 "$(dirname "$0")/render_permissions.py" "$POLICY_DIR/permissions.xml" "$name" \
    > "$dest/permissions.xml"
  openssl smime -sign -in "$dest/permissions.xml" \
    -text -out "$dest/permissions.p7s" \
    -signer "$dest/cert.pem" -inkey "$KEYSTORE/private/permissions_ca.key.pem" 2>/dev/null \
    || openssl smime -sign -in "$dest/permissions.xml" -text -out "$dest/permissions.p7s" \
         -signer "$KEYSTORE/public/permissions_ca.cert.pem" \
         -inkey "$KEYSTORE/private/permissions_ca.key.pem"
  log "Signed permissions for $enclave"
done

# Runtime secrets for compose (random, never committed)
[[ -f "$SECRETS_DIR/hsm_pin.txt" ]] || head -c 24 /dev/urandom | base64 > "$SECRETS_DIR/hsm_pin.txt"
[[ -f "$SECRETS_DIR/dashboard_token.txt" ]] || head -c 32 /dev/urandom | base64 | tr -d '=+/' > "$SECRETS_DIR/dashboard_token.txt"

[[ -f "$SECRETS_DIR/groq_api_key.txt" ]] || : > "$SECRETS_DIR/groq_api_key.txt"   # paste your free Groq key here

log "Done. Keystore: $KEYSTORE"
log "Dashboard token: $SECRETS_DIR/dashboard_token.txt"
