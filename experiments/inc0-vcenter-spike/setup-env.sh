#!/usr/bin/env bash
# ADR-0001 Inc 0 spike — interactive .env setup.
# Run this YOURSELF in your terminal. The password is read with `read -s`
# (no echo, no shell history) and written straight to .env (chmod 600).
set -euo pipefail
cd "$(dirname "$0")"

echo "── Inc 0 spike · vCenter connection setup ──────────────────────"
read -r -p "vCenter URL   [https://vcenter.lab.local]: " VC_URL
VC_URL="${VC_URL:-https://vcenter.lab.local}"
read -r -p "vCenter user  [svc-tracenium@vsphere.local]: " VC_USER
VC_USER="${VC_USER:-svc-tracenium@vsphere.local}"
read -r -s -p "vCenter password (not echoed): " VC_PASS
echo
read -r -p "Skip TLS verification? (lab) [Y/n]: " INSEC
INSEC="${INSEC:-Y}"

umask 077
cat > .env <<EOF
VC_URL=${VC_URL}
VC_USER=${VC_USER}
VC_PASS=${VC_PASS}
EOF
case "$INSEC" in
  [Nn]*) echo "VC_INSECURE=false" >> .env ;;
  *)     echo "VC_INSECURE=true"  >> .env ;;
esac
cat >> .env <<'EOF'
TARGET_VM_UUID=
TARGET_VM_NAME=
SNAP_QUIESCE=true
SNAP_MEMORY=false
SPIKE_CREATE=false
SPIKE_REVERT=false
EOF
chmod 600 .env
unset VC_PASS

echo
echo "✅ .env written (chmod 600, git-ignored)."
echo "   SPIKE_CREATE=false → the first run is READ-ONLY (inventory only)."
echo "   Tell Claude it's ready; no need to share the password."
