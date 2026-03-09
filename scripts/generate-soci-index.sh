#!/usr/bin/env bash
set -euo pipefail

# Generate SOCI (Seekable OCI) v2 index for a container image in ECR.
# Uses `soci convert` to create an OCI image index that binds the SOCI index
# to the container image. Fargate auto-detects v2 indexes and lazy-loads images,
# reducing image pull time by 30-70%.
#
# Output: The SOCI-enabled image is pushed with a "-soci" suffix tag.
# Use this tag in the sandbox task definition for Fargate lazy loading.
#
# Prerequisites:
#   - containerd >= 1.7 (running)
#   - soci CLI >= 0.10 (https://github.com/awslabs/soci-snapshotter/releases)
#   - AWS CLI with ECR access
#
# Usage:
#   ./scripts/generate-soci-index.sh <ecr-image-uri> [region]
#
# Examples:
#   ./scripts/generate-soci-index.sh 123456789012.dkr.ecr.us-west-2.amazonaws.com/repo:tag us-west-2

IMAGE_URI="${1:?Usage: $0 <ecr-image-uri> [region]}"
REGION="${2:-us-west-2}"
SOCI_IMAGE_URI="${IMAGE_URI}-soci"

echo "=== SOCI v2 Index Generator ==="
echo "Source:   ${IMAGE_URI}"
echo "Dest:     ${SOCI_IMAGE_URI}"
echo "Region:   ${REGION}"
echo ""

# Check prerequisites
MISSING=""
for cmd in ctr soci; do
  if ! command -v "$cmd" &>/dev/null; then
    MISSING="${MISSING} ${cmd}"
  fi
done
if [ -n "${MISSING}" ]; then
  echo "ERROR: Missing required tools:${MISSING}"
  echo ""
  echo "Install instructions:"
  echo "  containerd: https://containerd.io/downloads/"
  echo "  soci CLI:   https://github.com/awslabs/soci-snapshotter/releases (>= v0.10)"
  echo ""
  echo "Quick install (Amazon Linux 2 / Ubuntu):"
  echo "  sudo yum install -y containerd  # or: sudo apt-get install -y containerd"
  echo "  SOCI_VERSION=0.12.1"
  echo "  SOCI_ARCH=\$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')"
  echo "  curl -sSL https://github.com/awslabs/soci-snapshotter/releases/download/v\${SOCI_VERSION}/soci-snapshotter-\${SOCI_VERSION}-linux-\${SOCI_ARCH}.tar.gz | sudo tar -xzC /usr/local/bin soci"
  exit 1
fi

# Verify soci supports the convert subcommand (v0.10+)
if ! soci convert --help &>/dev/null; then
  SOCI_VER=$(soci --version 2>&1 | grep -oP 'v\K[0-9.]+' || echo "unknown")
  echo "ERROR: soci v${SOCI_VER} does not support 'convert' (requires >= v0.10)"
  echo "Upgrade: https://github.com/awslabs/soci-snapshotter/releases"
  exit 1
fi

# Ensure containerd is running
if ! sudo ctr version &>/dev/null; then
  echo "Starting containerd..."
  sudo systemctl start containerd 2>/dev/null || {
    echo "ERROR: Failed to start containerd. Start it manually: sudo containerd &"
    exit 1
  }
  sleep 2
fi

# Write ECR credentials to a temporary file to reduce exposure window (CWE-214).
ECR_CREDS_FILE=$(mktemp)
trap 'rm -f "${ECR_CREDS_FILE}"' EXIT
echo -n "AWS:$(aws ecr get-login-password --region "${REGION}")" > "${ECR_CREDS_FILE}"
chmod 600 "${ECR_CREDS_FILE}"

# Pull the source image into containerd's local store
echo "[1/3] Pulling source image..."
sudo ctr image pull --user "$(cat "${ECR_CREDS_FILE}")" "${IMAGE_URI}"

# Convert to SOCI v2 (creates OCI image index with embedded SOCI index in local store)
echo "[2/3] Creating SOCI v2 index..."
sudo soci convert "${IMAGE_URI}" "${SOCI_IMAGE_URI}"

# Push the SOCI v2 image index to ECR
echo "[3/3] Pushing SOCI v2 image index to ECR..."
sudo ctr image push --user "$(cat "${ECR_CREDS_FILE}")" "${SOCI_IMAGE_URI}"

# Clean up local images
sudo ctr image rm "${SOCI_IMAGE_URI}" 2>/dev/null || true

echo ""
echo "=== SOCI v2 index generation complete ==="
echo ""
echo "SOCI image URI: ${SOCI_IMAGE_URI}"
echo ""
echo "To use: deploy with --context sandboxSociImageUri='${SOCI_IMAGE_URI}'"
