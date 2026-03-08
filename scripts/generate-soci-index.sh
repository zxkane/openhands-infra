#!/usr/bin/env bash
set -euo pipefail

# Generate SOCI (Seekable OCI) index for a container image in ECR.
# Fargate auto-detects SOCI indexes and lazy-loads images instead of full-pulling,
# reducing image pull time by 30-70%.
#
# Prerequisites:
#   - containerd (running)
#   - soci CLI (https://github.com/awslabs/soci-snapshotter/releases)
#   - AWS CLI with ECR access
#
# Usage:
#   ./scripts/generate-soci-index.sh <ecr-image-uri> [region]
#
# Examples:
#   ./scripts/generate-soci-index.sh 123456789012.dkr.ecr.us-west-2.amazonaws.com/cdk-abc:latest us-west-2
#   ./scripts/generate-soci-index.sh 123456789012.dkr.ecr.us-west-2.amazonaws.com/cdk-abc@sha256:abcdef us-west-2

IMAGE_URI="${1:?Usage: $0 <ecr-image-uri> [region]}"
REGION="${2:-us-west-2}"

# Extract registry from image URI
ECR_REGISTRY="${IMAGE_URI%%/*}"

echo "=== SOCI Index Generator ==="
echo "Image:    ${IMAGE_URI}"
echo "Region:   ${REGION}"
echo "Registry: ${ECR_REGISTRY}"
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
  echo "  soci CLI:   https://github.com/awslabs/soci-snapshotter/releases"
  echo ""
  echo "Quick install (Amazon Linux 2 / Ubuntu):"
  echo "  sudo yum install -y containerd  # or: sudo apt-get install -y containerd"
  echo "  SOCI_VERSION=0.8.0"
  echo "  SOCI_ARCH=\$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')"
  echo "  curl -sSL https://github.com/awslabs/soci-snapshotter/releases/download/v\${SOCI_VERSION}/soci-snapshotter-\${SOCI_VERSION}-linux-\${SOCI_ARCH}.tar.gz | sudo tar -xzC /usr/local/bin soci"
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

# Write ECR credentials to a temporary file to avoid exposing the token
# in process argument lists (visible via ps aux). ECR tokens are short-lived
# (12h) but we still avoid unnecessary exposure per CWE-214.
ECR_CREDS_FILE=$(mktemp)
trap 'rm -f "${ECR_CREDS_FILE}"' EXIT
echo -n "AWS:$(aws ecr get-login-password --region "${REGION}")" > "${ECR_CREDS_FILE}"
chmod 600 "${ECR_CREDS_FILE}"

# Pull the image via containerd
echo "[1/3] Pulling image via containerd..."
sudo ctr image pull --user "$(cat "${ECR_CREDS_FILE}")" "${IMAGE_URI}"

# Create SOCI index
echo "[2/3] Creating SOCI index..."
sudo soci create "${IMAGE_URI}"

# Push SOCI index to ECR
echo "[3/3] Pushing SOCI index to ECR..."
sudo soci push --user "$(cat "${ECR_CREDS_FILE}")" "${IMAGE_URI}"

echo ""
echo "=== SOCI index generation complete ==="
echo "Fargate will automatically use lazy loading for this image on next RunTask."
