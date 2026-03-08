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
  echo "  curl -sSL https://github.com/awslabs/soci-snapshotter/releases/download/v\${SOCI_VERSION}/soci-snapshotter-\${SOCI_VERSION}-linux-arm64.tar.gz | sudo tar -xzC /usr/local/bin soci"
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

# Login to ECR
echo "[1/4] Logging into ECR..."
ECR_PASSWORD=$(aws ecr get-login-password --region "${REGION}")

# Pull the image via containerd
echo "[2/4] Pulling image via containerd..."
sudo ctr image pull --user "AWS:${ECR_PASSWORD}" "${IMAGE_URI}"

# Create SOCI index
echo "[3/4] Creating SOCI index..."
sudo soci create "${IMAGE_URI}"

# Push SOCI index to ECR
echo "[4/4] Pushing SOCI index to ECR..."
sudo soci push --user "AWS:${ECR_PASSWORD}" "${IMAGE_URI}"

echo ""
echo "=== SOCI index generation complete ==="
echo "Fargate will automatically use lazy loading for this image on next RunTask."
