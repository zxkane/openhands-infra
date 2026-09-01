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
#   - nerdctl
#   - soci CLI >= 0.10 (https://github.com/awslabs/soci-snapshotter/releases)
#   - AWS CLI with ECR access
#
# Usage:
#   ./scripts/generate-soci-index.sh <ecr-image-uri> [region]
#
# Examples:
#   ./scripts/generate-soci-index.sh 123456789012.dkr.ecr.us-west-2.amazonaws.com/repo:tag us-west-2

IMAGE_URI="${1:?Usage: $0 <ecr-image-uri> [region]}"
REGION="${2:-}"
ECR_IMAGE_PATTERN='^([0-9]{12})\.dkr\.ecr\.([a-z]{2}(-[a-z0-9]+)+-[0-9]+)\.amazonaws\.com/([a-z0-9]+([._-][a-z0-9]+)*)(/[a-z0-9]+([._-][a-z0-9]+)*)*:([A-Za-z0-9_][A-Za-z0-9_.-]{0,127})$'

if [[ ! "${IMAGE_URI}" =~ ${ECR_IMAGE_PATTERN} ]]; then
  echo "ERROR: Image must be a tagged private ECR image URI"
  exit 1
fi

IMAGE_REGION="${BASH_REMATCH[2]}"
REGION="${REGION:-${IMAGE_REGION}}"
IMAGE_PATH="${IMAGE_URI#*/}"
REPOSITORY_NAME="${IMAGE_PATH%:*}"
SOURCE_TAG="${IMAGE_URI##*:}"

if (( ${#REPOSITORY_NAME} < 2 || ${#REPOSITORY_NAME} > 256 )); then
  echo "ERROR: ECR repository name must contain 2-256 characters"
  exit 1
fi

if (( ${#SOURCE_TAG} > 123 )); then
  echo "ERROR: Source image tag must contain at most 123 characters so the -soci tag is valid"
  exit 1
fi

if [ "${REGION}" != "${IMAGE_REGION}" ]; then
  echo "ERROR: Region ${REGION} does not match image region ${IMAGE_REGION}"
  exit 1
fi

SOCI_IMAGE_URI="${IMAGE_URI}-soci"

echo "=== SOCI v2 Index Generator ==="
echo "Source:   ${IMAGE_URI}"
echo "Dest:     ${SOCI_IMAGE_URI}"
echo "Region:   ${REGION}"
echo ""

# Check prerequisites
MISSING=""
for cmd in aws ctr nerdctl soci; do
  if ! command -v "$cmd" &>/dev/null; then
    MISSING="${MISSING} ${cmd}"
  fi
done
if [ -n "${MISSING}" ]; then
  echo "ERROR: Missing required tools:${MISSING}"
  echo ""
  echo "Install instructions:"
  echo "  containerd: https://containerd.io/downloads/"
  echo "  nerdctl:    https://github.com/containerd/nerdctl/releases"
  echo "  soci CLI:   https://github.com/awslabs/soci-snapshotter/releases (>= v0.10)"
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

REGISTRY="${IMAGE_URI%%/*}"
DOCKER_CONFIG_DIR=$(mktemp -d)
chmod 700 "${DOCKER_CONFIG_DIR}"
SOURCE_IMAGE_WAS_PRESENT=false
SOCI_IMAGE_WAS_PRESENT=false

if sudo nerdctl --namespace default image inspect "${IMAGE_URI}" &>/dev/null; then
  SOURCE_IMAGE_WAS_PRESENT=true
fi
if sudo nerdctl --namespace default image inspect "${SOCI_IMAGE_URI}" &>/dev/null; then
  SOCI_IMAGE_WAS_PRESENT=true
fi

cleanup() {
  if [ "${SOCI_IMAGE_WAS_PRESENT}" = false ]; then
    sudo nerdctl --namespace default image rm "${SOCI_IMAGE_URI}" &>/dev/null || true
  fi
  if [ "${SOURCE_IMAGE_WAS_PRESENT}" = false ]; then
    sudo nerdctl --namespace default image rm "${IMAGE_URI}" &>/dev/null || true
  fi
  if [ -d "${DOCKER_CONFIG_DIR}" ]; then
    sudo find "${DOCKER_CONFIG_DIR}" -depth -delete
  fi
}
trap cleanup EXIT

echo "Authenticating to ECR..."
aws ecr get-login-password --region "${REGION}" |
  sudo env DOCKER_CONFIG="${DOCKER_CONFIG_DIR}" \
    nerdctl --namespace default login --username AWS --password-stdin "${REGISTRY}"

# Pull the source image into containerd's local store
echo "[1/3] Pulling source image..."
sudo env DOCKER_CONFIG="${DOCKER_CONFIG_DIR}" \
  nerdctl --namespace default pull "${IMAGE_URI}"

# Convert to SOCI v2 (creates OCI image index with embedded SOCI index in local store)
echo "[2/3] Creating SOCI v2 index..."
sudo soci convert "${IMAGE_URI}" "${SOCI_IMAGE_URI}"

# Push the SOCI v2 image index to ECR
echo "[3/3] Pushing SOCI v2 image index to ECR..."
sudo env DOCKER_CONFIG="${DOCKER_CONFIG_DIR}" \
  nerdctl --namespace default push "${SOCI_IMAGE_URI}"

echo ""
echo "=== SOCI v2 index generation complete ==="
echo ""
echo "SOCI image URI: ${SOCI_IMAGE_URI}"
echo ""
echo "To use: deploy with --context sandboxSociImageUri='${SOCI_IMAGE_URI}'"
