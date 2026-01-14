#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME="aws-c-s3-minio-client"

# Build the Docker image
sudo docker build -t "${IMAGE_NAME}" .

# Config (override these as needed)
ENDPOINT="${ENDPOINT:-http://localhost:9000}"
REGION="${REGION:-us-east-1}"
S3_BUCKET="${S3_BUCKET:-testbucket}"
S3_KEY="${S3_KEY:-test.bin}"
AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-minioadmin}"
AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-minioadmin}"
AWS_SESSION_TOKEN="${AWS_SESSION_TOKEN:-}"
N="${N:-1000}"

echo "Running client against ${ENDPOINT}, bucket=${S3_BUCKET}, key=${S3_KEY}, N=${N}"

# Use host network so localhost:9000 is reachable from the container
sudo docker run --rm --network host \
  -e ENDPOINT="${ENDPOINT}" \
  -e REGION="${REGION}" \
  -e S3_BUCKET="${S3_BUCKET}" \
  -e S3_KEY="${S3_KEY}" \
  -e AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID}" \
  -e AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY}" \
  -e AWS_SESSION_TOKEN="${AWS_SESSION_TOKEN}" \
  -e N="${N}" \
  "${IMAGE_NAME}"
