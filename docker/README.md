# Custom OpenHands Docker Image

This directory contains files to build a custom OpenHands Docker image with the localhost URL rewriting fix.

## Why This Fix Is Needed

When OpenHands runs behind a reverse proxy (CloudFront -> ALB -> EC2), the frontend tries to connect to runtime containers using `localhost:{port}` URLs. These connections fail because `localhost` refers to the user's browser machine, not the server.

This fix patches `WebSocket`, `fetch`, and `XMLHttpRequest` to rewrite:
- `wss://localhost:{port}/path` -> `wss://{host}/runtime/{port}/path`
- `http://localhost:{port}/path` -> `https://{host}/runtime/{port}/path`

## Files

- `Dockerfile` - Builds custom image based on official OpenHands image
- `patch-fix.js` - JavaScript that patches WebSocket/fetch/XHR
- `apply-patch.sh` - Startup script that injects the patch into index.html

## Building the Image

### Option 1: Build on ARM64 Machine (Recommended)

```bash
# SSH to an ARM64 instance (e.g., t4g.medium)
# Clone the repo and navigate to this directory

# Login to ECR
aws ecr get-login-password --region us-west-2 | docker login --username AWS --password-stdin <aws-account-id>.dkr.ecr.us-west-2.amazonaws.com

# Build and push
docker build -t <aws-account-id>.dkr.ecr.us-west-2.amazonaws.com/openhands-custom:latest .
docker push <aws-account-id>.dkr.ecr.us-west-2.amazonaws.com/openhands-custom:latest
```

### Option 2: Cross-Compile with QEMU

```bash
# Install QEMU for multi-arch builds (one-time setup)
docker run --privileged --rm tonistiigi/binfmt --install all

# Login to ECR
aws ecr get-login-password --region us-west-2 | docker login --username AWS --password-stdin <aws-account-id>.dkr.ecr.us-west-2.amazonaws.com

# Build and push for ARM64
docker buildx build --platform linux/arm64 \
  -t <aws-account-id>.dkr.ecr.us-west-2.amazonaws.com/openhands-custom:latest \
  --push .
```

## Using the Custom Image

Update the SSM parameter to use the custom image:

```bash
aws ssm put-parameter \
  --name "/openhands/docker/openhands-image" \
  --value "<aws-account-id>.dkr.ecr.us-west-2.amazonaws.com/openhands-custom:latest" \
  --type String \
  --overwrite \
  --region us-west-2
```

Then trigger an instance refresh to pick up the new image.

## Current Approach

The current deployment uses **runtime patching** instead of a custom Docker image. The `apply_localhost_url_patch()` function in `lib/compute-stack.ts` applies the patch after the container starts. This avoids the need to build and maintain a custom image.

The custom image approach is provided as an alternative that:
- Applies the patch at container startup (more reliable)
- Works across container restarts
- Doesn't depend on user data script timing
