#!/bin/sh
# Build the project bundle for staging.
set -eu
cd "$(dirname "$0")/.."
npm ci
npm run build
tar -czf dist.tar.gz dist
echo "bundle ready"
