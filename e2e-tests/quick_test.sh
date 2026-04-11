#!/bin/bash
# Quick E2E test runner for local development
# Usage: ./e2e-tests/quick_test.sh [backend]

set -e

BACKEND="${1:-pyinstaller}"
BUILD_ID="${BUILD_ID:-local-test-$(date +%s)}"

echo "=== Quick E2E Test ==="
echo "Backend: $BACKEND"
echo "BUILD_ID: $BUILD_ID"
echo ""

# Always rebuild to ensure BUILD_ID consistency between seal and seal-launcher
echo "Building release binaries..."
BUILD_ID="$BUILD_ID" cargo build --release

# Generate test user/sandbox fingerprints
USER_FP=$(openssl rand -hex 32)
SANDBOX_FP=$(openssl rand -hex 32)

echo "User FP: $USER_FP"
echo "Sandbox FP: $SANDBOX_FP"
echo ""

# Generate keys
KEYS_DIR="/tmp/seal-keys-$$"
mkdir -p "$KEYS_DIR"
./target/release/seal keygen --keys-dir "$KEYS_DIR"
echo "Keys generated in: $KEYS_DIR"
echo ""

# Select project based on backend
if [ "$BACKEND" = "go" ]; then
    PROJECT="./examples/go_agent"
else
    PROJECT="./examples/chat_agent"
fi

# Compile
echo "Compiling with $BACKEND..."
OUTPUT="/tmp/agent-$BACKEND-$$.sealed"
./target/release/seal compile \
    --project "$PROJECT" \
    --user-fingerprint "$USER_FP" \
    --sandbox-fingerprint "$SANDBOX_FP" \
    --output "$OUTPUT" \
    --launcher ./target/release/seal-launcher \
    --backend "$BACKEND"

echo ""
echo "Signing..."
./target/release/seal sign \
    --key "$KEYS_DIR/builder_secret.key" \
    --binary "$OUTPUT"

echo ""
echo "Verifying..."
./target/release/seal verify \
    --pubkey "$KEYS_DIR/builder_public.key" \
    --binary "$OUTPUT"

echo ""
echo "=== Test Summary ==="
ls -lh "$OUTPUT"
echo ""
echo "✓ Quick test passed for $BACKEND"

# Cleanup
rm -rf "$KEYS_DIR"