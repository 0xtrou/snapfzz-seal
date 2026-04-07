#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Agent Seal Demo ==="
echo ""

USER_FP=$(echo -n "demo-user-$(date +%s)" | sha256sum | cut -d' ' -f1)
SANDBOX_FP=$(echo -n "demo-sandbox-$(date +%s)" | sha256sum | cut -d' ' -f1)

echo "User fingerprint: $USER_FP"
echo "Sandbox fingerprint: $SANDBOX_FP"
echo ""

echo "[1/4] Building launcher..."
cargo build --release -p agent-seal-launcher --target x86_64-unknown-linux-musl 2>/dev/null || \
    cargo build --release -p agent-seal-launcher 2>/dev/null || \
    echo "Warning: launcher build failed, using existing binary"

LAUNCHER="${PROJECT_ROOT}/target/release/agent-seal-launcher"
[ ! -f "$LAUNCHER" ] && LAUNCHER="${PROJECT_ROOT}/target/debug/agent-seal-launcher"
[ ! -f "$LAUNCHER" ] && echo "ERROR: launcher not found" && exit 1

echo "Launcher: $LAUNCHER"
echo ""

echo "[2/4] Compiling demo agent..."
OUTPUT="/tmp/agent-seal-demo-$(date +%s).bin"
cargo run --release -p agent-seal-compiler -- \
  --project "${PROJECT_ROOT}/examples/demo_agent" \
  --user-fingerprint "$USER_FP" \
  --sandbox-fingerprint "$SANDBOX_FP" \
  --output "$OUTPUT" \
  --launcher "$LAUNCHER"

echo "Output: $OUTPUT ($(wc -c < "$OUTPUT") bytes)"
echo ""

echo "[3/4] Running sealed binary..."
export AGENT_SEAL_MASTER_SECRET_HEX=$(echo -n "demo-secret" | sha256sum | cut -d' ' -f1)
chmod +x "$OUTPUT"
"$OUTPUT" --payload "$OUTPUT"
echo ""

echo "=== Demo Complete ==="
