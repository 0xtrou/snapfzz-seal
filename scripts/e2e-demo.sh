#!/usr/bin/env bash
set -euo pipefail

# Snapfzz Seal E2E Demo Script
# This script demonstrates the full pipeline: build, compile, sign, verify, launch

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "╔════════════════════════════════════════════════════════════╗"
echo "║        Snapfzz Seal v0.2 - E2E Demo                        ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Check platform
if [[ "$(uname)" != "Linux" ]]; then
    echo "⚠️  WARNING: Running on $(uname)"
    echo "   Sealed agents can ONLY execute on Linux x86_64"
    echo "   This demo will build and sign, but cannot launch."
    echo ""
fi

# Check prerequisites
echo "=== Checking Prerequisites ==="

if ! command -v python3 &> /dev/null; then
    echo "ERROR: python3 not found"
    exit 1
fi
echo "✓ Python3: $(python3 --version)"

if command -v pyinstaller &> /dev/null; then
    echo "✓ PyInstaller: $(pyinstaller --version)"
elif command -v nuitka &> /dev/null; then
    echo "✓ Nuitka: $(nuitka --version)"
else
    echo "✗ No compiler backend (install: pip install pyinstaller)"
    exit 1
fi

if ! command -v cargo &> /dev/null; then
    echo "ERROR: cargo not found"
    exit 1
fi
echo "✓ Rust: $(cargo --version)"
echo ""

# Configuration
USER_FP="${USER_FP:-$(echo -n "demo-user-$(date +%s)" | shasum -a 256 | cut -d' ' -f1)}"
SANDBOX_FP="${SANDBOX_FP:-$(echo -n "demo-sandbox-$(date +%s)" | shasum -a 256 | cut -d' ' -f1)}"
export SNAPFZZ_SEAL_MASTER_SECRET_HEX="${SNAPFZZ_SEAL_MASTER_SECRET_HEX:-$(echo -n "demo-secret" | shasum -a 256 | cut -d' ' -f1)}"

KEYS_DIR="${KEYS_DIR:-/tmp/snapfzz-seal-keys-$(date +%s)}"
OUTPUT="${OUTPUT:-/tmp/snapfzz-seal-demo-$(date +%s).sealed}"

echo "=== Configuration ==="
echo "User Fingerprint:    $USER_FP"
echo "Sandbox Fingerprint: $SANDBOX_FP"
echo "Keys Directory:      $KEYS_DIR"
echo "Output Binary:       $OUTPUT"
echo ""

# Step 1: Build launcher
echo "=== [1/5] Building launcher ==="
cargo build --release -p snapfzz-seal-launcher 2>&1 | grep -v "^   Compiling" || true

LAUNCHER="${PROJECT_ROOT}/target/release/snapfzz-seal-launcher"
if [[ ! -f "$LAUNCHER" ]]; then
    echo "ERROR: Launcher not found at $LAUNCHER"
    exit 1
fi
echo "✓ Launcher: $LAUNCHER"
echo ""

# Step 2: Generate signing keys
echo "=== [2/5] Generating signing keys ==="
cargo run --release -p snapfzz-seal -- keygen --keys-dir "$KEYS_DIR"
echo ""

# Step 3: Compile agent
echo "=== [3/5] Compiling chat agent ==="
BACKEND="pyinstaller"
if command -v nuitka &> /dev/null && ! command -v pyinstaller &> /dev/null; then
    BACKEND="nuitka"
fi

cargo run --release -p snapfzz-seal -- compile \
    --project "${PROJECT_ROOT}/examples/chat_agent" \
    --user-fingerprint "$USER_FP" \
    --sandbox-fingerprint "$SANDBOX_FP" \
    --output "$OUTPUT" \
    --launcher "$LAUNCHER" \
    --backend "$BACKEND" \
    --mode batch

if [[ ! -f "$OUTPUT" ]]; then
    echo "ERROR: Sealed binary not created"
    exit 1
fi

echo "✓ Output: $OUTPUT ($(wc -c < "$OUTPUT" | tr -d ' ') bytes)"
echo ""

# Step 4: Sign
echo "=== [4/5] Signing sealed binary ==="
cargo run --release -p snapfzz-seal -- sign \
    --key "${KEYS_DIR}/builder_secret.key" \
    --binary "$OUTPUT"
echo "✓ Signed"
echo ""

# Step 5: Verify
echo "=== [5/5] Verifying signature ==="
cargo run --release -p snapfzz-seal -- verify \
    --binary "$OUTPUT" \
    --pubkey "${KEYS_DIR}/builder_public.key"
echo ""

# Launch (Linux only)
if [[ "$(uname)" == "Linux" ]]; then
    echo "=== Launching sealed agent ==="
    chmod +x "$OUTPUT"
    "$OUTPUT" --user-fingerprint "$USER_FP"
    echo ""
else
    echo "⚠️  Skipping launch (requires Linux x86_64)"
    echo "   Copy the binary to a Linux machine and run:"
    echo "   chmod +x $OUTPUT"
    echo "   $OUTPUT --user-fingerprint $USER_FP"
    echo ""
fi

echo "╔════════════════════════════════════════════════════════════╗"
echo "║                    Demo Complete!                         ║"
echo "╠════════════════════════════════════════════════════════════╣"
echo "║  Sealed Binary: $OUTPUT"
echo "║  Public Key:    ${KEYS_DIR}/builder_public.key"
echo "╚════════════════════════════════════════════════════════════╝"
