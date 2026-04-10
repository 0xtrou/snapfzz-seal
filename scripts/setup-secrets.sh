#!/usr/bin/env bash
# Setup GitHub secrets for E2E tests
# Run this script once to configure the required secrets

set -euo pipefail

echo "=== Setting up GitHub Secrets for Snapfzz Seal E2E Tests ==="
echo ""

REPO="0xtrou/snapfzz-seal"

# Check if gh is authenticated
if ! gh auth status &> /dev/null; then
    echo "ERROR: gh CLI not authenticated. Run 'gh auth login' first."
    exit 1
fi

# Set secrets
echo "Setting SNAPFZZ_SEAL_API_KEY..."
echo -n "sk-cfc48673f4ec32c8-def3ed-746624f9" | gh secret set SNAPFZZ_SEAL_API_KEY --repo "$REPO"

echo "Setting SNAPFZZ_SEAL_API_BASE..."
echo -n "https://llm.solo.engineer/v1" | gh secret set SNAPFZZ_SEAL_API_BASE --repo "$REPO"

echo "Setting SNAPFZZ_SEAL_MODEL..."
echo -n "bcp/qwen3.6-plus" | gh secret set SNAPFZZ_SEAL_MODEL --repo "$REPO"

echo "Setting SNAPFZZ_SEAL_MASTER_SECRET_HEX..."
MASTER_SECRET=$(echo -n "e2e-demo-secret-$(date +%s)" | shasum -a 256 | cut -d' ' -f1)
echo -n "$MASTER_SECRET" | gh secret set SNAPFZZ_SEAL_MASTER_SECRET_HEX --repo "$REPO"

echo ""
echo "✓ All secrets configured!"
echo ""
echo "Secrets set:"
gh secret list --repo "$REPO"
