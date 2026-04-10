# Demo Agent

A minimal agent that calls an LLM using BYOK (bring-your-own-key) and returns a result. Used to demonstrate the full Snapfzz Seal v0.2 pipeline: compile, sign, verify, and launch.

## Configuration

The agent uses environment variables set at deployment time:

| Variable | Description | Default |
|----------|-------------|---------|
| `SNAPFZZ_SEAL_API_KEY` | LLM provider API key | *(required)* |
| `SNAPFZZ_SEAL_API_BASE` | Provider API base URL | `https://api.openai.com` |
| `SNAPFZZ_SEAL_MODEL` | Model to use | `gpt-4o-mini` |
| `AGENT_PROMPT` | Prompt to send to the LLM | "Say 'Snapfzz Seal works!'" |

## Usage

### Compile, sign, and run

```bash
# Set your API key for the agent (set at deployment, not bake time)
export SNAPFZZ_SEAL_API_KEY="sk-..."

# Run the full demo pipeline
bash scripts/demo.sh
```

### Manual pipeline

```bash
# 1. Generate signing keys
seal keygen --keys-dir ./keys

# 2. Compile and seal (batch mode)
USER_FP=$(echo -n "my-user" | sha256sum | cut -d' ' -f1)
# Note: --sandbox-fingerprint auto generates a random binding nonce, not a real
# sandbox measurement. For production, collect a fingerprint from your target
# environment and pass it explicitly (as the demo.sh script does).
seal compile \
    --project examples/demo_agent \
    --user-fingerprint "$USER_FP" \
    --sandbox-fingerprint auto \
    --output /tmp/demo.sealed \
    --launcher ./target/release/seal-launcher \
    --mode batch

# 3. Sign
seal sign --key ./keys/builder_secret.key --binary /tmp/demo.sealed

# 4. Verify and run
# --pubkey pins builder identity; omitting it uses TOFU (embedded key)
seal verify --binary /tmp/demo.sealed --pubkey ./keys/builder_public.key
SNAPFZZ_SEAL_MASTER_SECRET_HEX=... /tmp/demo.sealed --user-fingerprint "$USER_FP"
```
