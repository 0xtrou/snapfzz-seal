# Demo Agent

A minimal agent that calls an LLM using BYOK (bring-your-own-key) and returns a result. Used to demonstrate the full Agent Seal v0.2 pipeline: compile, sign, verify, and launch.

## Configuration

The agent uses environment variables set at deployment time:

| Variable | Description | Default |
|----------|-------------|---------|
| `AGENT_SEAL_API_KEY` | LLM provider API key | *(required)* |
| `AGENT_SEAL_API_BASE` | Provider API base URL | `https://api.openai.com` |
| `AGENT_SEAL_MODEL` | Model to use | `gpt-4o-mini` |
| `AGENT_PROMPT` | Prompt to send to the LLM | "Say 'Agent Seal works!'" |

## Usage

### Compile, sign, and run

```bash
# Set your API key for the agent (set at deployment, not bake time)
export AGENT_SEAL_API_KEY="sk-..."

# Run the full demo pipeline
bash scripts/demo.sh
```

### Manual pipeline

```bash
# 1. Generate signing keys
seal keygen --keys-dir ./keys

# 2. Compile and seal (batch mode)
USER_FP=$(echo -n "my-user" | sha256sum | cut -d' ' -f1)
seal compile \
    --project examples/demo_agent \
    --user-fingerprint "$USER_FP" \
    --sandbox-fingerprint auto \
    --output /tmp/demo.sealed \
    --launcher ./target/release/agent-seal-launcher \
    --mode batch

# 3. Sign
seal sign --key ./keys/key --binary /tmp/demo.sealed

# 4. Verify and run
seal verify --binary /tmp/demo.sealed --pubkey ./keys/key.pub
AGENT_SEAL_MASTER_SECRET_HEX=... /tmp/demo.sealed --user-fingerprint "$USER_FP"
```
