# Quick Start

## 1. Generate Keys

```bash
seal keygen
```

## 2. Compile

```bash
export USER_FP=$(openssl rand -hex 32)

seal compile \
  --project ./examples/demo_agent \
  --user-fingerprint $USER_FP \
  --sandbox-fingerprint auto \
  --output ./agent.sealed \
  --launcher ./target/release/agent-seal-launcher
```

## 3. Sign

```bash
seal sign --key ~/.agent-seal/keys/key --binary ./agent.sealed
```

## 4. Launch

```bash
AGENT_SEAL_MASTER_SECRET_HEX=... \
  seal launch --payload ./agent.sealed --user-fingerprint $USER_FP
```