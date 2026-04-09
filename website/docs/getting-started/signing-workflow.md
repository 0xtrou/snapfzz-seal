# Signing Workflow

## Key Generation

```bash
seal keygen
```

Creates:
- `~/.agent-seal/keys/key` — Secret key (keep secret!)
- `~/.agent-seal/keys/key.pub` — Public key (distribute)

## Signing

```bash
seal sign --key ~/.agent-seal/keys/key --binary ./agent.sealed
```

## Verification

**TOFU (Trust-on-First-Use):**
```bash
seal verify --binary ./agent.sealed
```

**Pinned Key (recommended for production):**
```bash
seal verify --binary ./agent.sealed --pubkey ./builder-key.pub
```

Signing is **mandatory** — unsigned payloads are rejected at launch.