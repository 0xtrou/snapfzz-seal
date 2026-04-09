# Agent Seal

![Build](docs/badges/build-status.svg)
![Coverage](docs/badges/coverage.svg)
![Rust](docs/badges/rust-version.svg)

**Encrypted, sandbox-bound agent delivery system for Linux.**

[📚 Full Documentation](https://0xtrou.github.io/agentseal/) | [GitHub](https://github.com/0xtrou/agentseal)

## What It Does

Agent Seal compiles AI agents into sealed binaries that:
- Bind decryption to runtime environment fingerprints
- Execute entirely from memory (memfd + fexecve)
- Verify builder signatures before launch
- Protect API keys with AES-256-GCM encryption

## Quick Start

### 1. Install

```bash
cargo install --path crates/agent-seal
```

### 2. Generate Keys

```bash
seal keygen
```

### 3. Compile

```bash
export USER_FP=$(openssl rand -hex 32)

seal compile \
  --project ./examples/demo_agent \
  --user-fingerprint $USER_FP \
  --sandbox-fingerprint auto \
  --output ./agent.sealed \
  --launcher ./target/release/agent-seal-launcher
```

### 4. Sign

```bash
seal sign --key ~/.agent-seal/keys/key --binary ./agent.sealed
```

### 5. Launch

```bash
AGENT_SEAL_MASTER_SECRET_HEX=... \
  seal launch --payload ./agent.sealed --user-fingerprint $USER_FP
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `seal compile` | Compile and seal an agent |
| `seal launch` | Launch a sealed agent |
| `seal keygen` | Generate signing keys |
| `seal sign` | Sign a sealed binary |
| `seal verify` | Verify signature |
| `seal server` | Start orchestration API |

## Platform Support

| Platform | Status |
|----------|--------|
| Linux x86_64 | Full support |
| macOS arm64 | Decrypt only |
| Windows x86_64 | No-op stub |

## Security

Agent Seal raises attacker cost but is **not** a replacement for:
- Host-level trust
- Hardware attestation
- Secure key distribution

See [Threat Model](https://0xtrou.github.io/agentseal/security/threat-model.html) for details.

## License

MIT OR Apache-2.0