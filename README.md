# Snapfzz Seal

![Build](docs/badges/build-status.svg)
![Coverage](docs/badges/coverage.svg)
![Rust](docs/badges/rust-version.svg)

**Encrypted, sandbox-bound agent delivery system for Linux.**

[📚 Full Documentation](https://0xtrou.github.io/snapfzz-seal/) | [GitHub](https://github.com/0xtrou/snapfzz-seal)

## What It Does

Snapfzz Seal compiles AI agents into sealed binaries that:
- Bind decryption to runtime environment fingerprints
- Execute entirely from memory (memfd + fexecve)
- Verify builder signatures before launch
- Protect API keys with AES-256-GCM encryption
- **Defense-in-depth security with 6 protection layers**

## Security Features

Snapfzz Seal implements defense-in-depth security to protect the master secret:

### 🔒 6-Layer Security Architecture

1. **No Observable Patterns** - Random markers generated at compile time
2. **Shamir Secret Sharing** - Split into 5 shares, requires 3 to reconstruct
3. **Decoy Secrets** - 10 fake secret sets to confuse attackers
4. **Anti-Analysis** - Debugger and VM detection
5. **Integrity Binding** - Decryption key depends on binary hash
6. **White-Box Cryptography** - Key spread across thousands of lookup tables

**Security Impact:**
- Before: Master secret trivially extractable with basic tools
- After: Requires expert-level reverse engineering and cryptanalysis

See [Security Architecture](https://0xtrou.github.io/snapfzz-seal/security/threat-model.html) for details.

## Quick Start

### 1. Install

```bash
cargo install --path crates/snapfzz-seal
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
  --launcher ./target/release/snapfzz-seal-launcher
```

### 4. Sign

```bash
seal sign --key ~/.snapfzz-seal/keys/key --binary ./agent.sealed
```

### 5. Launch

```bash
SNAPFZZ_SEAL_MASTER_SECRET_HEX=... \
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

Snapfzz Seal raises attacker cost but is **not** a replacement for:
- Host-level trust
- Hardware attestation
- Secure key distribution

### Security Posture

**Coverage:** 92.38% test coverage  
**Security Layers:** 6 independent protection mechanisms  
**Attacker Cost:** Expert-level cryptanalysis required

See [Threat Model](https://0xtrou.github.io/snapfzz-seal/security/threat-model.html) for details.

## License

MIT License — See [LICENSE](LICENSE) for details.