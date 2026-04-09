---
sidebar_position: 1
---

# Introduction

**Encrypted, sandbox-bound agent delivery system for Linux.**

Agent Seal compiles AI agents into sealed binaries that:
- Bind decryption to runtime environment fingerprints
- Execute entirely from memory (memfd + fexecve)
- Verify builder signatures before launch
- Protect API keys with AES-256-GCM encryption

## Quick Links

- [Installation](./getting-started/installation) — Get up and running
- [Quick Start](./getting-started/quick-start) — Seal your first agent
- [CLI Reference](./reference/cli) — All commands
- [Threat Model](./security/threat-model) — Security properties

## Features

| Feature | Description |
|---------|-------------|
| AES-256-GCM encryption | Streaming chunk encryption |
| HKDF key binding | Dual derivation to fingerprints |
| Ed25519 signatures | Mandatory builder verification |
| memfd execution | Payload never touches disk |
| seccomp hardening | Syscall allowlist |
| Orchestration API | REST API for automation |

## License

MIT OR Apache-2.0