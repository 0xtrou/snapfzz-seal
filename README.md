# Agent Seal

![Build](docs/badges/build-status.svg)
![Coverage](docs/badges/coverage.svg)
![Rust](docs/badges/rust-version.svg)

Agent Seal is an encrypted, sandbox-bound agent delivery system for Linux. It compiles agents into sealed payloads, binds decryption to runtime fingerprints, executes from memory. The master secret used for key derivation is embedded in assembled binaries by default (env var delivery is a fallback); provider API keys inside agent payloads are encrypted, not shipped in plaintext.

The primary interface is a single binary, `seal`, with six subcommands:

- `seal compile`: compile and seal an agent payload
- `seal launch`: launch a sealed agent payload
- `seal keygen`: generate Ed25519 signing keys
- `seal sign`: sign a sealed binary with a builder key
- `seal verify`: verify a sealed binary signature
- `seal server`: start the orchestration API server

## Architecture

```text
                              ┌─────────────────────────┐
                              │        seal             │
                              │   single CLI binary     │
                              └──────────┬──────────────┘
                                         │
         ┌────────────────────────────────┼────────────────────────────────┐
         │                                │                                │
┌───────▼────────┐             ┌─────────▼────────┐
│  seal server   │             │  seal compile    │
│ orchestration  │             │ compile + seal   │
│ API entrypoint │             │ pipeline         │
└───────┬────────┘             └─────────┬────────┘
        │                                │
        │                      ┌─────────▼────────┐
        │                      │  seal launch     │
        │                      │ decrypt + exec   │
        │                      │ from memfd       │
        │                      └─────────┬────────┘
        │                                │
        │                ┌───────────────▼───────────────┐                │
        │                │      builder signing flow      │                │
        │                └───────┬─────────┬──────────────┘                │
        │                        │         │                               │
        │              ┌─────────▼────┐ ┌──▼─────────┐ ┌─────────▼────┐    │
        │              │ seal keygen  │ │ seal sign  │ │ seal verify  │    │
        │              │ generate keys│ │ append sig │ │ verify sig   │    │
        │              └──────────────┘ └────────────┘ └──────────────┘    │
        │                                │                                │
        └──────────────────────┬─────────▼────────┬───────────────────────┘
                               │ agent-seal-core  │
                               │ crypto + payload │
                               └─────────┬────────┘
                                         │
                               ┌─────────▼───────────────┐
                               │ agent-seal-fingerprint  │
                               │ env identity collection │
                               └─────────────────────────┘
```

## How It Works

1. **Compile**: `seal compile` turns source projects into Linux executables and assembles a sealed payload.
2. **Encrypt**: the artifact is chunk-encrypted with AES-256-GCM and sealed with versioned payload metadata.
3. **Ship**: launcher + encrypted payload are distributed to target environments.
4. **Sign**: builders sign sealed binaries with Ed25519 keys.
5. **Run**: `seal launch` verifies signature, collects fingerprint, derives a decryption key, decrypts payload, verifies tamper hash, then executes from memory.
6. **Capture**: execution output is collected (stdout/stderr/exit code) for orchestration.
7. **Destroy**: runtime design aims to minimize residual plaintext footprint.

## Encryption Design

### Streaming encryption

- Algorithm: **AES-256-GCM**
- Mode: **chunked streaming payload format**
- Chunk size baseline: **64 KiB**
- Intent: avoid loading large binaries into memory as one plaintext block

### Dual HKDF derivation model

- `K_env = HKDF(ikm=master_secret, salt=stable_fingerprint || user_fingerprint, info="agent-seal/env/v1")`
- `K_session = HKDF(ikm=K_env, salt=ephemeral_fingerprint, info="agent-seal/session/v1")`

### Payload format (v1)

```text
┌──────────┬─────────┬─────────┬──────────┬────────────┬─────────────┐
│ magic    │ version │ enc_alg │ fmt_ver  │ chunk_count│ header_hmac │
│ ASL\x01  │ u16     │ u16     │ u16      │ u32        │ [u8; 32]    │
└──────────┴─────────┴─────────┴──────────┴────────────┴─────────────┘
┌──────────────┐
│ mode_byte[1] │ 0x00=batch, 0x01=interactive
└──────────────┘
┌──────────────────────────────────────────────────────────────────────┐
│ chunk records: [len:u32][ciphertext+tag] * N                        │
└──────────────────────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────────────────┐
│ footer: original_hash[32] + launcher_hash[32]                       │
└──────────────────────────────────────────────────────────────────────┘
```

## Sandbox Fingerprinting

Fingerprinting is split into:

- **Stable signals** (restart-survivable): machine identity, container/runtime identifiers, kernel/runtime context.
- **Ephemeral signals** (session-level): values expected to vary across short-lived sessions and namespaces.

Current target runtimes:

- Docker / OCI containers
- Firecracker microVM environments
- gVisor-style sandboxed Linux runtime contexts

> **Note:** Runtime detection is heuristic-based (cgroups, `/proc` files, env vars), not hardware-attested. It is advisory metadata and does not feed into the cryptographic fingerprint hash.

## Threat Model

### Protected against

- Casual payload extraction from static binaries
- Running encrypted payload in an unrelated sandbox environment
- Direct exposure of provider API keys from shipped agent artifacts (encrypted at rest; master secret is embedded in assembled binaries)
- Payload tampering: Ed25519 signatures verify builder identity and payload integrity

### Not protected against

- **Root-level compromise** on host or sandbox
- Hardware-backed attestation bypass scenarios
- Full runtime memory extraction by privileged adversaries
- **Local process environment inspection**: when using env var fallback for master secret delivery, the secret is visible in `/proc/[pid]/environ` to root and same-UID processes. The embedded-secret path avoids this.

In short: Agent Seal raises attacker cost and narrows abuse windows; it is not a replacement for host trust or attestation systems.

## Crate Overview

| Crate | Type | Role |
|---|---|---|
| `agent-seal` | bin | Umbrella CLI that provides `seal compile`, `seal launch`, `seal keygen`, `seal sign`, `seal verify`, and `seal server` |
| `agent-seal-core` | lib | Shared types, crypto boundaries, payload metadata, derivation primitives, and Ed25519 signing primitives |
| `agent-seal-fingerprint` | lib | Fingerprint collection, canonicalization, mismatch detection |
| `agent-seal-launcher` | bin | Runtime launcher for decrypt and execution flow (Linux, macOS, Windows) |
| `agent-seal-compiler` | lib + bin | Build and seal pipeline, backend adapters (`nuitka`, `pyinstaller`, `go`) |
| `agent-seal-server` | bin | Orchestration API that composes compile, dispatch, and sandbox management |

## Compatibility Matrix

### Compile Backends

| Backend | Detection Signal | Produces | Status |
|---|---|---|---|
| Nuitka | `main.py` or `setup.py` | Static Linux ELF (Python → C → native) | Stable |
| PyInstaller | `main.py` | Linux ELF (Python import freeze) | Stable |
| Go | `go.mod` | Static Linux ELF (`CGO_ENABLED=0`) | Stable |

Auto-detection tries backends in order: Nuitka → PyInstaller → Go. Explicit selection via `--backend nuitka/pyinstaller/go`.

### Sandbox Targets

| Backend | API | Copy Strategy | Isolation Level | Status |
|---|---|---|---|---|
| Docker | Docker CLI | `docker cp` into container | Process + capabilities | Stable |
| Firecracker | REST API (Unix socket) | Bake into rootfs | MicroVM (kernel-level) | Planned |

### Platform Support

| Platform | Launcher | Compilation | Status |
|---|---|---|---|
| Linux x86_64 | Full (memfd + fexecve + seccomp) | Native | Stable |
| macOS arm64 | Stub (protection + cleanup) | Cross-compile via Docker | Foundation |
| Windows x86_64 | Stub (no-op) | Cross-compile via Docker | Foundation |

Linux launcher features: seccomp allowlist filter, `PR_SET_NO_NEW_PRIVS`, `PR_SET_DUMPABLE(0)`, ptrace anti-debug, env scrub (master secret denied to child), output size limits (64 MB/stream, silent truncation), self-delete on launch.

### Fingerprint Signals

| Signal | Stability | Platform | Status |
|---|---|---|---|
| Machine ID HMAC | Stable | Linux | Active |
| Hostname | Semi-stable | Linux | Active |
| Kernel release | Stable | Linux | Active |
| Cgroup path | Semi-stable | Linux | Active |
| Proc cmdline hash | Stable | Linux | Active (low entropy in homogeneous cloud fleets) |
| MAC address | Stable | Linux | Active |
| DMI product UUID HMAC | Stable | Linux | Active |
| Namespace inodes (mnt/pid/net/uts) | Ephemeral | Linux | Active (session mode) |

## Installation

```bash
cargo install --path crates/agent-seal
```

## Quick Start

### Prerequisites

- Rust toolchain (stable, edition 2024)
- `clippy` and `rustfmt` components
- Linux musl linker support (`x86_64-linux-musl-gcc` / `musl-tools`)
- Optional for CI parity: `cargo-nextest`, `cargo-llvm-cov`

### Build from source

```bash
cargo build --workspace
```

### Compile and seal

```bash
seal compile --project ./agent --user-fingerprint u1 --sandbox-fingerprint auto --output ./out --backend nuitka
```

> **Note:** `--sandbox-fingerprint auto` generates a cryptographically random binding nonce, not an actual sandbox measurement. For real environment binding, collect a fingerprint from your target sandbox and pass it explicitly.

### Launch

```bash
seal launch --payload ./out/payload.asl --fingerprint-mode stable --user-fingerprint u1 --verbose
```

### Run orchestration server

```bash
seal server --bind 127.0.0.1:9090 --compile-dir ./.agent-seal/compile --output-dir ./.agent-seal/output
```

### Run orchestration server

```bash
# 1. Generate a signing keypair (one-time per builder)
seal keygen

# 2. Compile and seal an agent
seal compile --project ./agent --user-fingerprint $USER_FP --output ./agent.sealed

# 3. Sign the sealed binary
seal sign --key ~/.agent-seal/keys/key --binary ./agent.sealed

# 4. Distribute agent.sealed + key.pub to enterprise

# 5. Enterprise verifies before running
seal verify --binary ./agent.sealed --pubkey ./key.pub
seal launch --payload ./agent.sealed --user-fingerprint $USER_FP
```

Individual crate binaries are still available for crate-local development, but `seal` is the primary UX.

---

## CLI Reference

### `seal compile` — Build and seal an agent

Compiles a source project into a Linux executable using nuitka or pyinstaller, encrypts it with AES-256-GCM keyed to fingerprints, and assembles a self-contained sealed binary (launcher + payload).

```text
Usage: seal compile [OPTIONS] --project <PROJECT> --user-fingerprint <USER_FINGERPRINT> --output <OUTPUT>
Options:
  --project <PROJECT>              Path to the agent source directory
  --user-fingerprint <HEX>         64-hex user identity (32 bytes)
  --sandbox-fingerprint <HEX>      64-hex sandbox identity [default: auto]
  --output <PATH>                  Output path for the sealed binary
  --launcher <PATH>                Path to agent-seal-launcher binary (for assembly)
  --backend <BACKEND>              Compile backend [default: nuitka] (nuitka | pyinstaller | go)
  --mode <MODE>                    Agent execution mode [default: batch] (batch | interactive)
```

The `--launcher` flag embeds the launcher binary into the output, producing a single file that contains both the runtime and the encrypted payload. Without it, only the encrypted payload is produced.

Batch mode runs the agent once and captures output. Interactive mode keeps the agent running with stdin/stdout pipes for multi-turn conversations.

**Examples:**

```bash
# Compile a Python agent into a sealed binary
seal compile \
  --project ./my-agent \
  --user-fingerprint a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2 \
  --sandbox-fingerprint auto \
  --output ./my-agent.sealed \
  --launcher ./target/release/agent-seal-launcher \
  --backend nuitka

# Use pyinstaller backend
seal compile \
  --project ./my-agent \
  --user-fingerprint $USER_FP \
  --output ./out.sealed \
  --backend pyinstaller

# Produce only the encrypted payload (no launcher assembly)
seal compile \
  --project ./my-agent \
  --user-fingerprint $USER_FP \
  --output ./payload.asl
```

---

### `seal keygen` — Generate signing keys

Generates an Ed25519 keypair for builder signing. Creates two files:

- `key` — 64-hex secret key (KEEP SECRET)
- `key.pub` — 64-hex public key (safe to distribute)

```text
Usage: seal keygen [OPTIONS]
Options:
  --keys-dir <PATH>    Output directory for key files [default: ~/.agent-seal/keys]
```

**Examples:**

```bash
seal keygen
seal keygen --keys-dir ./my-keys
```

---

### `seal sign` — Sign a sealed binary

Appends an Ed25519 signature and the builder's public key to a sealed binary. The signature covers all bytes preceding it, header + mode + chunks + footer.

```text
Usage: seal sign [OPTIONS] --key <KEY> --binary <BINARY>
Options:
  --key <PATH>       Path to 64-hex secret key file
  --binary <PATH>    Path to sealed binary to sign
```

**Examples:**

```bash
seal sign --key ~/.agent-seal/keys/key --binary ./my-agent.sealed
```

---

### `seal verify` — Verify a sealed binary's signature

Verifies the Ed25519 signature on a sealed binary. If `--pubkey` is not provided, the embedded public key (appended by `seal sign`) is used. This implements Trust-on-First-Use (TOFU): enterprises trust the first public key they see per builder.

```text
Usage: seal verify [OPTIONS] --binary <BINARY>
Options:
  --binary <PATH>        Path to sealed binary to verify
  --pubkey <PATH>        Path to 64-hex public key file (optional; uses embedded key if omitted)
```

**Examples:**

```bash
# Verify with embedded public key
seal verify --binary ./my-agent.sealed

# Verify with explicit public key
seal verify --binary ./my-agent.sealed --pubkey ./builder-key.pub
```

---

### `seal launch` — Execute a sealed agent

Decrypts and executes a sealed payload from memory using memfd + fexecve. Derives decryption keys from the master secret, runtime fingerprint, and user fingerprint. Linux only.

```text
Usage: seal launch [OPTIONS]
Options:
  --payload <PATH>                Path to sealed binary or encrypted payload
  --fingerprint-mode <MODE>       Fingerprint collection mode [default: stable] (stable | session)
  --user-fingerprint <HEX>        64-hex user identity (32 bytes) [required]
  --mode <MODE>                   Execution mode [default: batch] (batch | interactive)
  --max-lifetime <SECS>           Maximum process lifetime in seconds (interactive mode)
  --grace-period <SECS>           Grace period before SIGKILL after lifetime expires [default: 30]
  --verbose                       Enable debug-level logging
```

**Fingerprint modes:**
- `stable` — Uses only restart-survivable signals (machine-id, hostname, kernel, cgroup). Best for persistent environments.
- `session` — Includes ephemeral signals (namespace inodes, UIDs). Best for short-lived containers where you want stricter binding.

#### Execution modes

- **batch** (default): Launches the agent, captures stdout/stderr/exit code, returns `ExecutionResult`. One-shot execution.
- **interactive**: Forks the agent with stdin/stdout/stderr pipes. The launcher becomes a process supervisor. Supports `--max-lifetime` for timeout enforcement and `--grace-period` for graceful shutdown.

If `--payload` is omitted or set to `self`, the launcher extracts the embedded payload from its own executable (the assembled binary created by `seal compile --launcher`).

**Examples:**

```bash
# Run an assembled sealed binary (self-extracting)
AGENT_SEAL_MASTER_SECRET_HEX=... ./my-agent.sealed --user-fingerprint $FP

# Run via seal launch with explicit payload
AGENT_SEAL_MASTER_SECRET_HEX=... \
  seal launch \
  --payload ./payload.asl \
  --user-fingerprint $FP \
  --fingerprint-mode stable \
  --verbose

# Session mode for ephemeral containers
AGENT_SEAL_MASTER_SECRET_HEX=... \
  seal launch \
  --payload ./payload.asl \
  --user-fingerprint $FP \
  --fingerprint-mode session

# Interactive mode with lifetime limit
AGENT_SEAL_MASTER_SECRET_HEX=... \
  seal launch \
  --payload ./payload.asl \
  --user-fingerprint $FP \
  --mode interactive \
  --max-lifetime 300 \
  --grace-period 10
```

**Decryption failure** means the runtime fingerprint, user fingerprint, or master secret does not match what was used at compile time. This is by design — the payload is bound to a specific environment.

---

### `seal server` — Orchestration API

Starts the Agent Seal orchestration server. Provides a REST API for compiling agents, dispatching them to Docker sandboxes, and collecting execution results.

```text
Usage: seal server [OPTIONS]
Options:
  --bind <ADDR>                   Listen address [default: 127.0.0.1:9090]
  --compile-dir <PATH>            Directory for compile artifacts [default: ./.agent-seal/compile]
  --output-dir <PATH>             Directory for output binaries [default: ./.agent-seal/output]
```

#### Server API Routes

| Method | Route | Auth | Description |
|--------|-------|------|-------------|
| GET | `/health` | none | Health check with job count |
| POST | `/api/v1/compile` | none | Submit a compile job |
| POST | `/api/v1/dispatch` | none | Dispatch a compiled job to a sandbox |
| GET | `/api/v1/jobs/{job_id}` | none | Get job status |
| GET | `/api/v1/jobs/{job_id}/results` | none | Get job execution results |

#### Job Lifecycle

```
pending -> compiling -> ready -> dispatched -> running -> completed
                                                    \-> failed (at any stage)
```

#### `POST /api/v1/compile`

```json
{
  "project_dir": "/path/to/agent",
  "user_fingerprint": "64-hex-string",
  "sandbox_fingerprint": "64-hex-string"
}
```

> **Note:** `project_dir` must be within the server's configured `--compile-dir`. Paths outside the workspace are rejected with `400 Bad Request`.

Response `202 Accepted`:
```json
{
  "job_id": "job-1744032000-1-a1b2c3d4",
  "status": "pending"
}
```

#### `POST /api/v1/dispatch`

```json
{
  "job_id": "job-1744032000-1-a1b2c3d4",
  "sandbox": {
    "image": "python:3.11-slim",
    "timeout_secs": 120,
    "memory_mb": 512,
    "env": [["AGENT_PROMPT", "What is 2+2?"]]
  }
}
```

Response `202 Accepted`:
```json
{
  "job_id": "job-1744032000-1-a1b2c3d4",
  "status": "dispatched"
}
```

#### `GET /api/v1/jobs/{job_id}/results`

Response `200 OK`:
```json
{
  "job_id": "job-1744032000-1-a1b2c3d4",
  "status": "completed",
  "result": {
    "exit_code": 0,
    "stdout": "{\"answer\":\"4\",\"mode\":\"standalone\"}\n",
    "stderr": "[agent] Prompt: What is 2+2?\n[agent] Standalone mode\n[agent] Done\n"
  }
}
```

**Examples:**

```bash
# Start the server
seal server --bind 127.0.0.1:9090

# Submit a compile job
curl -X POST http://127.0.0.1:9090/api/v1/compile \
  -H 'Content-Type: application/json' \
  -d '{"project_dir":"./my-agent","user_fingerprint":"...","sandbox_fingerprint":"..."}'

# Poll job status
curl http://127.0.0.1:9090/api/v1/jobs/job-1744032000-1-a1b2c3d4

# Dispatch to Docker sandbox
curl -X POST http://127.0.0.1:9090/api/v1/dispatch \
  -H 'Content-Type: application/json' \
  -d '{"job_id":"job-...","sandbox":{"image":"python:3.11-slim","timeout_secs":60}}'

# Get execution results
curl http://127.0.0.1:9090/api/v1/jobs/job-.../results
```

---

## Configuration

### Environment variables

| Variable | Component | Description |
|----------|-----------|-------------|
| `AGENT_SEAL_MASTER_SECRET_HEX` | launch | 64-hex master secret for HKDF key derivation |
| `AGENT_SEAL_LAUNCHER_PATH` | compile | Path to launcher binary (alternative to `--launcher`) |
| `AGENT_SEAL_LAUNCHER_SIZE` | launch | Launcher binary size (for self-extraction) |
| `RUST_LOG` | all | Tracing level/filter (e.g. `debug`, `info`, `agent_seal=trace`) |

---

## Development

### Format and lint

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
```

### Tests and coverage

```bash
cargo nextest run --workspace
cargo llvm-cov nextest --workspace --ignore-filename-regex "main\.rs" --lcov --output-path lcov.info --fail-under-lines 90
```

### CI summary

CI runs on pushes to `main` and pull requests:

- `fmt` check
- `clippy` (all targets)
- `nextest` + `llvm-cov` (90% minimum)
- release workspace build

## License

MIT
