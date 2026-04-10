# Crate Overview

This section describes the crate-level architecture and API surface of Snapfzz Seal.

## Workspace members

| Crate | Responsibility |
|---|---|
| `snapfzz-seal` | Primary CLI entrypoint (`seal`) |
| `snapfzz-seal-core` | Cryptographic primitives, payload types, error model |
| `snapfzz-seal-fingerprint` | Host and runtime signal collection and canonicalization |
| `snapfzz-seal-compiler` | Project compilation, payload assembly, embed operations |
| `snapfzz-seal-launcher` | Runtime verification, key derivation, in-memory execution |
| `snapfzz-seal-server` | Orchestration API and sandbox dispatch |

## Dependency graph

```text
snapfzz-seal (CLI)
  -> snapfzz-seal-compiler
      -> snapfzz-seal-core
      -> snapfzz-seal-fingerprint
  -> snapfzz-seal-launcher
      -> snapfzz-seal-core
      -> snapfzz-seal-fingerprint
  -> snapfzz-seal-server
      -> snapfzz-seal-core
      -> snapfzz-seal-compiler
      -> snapfzz-seal-fingerprint
```

`/crates/snapfzz-seal-core` is the cryptographic and structural foundation. Most crates depend on it directly or indirectly.

## API surface by crate

### `snapfzz-seal`

- CLI command tree (`compile`, `keygen`, `launch`, `server`, `sign`, `verify`)
- Argument mapping to lower-level crate interfaces
- Process exit behavior for command failures

Example command dispatch entry:

```rust
match cli.command {
    Command::Compile(cli) => compile::run(cli),
    Command::Launch(cli) => launch::run(cli),
    Command::Sign(cli) => sign::run(cli),
    // ...
}
```

### `snapfzz-seal-core`

Key exported modules include:

- `crypto`: stream encryption and decryption
- `derive`: HKDF-based key derivation
- `payload`: header parsing, payload packing and unpacking
- `signing`: Ed25519 key generation, sign and verify
- `tamper`: hash and integrity verification helpers
- `types`: canonical constants and wire structures

### `snapfzz-seal-fingerprint`

- `FingerprintCollector` for stable and ephemeral data capture
- `canonicalize_stable` and `canonicalize_ephemeral` for deterministic hashing
- source model registry through `FINGERPRINT_SOURCES`

### `snapfzz-seal-compiler`

- Backend abstraction (`CompileBackend` trait)
- Backend implementations for language-specific builds
- `assemble` stage for launcher plus payload composition
- marker-based embed utilities for launcher metadata

### `snapfzz-seal-launcher`

- Signature verification
- Runtime fingerprint-driven key derivation
- launcher integrity checks
- memfd executor and stream I/O control
- platform protection hooks

### `snapfzz-seal-server`

- HTTP routes for compile, dispatch, and job status
- sandbox interface trait and Docker backend
- asynchronous job state transitions and artifact management

## Practical usage example

A minimal end-to-end integration from CLI perspective:

```bash
seal compile --project ./examples/demo_agent --user-fingerprint "$USER_FP" --output ./agent.sealed
seal sign --key ~/.snapfzz-seal/keys/builder_secret.key --binary ./agent.sealed
seal launch --payload ./agent.sealed --user-fingerprint "$USER_FP"
```

## Security Architecture

### Defense-in-Depth Layers

Snapfzz Seal implements 6 security layers to protect master secrets:

| Layer | Module | Protection |
|-------|--------|------------|
| 1 | `build.rs` | Random markers |
| 2 | `shamir.rs` | Secret sharing |
| 3 | `decoys.rs` | Decoy secrets |
| 4 | `anti_analysis.rs` | Debugger/VM detection |
| 5 | `integrity.rs` | Binary hash binding |
| 6 | `whitebox/` | Lookup table cryptography |

**Combined Effect:** Weeks-months of expert cryptanalysis required.

### Key Security Components

#### snapfzz-seal-core
- `shamir`: Shamir Secret Sharing implementation (GF(2^256))
- `integrity`: ELF binary parsing and integrity verification
- `whitebox`: White-box AES-256 with T-boxes and mixing tables
- `build.rs`: Compile-time random marker generation

#### snapfzz-seal-compiler
- `decoys`: Decoy secret set generation and embedding
- `whitebox_embed`: White-box table generation and binary embedding
- `embed`: Shamir share splitting and embedding

#### snapfzz-seal-launcher
- `anti_analysis`: Runtime environment analysis (debugger, VM, timing)
- `integrity`: Binary hash computation and verification
- `protection`: Process hardening and security hooks

### Security Guarantees

**Before (Pre-v0.2):**
- Master secret trivially extractable
- Basic tools sufficient for extraction

**After (v0.2+):**
- Master secret protected by 6 layers
- Key spread across ~500KB-2MB of lookup tables
- Requires expert-level reverse engineering

The above flow traverses `snapfzz-seal` -> compiler/core -> launcher/core/fingerprint crates.

## Security considerations

- Cryptographic operations are centralized in `snapfzz-seal-core` to reduce duplicated logic.
- Signature verification is executed by launcher path before payload execution.
- Server crate should be deployed with strict perimeter controls due to orchestration capabilities.

## Limitations

- API stability policy across crate internals is not formally versioned yet.
- Backend behavior depends on host toolchain availability and may vary by environment.
- Cross-crate interfaces are documented by source and tests, not yet by generated API reference docs.
