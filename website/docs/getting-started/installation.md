---
sidebar_position: 1
---

# Installation

This section describes deterministic installation and verification procedures for Snapfzz Seal.

## System requirements

### Required toolchain

- Rust toolchain: stable channel, edition 2024 compatible
- Cargo: installed with Rust toolchain
- Git: for source checkout
- OpenSSL CLI: used in many operational examples

### Runtime assumptions

- Linux is the production target for complete launcher behavior.
- macOS and Windows may be used for development workflows, but behavior differs by platform.

### Optional dependencies

- Python build ecosystem if using Python-oriented compile backends.
- Docker engine when using server-side sandbox execution.

## Platform notes

### Linux

Linux is the primary supported execution platform for sealed runtime behavior. Linux-specific controls include process hardening and seccomp filter application.

### macOS

macOS development is supported for selected workflows. Security behavior differs from Linux. Production deployment should be validated against explicit acceptance criteria.

### Windows

Windows support is limited for current launcher semantics. Use Linux for production execution of sealed payloads.

## Build from source

```bash
git clone https://github.com/0xtrou/snapfzz-seal.git
cd snapfzz-seal
cargo build --release
cargo install --path crates/snapfzz-seal
```

The installed binary is `seal`.

## Reproducible local build

For CI-style local validation:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --release --workspace
```

## Verify installation

### Binary resolution

```bash
which seal
seal --version
seal --help
```

Expected behavior:

- `which seal` prints a single resolved path.
- `seal --version` returns non-empty version output.
- `seal --help` lists subcommands: `compile`, `keygen`, `launch`, `server`, `sign`, `verify`.

### Key generation smoke test

```bash
seal keygen
ls -l ~/.snapfzz-seal/keys/
```

Expected files:

- `~/.snapfzz-seal/keys/builder_secret.key`
- `~/.snapfzz-seal/keys/builder_public.key`

## Security considerations

- Build hosts should be treated as high-trust assets.
- Signing key generation should occur on controlled hosts only.
- Secret key files should have minimal file permissions and should never be committed to source control.

## Limitations

- A package manager distribution channel is not currently defined in this repository.
- Cross-platform parity is incomplete for runtime hardening behavior.
- Build reproducibility across heterogeneous toolchains is not guaranteed without pinned compiler and dependency versions.
