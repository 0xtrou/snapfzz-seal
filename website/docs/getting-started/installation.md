# Installation

## Prerequisites

- Rust toolchain (stable, edition 2024)
- clippy and rustfmt components
- Linux musl linker support

## Build from Source

```bash
git clone https://github.com/0xtrou/agentseal.git
cd agentseal
cargo build --release
cargo install --path crates/agent-seal
```

## Verify

```bash
seal --version
```