---
title: "v0.2: Wire Security Internals, Interactive Mode, Builder Signing"
type: feat
status: active
date: 2026-04-08
origin: Oracle consultation + product redesign session
depends: 2026-04-07-001-feat-agent-seal-implementation-plan.md
---

# Agent Seal v0.2 Implementation Plan

## Overview

v0.1 delivered a working end-to-end pipeline: compile → encrypt → bind to fingerprint → launch via memfd → self-delete. v0.2 has three goals:

1. **Complete the security story** — wire existing but disconnected crypto primitives (embedded master secret, tamper verification, session fingerprint, payload footer)
2. **Add interactive/persistent agent mode** — sealed agents can run timeless as daemons, accept user input via NDJSON over stdin/stdout, manage encrypted workspace state, and run background tasks
3. **Add builder signing** — Ed25519 signatures so enterprises can verify binary provenance (who built this, has it been tampered with)

## Non-Negotiable Constraints

- 90% code coverage (CI-enforced via cargo-llvm-cov + nextest + --fail-under-lines 90)
- All tests pass: `cargo test --workspace`
- Clippy clean: `cargo clippy --workspace --all-targets -- -D warnings`
- Must work on Linux CI (ubuntu-latest, rustc 1.94.1) AND macOS (local dev)
- No new dependencies unless absolutely necessary (ed25519-dalek for signing is approved)
- Keep individual crate main.rs files working (`cargo run -p agent-seal-compiler` still works)
- Do NOT break existing batch mode functionality

---

## PHASE 1: Wire Security Internals

### TASK 1.1 — Wire embedded master secret into launcher

**Status:** pending
**Dependencies:** none
**Priority:** CRITICAL — current security model is broken

**Problem:** `assemble.rs` embeds the master secret into the binary via `SECRET_MARKER`. But `launcher/lib.rs:load_master_secret()` reads from env var `AGENT_SEAL_MASTER_SECRET_HEX` — the embedded secret is dead code. This means the master secret must be provided externally, defeating the purpose of sealing it into the binary.

**Changes:**
- `crates/agent-seal-launcher/src/lib.rs` — `load_master_secret()`: search binary bytes for `SECRET_MARKER`, extract embedded 32-byte secret. Fall back to env var only if marker not found (dev mode).
- `crates/agent-seal-launcher/src/lib.rs` — `run()`: call new `load_master_secret(payload_bytes)` instead of env-var version

**Acceptance Criteria:**
- [ ] `load_master_secret()` reads from binary bytes when SECRET_MARKER present
- [ ] Falls back to `AGENT_SEAL_MASTER_SECRET_HEX` env var when marker absent (dev mode)
- [ ] Existing tests pass (env-var path)
- [ ] New test: create temp binary with embedded secret, verify load_master_secret() extracts it
- [ ] New test: verify env var fallback works when marker absent
- [ ] `cargo clippy -p agent-seal-launcher --all-targets -- -D warnings` passes
- [ ] Coverage >= 90% on modified files

---

### TASK 1.2 — Wire tamper verification into run()

**Status:** pending
**Dependencies:** TASK 1.1 (embedded secret needed for tamper hash)
**Priority:** CRITICAL

**Problem:** `core/tamper.rs:verify_tamper()` is fully implemented but never called in `launcher/lib.rs:run()`. The tamper hash IS embedded during assembly but the launcher ignores it.

**Changes:**
- `crates/agent-seal-launcher/src/lib.rs` — `run()`: add `tamper::verify_tamper(payload_bytes)?` call after payload decryption, before `MemfdExecutor::execute()`
- Ensure error is `SealError::TamperDetected` with clear message

**Acceptance Criteria:**
- [ ] `run()` calls `verify_tamper()` on the raw payload bytes
- [ ] Returns `SealError::TamperDetected` when hash mismatch
- [ ] Existing tamper tests pass (they test the function itself)
- [ ] New integration test: modify payload bytes, verify run() rejects with TamperDetected
- [ ] `cargo clippy -p agent-seal-launcher --all-targets -- -D warnings` passes
- [ ] Coverage >= 90% on modified files

---

### TASK 1.3 — Fix session fingerprint mode

**Status:** pending
**Dependencies:** none
**Priority:** HIGH

**Problem:** `FingerprintMode::Session` is accepted via CLI but ignored — `run()` always uses `canonicalize_stable()`. The `derive_session_key()` function exists but is never called.

**Changes:**
- `crates/agent-seal-launcher/src/lib.rs` — `run()`: when `fingerprint_mode == FingerprintMode::Session`, use `canonicalize_ephemeral()` for fingerprint hash, then call `derive_session_key()` instead of `derive_env_key()`
- The decrypted payload must use the session key (K_session) not the env key (K_env)

**Acceptance Criteria:**
- [ ] Batch of tests with `FingerprintMode::Stable` still passes unchanged
- [ ] New tests: verify `FingerprintMode::Session` uses ephemeral signals in key derivation
- [ ] New test: verify different session fingerprints produce different keys
- [ ] `cargo clippy -p agent-seal-launcher --all-targets -- -D warnings` passes
- [ ] Coverage >= 90% on modified files

---

### TASK 1.4 — Implement payload footer

**Status:** pending
**Dependencies:** TASK 1.2 (footer needs tamper verification)
**Priority:** HIGH

**Problem:** `PayloadFooter` in `core/types.rs` is an empty struct. README documents `original_hash[32] + launcher_hash[32]` but nothing is written or read.

**Changes:**
- `crates/agent-seal-core/src/types.rs` — define `PayloadFooter { original_hash: [u8; 32], launcher_hash: [u8; 32] }`
- `crates/agent-seal-core/src/payload.rs` — add `write_footer()` and `read_footer()` functions
- `crates/agent-seal-compiler/src/assemble.rs` — call `write_footer()` after embedding encrypted payload
- `crates/agent-seal-launcher/src/lib.rs` — call `read_footer()` during payload parsing, verify hashes

**Acceptance Criteria:**
- [ ] `PayloadFooter` has correct fields (32-byte arrays)
- [ ] `write_footer()` serializes to 64 bytes
- [ ] `read_footer()` deserializes from 64 bytes, validates
- [ ] Assembler writes footer after encrypted payload
- [ ] Launcher reads and validates footer during payload parsing
- [ ] New tests: round-trip footer write/read
- [ ] New tests: modified footer detected as error
- [ ] `cargo test -p agent-seal-core -p agent-seal-compiler -p agent-seal-launcher` passes
- [ ] Coverage >= 90% on modified files

---

### TASK 1.5 — Remove dev-admin-token default

**Status:** pending
**Dependencies:** none
**Priority:** MEDIUM

**Problem:** `proxy/routes.rs` falls back to `"dev-admin-token"` if `AGENT_SEAL_ADMIN_TOKEN` env var not set. This is a security risk in production.

**Changes:**
- `crates/agent-seal-proxy/src/routes.rs` — require `AGENT_SEAL_ADMIN_TOKEN` env var, return error if missing

**Acceptance Criteria:**
- [ ] Server refuses to start without AGENT_SEAL_ADMIN_TOKEN env var
- [ ] Error message is clear about what env var to set
- [ ] Existing tests that set the env var still pass
- [ ] New test: verify startup fails without env var
- [ ] `cargo clippy -p agent-seal-proxy --all-targets -- -D warnings` passes

---

### TASK 1.6 — Wire server compile request fingerprints

**Status:** pending
**Dependencies:** none
**Priority:** MEDIUM

**Problem:** `server/routes.rs:70` has `user_fingerprint` and `sandbox_fingerprint` fields in the compile request, but both are ignored — hardcodes `FingerprintMode::Stable`.

**Changes:**
- `crates/agent-seal-server/src/routes.rs` — pass fingerprint fields from compile request to compiler options
- `crates/agent-seal-server/src/routes.rs` — map sandbox_fingerprint to FingerprintMode (auto → Stable, ephemeral → Session)

**Acceptance Criteria:**
- [ ] Compile request fingerprint fields are passed to compiler
- [ ] `sandbox_fingerprint: "ephemeral"` triggers Session mode
- [ ] `sandbox_fingerprint: "auto"` (default) triggers Stable mode
- [ ] New tests: verify fingerprint passthrough in compile endpoint
- [ ] `cargo clippy -p agent-seal-server --all-targets -- -D warnings` passes

---

## PHASE 2: Interactive Mode

### TASK 2.1 — Add AgentMode to payload metadata

**Status:** pending
**Dependencies:** TASK 1.4 (payload format change)
**Priority:** HIGH

**Problem:** No way for the launcher to know whether the agent expects batch or interactive execution.

**Changes:**
- `crates/agent-seal-core/src/types.rs` — add `AgentMode { Batch, Interactive }` enum
- `crates/agent-seal-core/src/payload.rs` — add mode field to `PayloadHeader`, read/write it in pack/unpack
- `crates/agent-seal-compiler/src/lib.rs` — add `--mode <batch|interactive>` CLI flag, write to payload header

**Acceptance Criteria:**
- [ ] `AgentMode` enum with Batch and Interactive variants
- [ ] Payload header includes mode field
- [ ] Compiler writes mode from CLI flag
- [ ] Launcher reads mode from payload header
- [ ] Default mode is Batch (backward compatible)
- [ ] New tests: round-trip mode through pack/unpack
- [ ] Coverage >= 90% on modified files

---

### TASK 2.2 — Add execute_interactive() to MemfdExecutor

**Status:** pending
**Dependencies:** TASK 2.1 (need to know mode)
**Priority:** HIGH

**Problem:** Current `MemfdExecutor::execute()` forks, waits, captures result, returns `ExecutionResult`. Interactive mode needs the parent to stay alive and relay stdin/stdout.

**Changes:**
- `crates/agent-seal-launcher/src/memfd_exec.rs` — add `execute_interactive()` that returns `InteractiveHandle { stdin: ChildStdin, stdout: ChildStdout, stderr: ChildStderr, child: Pid }`
- Parent enters relay loop using `select`/`poll` on all three fds
- SIGTERM/SIGINT handler: forward signal to child, wait for graceful shutdown, SIGKILL after timeout
- Heartbeat: if no stdout for configurable seconds, log warning (not fatal)

**Acceptance Criteria:**
- [ ] `execute_interactive()` returns a handle with open pipes and child pid
- [ ] Relay loop bridges stdin→child stdin, child stdout→stdout, child stderr→stderr
- [ ] SIGTERM to parent forwards to child
- [ ] Heartbeat timeout logs warning when no stdout received
- [ ] Existing `execute()` still works unchanged (batch mode)
- [ ] New tests: mock child process, verify relay behavior
- [ ] `cargo clippy -p agent-seal-launcher --all-targets -- -D warnings` passes
- [ ] Coverage >= 90% on modified files

---

### TASK 2.3 — Add --interactive flag to seal launch CLI

**Status:** pending
**Dependencies:** TASK 2.1, TASK 2.2
**Priority:** HIGH

**Problem:** No CLI flag to activate interactive mode.

**Changes:**
- `crates/agent-seal/src/launch.rs` — add `--interactive` flag to LaunchArgs
- `crates/agent-seal-launcher/src/lib.rs` — `run()`: when mode=Interactive, call `execute_interactive()` instead of `execute()`, enter relay loop
- Set `PYTHONUNBUFFERED=1` in child env (prevent pipe deadlocks with Python)
- Create workspace directory: `/tmp/agent-seal-{sandbox_id}/`
- Pass `AGENT_SEAL_WORKSPACE` and `AGENT_SEAL_SESSION_KEY_HEX` (hex of K_env) as env vars to child

**Acceptance Criteria:**
- [ ] `seal launch --interactive` activates interactive mode
- [ ] `seal launch` (no flag) still runs batch mode
- [ ] Workspace directory created before child starts
- [ ] Child receives AGENT_SEAL_WORKSPACE and session key env vars
- [ ] PYTHONUNBUFFERED=1 set in child env
- [ ] New tests: CLI flag parsing
- [ ] `cargo clippy -p agent-seal -p agent-seal-launcher --all-targets -- -D warnings` passes

---

### TASK 2.4 — Add signal forwarding and lifetime enforcement

**Status:** pending
**Dependencies:** TASK 2.2
**Priority:** MEDIUM

**Problem:** No way to limit how long an interactive agent runs, or forward OS signals properly.

**Changes:**
- `crates/agent-seal/src/launch.rs` — add `--max-lifetime <SECS>` and `--heartbeat-timeout <SECS>` CLI flags
- `crates/agent-seal-launcher/src/memfd_exec.rs` — add max_lifetime enforcement: after N seconds, send SIGTERM to child → wait → SIGKILL
- Signal forwarding: SIGTERM/SIGINT to parent → forward to child → wait for graceful shutdown → SIGKILL after timeout

**Acceptance Criteria:**
- [ ] `--max-lifetime 3600` terminates agent after 1 hour
- [ ] SIGTERM to launcher forwards to child process
- [ ] Graceful shutdown timeout: wait N seconds then SIGKILL (default 30s)
- [ ] `--heartbeat-timeout` warns when no stdout received
- [ ] New tests: signal forwarding, lifetime enforcement
- [ ] `cargo clippy -p agent-seal -p agent-seal-launcher --all-targets -- -D warnings` passes

---

## PHASE 3: Builder Signing

### TASK 3.1 — Add Ed25519 signing primitives to core

**Status:** pending
**Dependencies:** TASK 1.4 (footer format needed for signature placement)
**Priority:** HIGH

**Problem:** No way for enterprises to verify binary provenance.

**Changes:**
- Add `ed25519-dalek` to `crates/agent-seal-core/Cargo.toml`
- `crates/agent-seal-core/src/signing.rs` — new module with:
  - `keygen()` → (SecretKey, PublicKey)
  - `sign(private_key, data) -> Signature`
  - `verify(public_key, data, signature) -> bool`
- `crates/agent-seal-core/src/lib.rs` — add `pub mod signing`

**Acceptance Criteria:**
- [ ] `ed25519-dalek` dependency added
- [ ] `keygen()` returns a valid Ed25519 keypair
- [ ] `sign()` produces a 64-byte signature
- [ ] `verify()` returns true for valid signature, false for invalid/tampered
- [ ] New tests: keygen round-trip, sign+verify, tamper detection, wrong key rejection
- [ ] `cargo clippy -p agent-seal-core --all-targets -- -D warnings` passes
- [ ] Coverage >= 90% on signing.rs

---

### TASK 3.2 — Add seal sign / seal verify / seal keygen CLI commands

**Status:** pending
**Dependencies:** TASK 3.1, TASK 1.4
**Priority:** HIGH

**Problem:** No CLI commands for builder signing workflow.

**Changes:**
- NEW `crates/agent-seal/src/sign.rs` — `seal sign --key <KEY_PATH> --binary <BINARY_PATH>` reads binary, signs with private key, appends signature + public key to footer
- NEW `crates/agent-seal/src/verify.rs` — `seal verify --binary <BINARY_PATH> [--pubkey <PUBKEY_PATH>]` reads footer, verifies signature against embedded or provided pubkey
- NEW `crates/agent-seal/src/keygen.rs` — `seal keygen` generates Ed25519 keypair, saves to ~/.agent-seal/keys/
- `crates/agent-seal/src/main.rs` — add Sign, Verify, Keygen subcommands

**Acceptance Criteria:**
- [ ] `seal keygen` creates keypair in ~/.agent-seal/keys/
- [ ] `seal sign` appends signature + pubkey to binary footer
- [ ] `seal verify` validates signature against embedded pubkey
- [ ] `seal verify --pubkey <path>` validates against external pubkey
- [ ] `seal verify` prints builder pubkey fingerprint for TOFU
- [ ] Signing a tampered binary fails verification
- [ ] `cargo clippy -p agent-seal --all-targets -- -D warnings` passes
- [ ] Coverage >= 90% on new files

---

### TASK 3.3 — Add signature verification to launch chain

**Status:** pending
**Dependencies:** TASK 3.1, TASK 3.2
**Priority:** HIGH

**Problem:** Even if binary is signed, launcher doesn't verify signature before execution.

**Changes:**
- `crates/agent-seal-launcher/src/lib.rs` — `run()`: add signature verification step BEFORE fingerprint collection (reject untrusted builders before doing any work)
- Verification order: parse header → verify signature → collect fingerprint → derive key → verify tamper → decrypt → execute

**Acceptance Criteria:**
- [ ] Launcher verifies Ed25519 signature before any other processing
- [ ] Verification against embedded pubkey (TOFU model)
- [ ] `SealError::InvalidSignature` returned for tampered/untrusted binaries
- [ ] Unsigned binaries still work in batch mode (backward compatible for dev)
- [ ] New tests: verify chain rejects tampered signature
- [ ] `cargo clippy -p agent-seal-launcher --all-targets -- -D warnings` passes

---

### TASK 3.4 — Retire seal proxy → optional/dev-only

**Status:** pending
**Dependencies:** none
**Priority:** LOW

**Problem:** `seal proxy` is positioned as required infrastructure but the product direction is "one binary, zero config." Proxy should be optional.

**Changes:**
- `crates/agent-seal/src/proxy.rs` — add deprecation notice in CLI help text
- `crates/agent-seal/src/proxy.rs` — keep full functionality, just mark as "optional dev tool"
- Keep proxy crate code intact — it's useful for dev/testing and may become BYOK proxy later

**Acceptance Criteria:**
- [ ] `seal proxy --help` shows deprecation notice
- [ ] Proxy still works when invoked directly
- [ ] Existing proxy tests all pass
- [ ] No clippy warnings

---

## Dependency Graph

```
PHASE 1 (can run in parallel except where noted):
  1.1 Wire embedded master secret ───────────────────────┐
  1.2 Wire tamper verification ───── depends on 1.1 ──────┤
  1.3 Fix session fingerprint mode ───────────────────────┤
  1.4 Implement payload footer ───── depends on 1.2 ─────┤
  1.5 Remove dev-admin-token default ────────────────────┤
  1.6 Wire server compile fingerprints ───────────────────┘

PHASE 2 (depends on Phase 1):
  2.1 Add AgentMode to payload metadata ── depends on 1.4 ─┐
  2.2 Add execute_interactive() ─────── depends on 2.1 ──┤
  2.3 Add --interactive CLI flag ──────── depends on 2.1, 2.2
  2.4 Signal forwarding + lifetime ────── depends on 2.2 ──┘

PHASE 3 (depends on Phase 1):
  3.1 Add Ed25519 signing primitives ── depends on 1.4 ──┐
  3.2 Add seal sign/verify/keygen CLI ──── depends on 3.1, 1.4
  3.3 Add signature verification to launch ── depends on 3.1, 3.2
  3.4 Retire seal proxy ───────────────── independent
```

## Test Coverage Requirements

Every task MUST maintain >= 90% coverage on all modified files. The CI enforces this with:
```
cargo llvm-cov nextest --workspace --ignore-filename-regex "main\.rs" --fail-under-lines 90
```

After all tasks complete, verify:
```bash
cargo test --workspace          # all tests pass
cargo clippy --workspace --all-targets -- -D warnings  # no warnings
cargo llvm-cov nextest --workspace --ignore-filename-regex "main\.rs" --summary-only  # >= 90%
```
