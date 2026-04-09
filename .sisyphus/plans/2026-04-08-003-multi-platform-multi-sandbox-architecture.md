# Multi-Platform, Multi-Sandbox Architecture

**Status**: Specification  
**Date**: April 8, 2026  
**Predecessor**: v0.2 implementation plan (`.sisyphus/plans/2026-04-08-002-v02-agent-seal-implementation-plan.md`)

---

## Goal

Evolve Agent Seal from its current single-language, single-sandbox design to support:

1. **Multiple compile backends**: Python (Nuitka/PyInstaller), Go, Node.js, Rust, and pre-built binaries
2. **Multiple sandbox targets**: Docker, Firecracker microVMs, with a trait-based abstraction for future targets
3. **Cross-platform launchers**: Linux (current), macOS, and Windows execution

All while keeping the core value proposition intact: **one sealed binary, zero config, fingerprint-bound, signed by builder.**

## Design Principles

- **Three orthogonal trait axes**: sandbox provisioning, language compilation, platform execution — each independently shippable
- **Core stays frozen**: `agent-seal-core` (crypto, payload format, signing, key derivation) and `agent-seal-fingerprint` (fingerprint model) are versioned stability boundaries
- **Feature gates, not runtime dispatch**: Platform-specific code uses `#[cfg(target_os)]`, not runtime OS detection. Each launcher binary is compiled per-target triple.
- **All backends produce the same artifact**: A native executable that gets encrypted. The backend abstraction is "compile this project into a native binary," not "manage the encryption pipeline."
- **Preserve the assembled binary format**: `launcher_bytes ++ SENTINEL ++ encrypted_payload ++ footer ++ signature_block` — this is the wire format
- **Incremental migration**: Each axis (sandbox, compiler, launcher) can be extracted independently without breaking the others

## What Must NOT Change

These are load-bearing walls:

| Boundary | Reason |
|----------|--------|
| `agent-seal-core` crate | Protocol specification — payload format, AES-256-GCM, HKDF, Ed25519, error types |
| `FingerprintSnapshot` + `RuntimeKind` + canonicalization | Identity system — additive-only for new variants |
| Assembled binary format (`launcher_bytes ++ SENTINEL ++ payload ++ footer ++ sig`) | Wire format |
| `ExecutionOps` trait surface (`create_fd → write → seal → exec`) | Cross-platform contract |
| `ExecConfig` / `ExecutionResult` types | Cross-component API |

---

## Phase 1: Sandbox Backend Trait Extraction

**Effort**: Short (1-2 days)  
**Ships independently**: Yes  
**Unblocks**: Firecracker backend, Kata Containers

### Current State

`SandboxProvisioner` is a concrete struct in `sandbox.rs` that hardcodes Docker CLI commands. Free functions `copy_into_sandbox()` and `exec_in_sandbox()` are module-level functions that take a `SandboxProvisioner` reference.

### Target State

```rust
// crates/agent-seal-server/src/sandbox/mod.rs
pub mod docker;
pub mod firecracker;  // Phase 3

#[async_trait]
pub trait SandboxBackend: Send + Sync {
    /// Provision a sandbox environment, return opaque handle
    async fn provision(&self, config: &SandboxConfig) -> Result<SandboxHandle, SealError>;

    /// Copy a file into the sandbox
    async fn copy_into(&self, handle: &SandboxHandle, host_path: &Path, target: &str) -> Result<(), SealError>;

    /// Execute a command inside the sandbox
    async fn exec(&self, handle: &SandboxHandle, command: &str, timeout_secs: u64) -> Result<ExecutionResult, SealError>;

    /// Collect fingerprint from running sandbox
    async fn collect_fingerprint(&self, handle: &SandboxHandle) -> Result<FingerprintSnapshot, SealError>;

    /// Destroy the sandbox and release resources
    async fn destroy(&self, handle: &SandboxHandle) -> Result<(), SealError>;

    /// Which runtime kind this backend provisions
    fn runtime_kind(&self) -> RuntimeKind;
}
```

### Migration Steps

1. Create `sandbox/mod.rs` with `SandboxBackend` trait
2. Move current `SandboxProvisioner` to `sandbox/docker.rs`, rename to `DockerBackend`, implement `SandboxBackend`
3. Convert free functions to trait methods on `SandboxBackend`
4. `SandboxHandle` gains `backend_data: HashMap<String, String>` for backend-specific state (Docker: `container_id`, Firecracker: `vm_id` + `socket_path`)
5. `ServerState` holds `Arc<dyn SandboxBackend>` instead of inline `SandboxProvisioner::new()`
6. Dispatch route selects backend via optional `runtime_kind` field in `DispatchRequest`

### Docker Hardening (DONE)

Already implemented in this session:
- `--security-opt no-new-privileges:true`
- `--cap-drop ALL`
- `--read-only`
- `--tmpfs /tmp`
- `--pids-limit 64`

### Tests

- Existing Docker stub tests updated to test against `dyn SandboxBackend`
- New `SandboxBackend` trait tests with mock backend

---

## Phase 2: Compiler Backend Trait Extraction

**Effort**: Short (1-2 days)  
**Ships independently**: Yes  
**Unblocks**: Go, Node.js, Rust, passthrough backends

### Current State

`Backend` enum in `compile.rs` with two variants: `Nuitka`, `PyInstaller`. `compile_agent()` matches on the enum and calls the appropriate function. PyInstaller requires `main.py`.

### Target State

```rust
// crates/agent-seal-compiler/src/backend/mod.rs
pub mod nuitka;
pub mod pyinstaller;
// Future: nodejs, golang, rust_static, passthrough

pub trait CompileBackend: Send + Sync {
    /// Human-readable name for logging/errors
    fn name(&self) -> &str;

    /// Detect if this backend can handle the given project
    fn can_compile(&self, project_dir: &Path) -> bool;

    /// Compile the project into a native executable
    fn compile(&self, config: &CompileConfig) -> Result<PathBuf, SealError>;
}

pub struct CompileConfig {
    pub project_dir: PathBuf,
    pub output_dir: PathBuf,
    pub target_triple: String,
    pub timeout_secs: u64,
}

pub struct ChainBackend {
    backends: Vec<Box<dyn CompileBackend>>,
}
```

### Backend Auto-Detection

| Backend | Detection Signal | Produces |
|---------|-----------------|---------|
| Nuitka | `main.py` or `setup.py` | Linux ELF via Python → C compilation |
| PyInstaller | `main.py` | Linux ELF via Python import freezing |
| Go | `go.mod` | Static Linux ELF via `go build -ldflags '-s -w'` |
| Node.js | `package.json` | Static Linux ELF via `pkg` or `sea` |
| Rust | `Cargo.toml` | Static Linux ELF via `cargo build --release --target x86_64-unknown-linux-musl` |
| Passthrough | Existing ELF/Mach-O/PE binary | No compilation, just validates |

### CLI Changes

```bash
# Current
seal compile --project ./agent --backend nuitka ...

# After: auto-detect or explicit
seal compile --project ./agent                           # auto-detect via can_compile()
seal compile --project ./go-agent --language go              # explicit language
seal compile --project ./go-agent --backend golang          # explicit backend
```

### Fallback Behavior

Replace the implicit `nuitka fails → try pyinstaller` fallback with an explicit `ChainBackend`:

```rust
let backend = ChainBackend::new(vec![
    Box::new(NuitkaBackend),
    Box::new(PyInstallerBackend),
]);
let result = backend.compile(config)?;
```

### Tests

- `can_compile` returns correct detection for each project type
- `ChainBackend` tries backends in order, stops on first success
- Existing backend tests preserved

---

## Phase 3: Cross-Platform Launchers

**Effort**: Medium (3-5 days)  
**Ships independently**: Each platform ships separately  
**Depends on**: Phase 1 (sandbox), Phase 2 (compiler) optional

### Architecture

The launcher crate splits into platform-agnostic core and platform-specific modules:

```
crates/agent-seal-launcher/
  src/
    lib.rs                # platform-agnostic orchestration
                            # (crypto, payload, signature, key derivation)
    exec/
      mod.rs              # ExecutionOps trait + re-exports
      linux.rs            # KernelMemfdOps (current memfd + fexecve)
      macos.rs            # DarwinExecOps (tmpfile + posix_spawn + unlink)
      windows.rs          # WindowsExecOps (VirtualAlloc + CreateProcess)
    protection/
      mod.rs              # re-exports platform protections
      linux.rs            # PR_SET_DUMPABLE, ptrace::traceme(), seccomp
      macos.rs            # PT_DENY_ATTACH, sandbox-exec, amfid
      windows.rs          # Job objects, SetProcessMitigationPolicy, CFG
    cleanup/
      mod.rs              # re-exports platform cleanup
      linux.rs            # /proc/self/exe unlink (current)
      macos.rs            # unlink(argv[0])
      windows.rs          # MoveFileExW(DELETE_ON_CLOSE)
```

### ExecutionOps Trait (renamed from MemfdOps)

```rust
pub trait ExecutionOps: Send + Sync {
    fn create_fd(&self, name: &str) -> Result<OwnedFd, SealError>;
    fn write(&self, fd: &OwnedFd, data: &[u8]) -> Result<(), SealError>;
    fn seal(&self, fd: &OwnedFd) -> Result<(), SealError>;
    fn exec(&self, fd: OwnedFd, argv: &[CString], envp: &[CString]) -> Result<(), SealError>;
}
```

### Platform Details

#### Linux (current — unchanged)
- `create_fd`: `memfd_create()`
- `write`: `write()`
- `seal`: `memfd_seal()`
- `exec`: `fexecve()`
- Protections: `PR_SET_DUMPABLE(0)`, `ptrace::traceme()`, seccomp allowlist
- Cleanup: `unlink(/proc/self/exe)`

#### macOS (new)
- `create_fd`: `mkstemp()` with appropriate template
- `write`: `write()`
- `seal`: `fchmod(fd, 0o111)` (make executable)
- `exec`: `posix_spawn_file_actions()` + `posix_spawn()`
- Protections: `PT_DENY_ATTACH`, `sandbox-exec` sandbox profile, `amfid` code signing
- Cleanup: `unlink(argv[0])` immediately after fork, before exec
- **Caveat**: macOS Apple Silicon requires code signing for executables. Options:
  - Ad-hoc sign: `codesign -s -` (requires Developer ID, triggers UI prompt on first run)
  - Hardened runtime entitlements: `codesign --entitlements seal-launcher.ent`
  - Anonymous: `codesign -s -f -` (available since macOS 12, no Developer ID needed)

#### Windows (new)
- `create_fd`: N/A — `VirtualAlloc(MEM_COMMIT | MEM_RESERVE)` returns raw pointer
- `write`: `WriteProcessMemory()`
- `seal`: N/A — memory is already committed
- `exec`: `CreateProcessW()` with `EXTENDED_STARTUPINFO_EX` + `PROC_THREAD_ATTRIBUTE_JOB_OBJECT`
- Protections: `SetProcessMitigationPolicy()` with ACG, CFG, CET
- Cleanup: `MoveFileExW(path, NULL, MOVEFILE_DELAY_UNTIL_REBOOT)` (set `DELETE_ON_CLOSE` on handle)
- **Caveat**: Windows Defender SmartScreen blocks unsigned executables from the internet. Enterprises manage this via policy.

### Cargo.toml Changes

```toml
[target.'cfg(target_os = "linux")']
dependencies = { nix = { workspace = true, features = ["process", "fs", "sched", "signal", "ptrace"] } }

[target.'cfg(target_os = "macos")']
dependencies = { libc = "0.2" }

[target.'cfg(target_os = "windows")']
dependencies = { windows-sys = "0.59" }
```

### Platform Binary Naming

| Platform | Binary Name | Format |
|----------|-------------|--------|
| Linux x86_64 | `seal-launcher-linux-x86_64` | ELF static (musl) |
| macOS arm64 | `seal-launcher-darwin-arm64` | Mach-O (signed) |
| Windows x86_64 | `seal-launcher-windows-x86_64.exe` | PE (signed) |

### Tests

- Linux tests remain unchanged
- macOS tests use `#[cfg(target_os = "macos")]` — CI needs macOS runner
- Windows tests use `#[cfg(target_os = "windows")]` — CI needs Windows runner
- Platform-agnostic tests in `lib.rs` verify the shared orchestration path

---

## Phase 4: Firecracker Backend

**Effort**: Medium (2-3 days)  
**Depends on**: Phase 1 (sandbox trait)  
**Unblocks**: MicroVM isolation with attestation

### Architecture

Firecracker uses a REST API (Unix socket), not Docker CLI. The `SandboxBackend` trait already accommodates this.

```rust
pub struct FirecrackerBackend {
    api_socket: PathBuf,
    kernel_path: PathBuf,     // vmlinux
    rootfs_path: PathBuf,     // rootfs.ext4
}
```

### Key Design Decision: Copy Strategy

Unlike Docker (which copies files into a running container), Firecracker has three options:

| Strategy | Pros | Cons |
|---------|-------|-------|
| Bake into rootfs at provision time | Simple, no post-boot API calls | Slower provision |
| virtio-vsock after boot | Fast, flexible | Complex vsock setup in guest |
| HTTP metadata service | Standard pattern | Requires guest agent |

**Recommendation**: Bake the sealed binary into the rootfs image during `provision()`. This means `copy_into()` becomes a no-op for Firecracker (payload already in rootfs). The rootfs image can be pre-built with a base layer containing the launcher, and provision just adds the encrypted payload layer.

### REST API Flow

```
PUT  /machine-config    → vcpu_count, mem_size_mib
PUT  /boot-source      → kernel_image_path, boot_args="console=ttyS0 init=/agent.bin"
PUT  /drives/rootfs    → path_on_host=rootfs.ext4, is_root_device=true
PUT  /actions          → InstanceStart
GET  /                 → Instance info (wait for running state)
PUT  /actions          → SendCtrlAltDel
```

### Handle Data

```rust
SandboxHandle {
    backend_data: {
        "vm_id": "i-12345678",
        "socket_path": "/tmp/firecracker.sock",
    }
}
```

### Attestation Path (Future)

Firecracker backend enables future attestation integration:
- Launcher sends attestation quote to seal server
- Server verifies quote against CPU measurement registers
- Binds `master_secret` release to verified TEE environment

This is NOT implemented in this phase but the backend abstraction is designed to support it.

---

## Phase 5: Go Language Backend

**Effort**: Short (1 day)  
**Depends on**: Phase 2 (compiler trait)  
**Rationale**: Easiest new language to add — `go build` produces static binaries natively

### Implementation

```rust
pub struct GoBackend;

impl CompileBackend for GoBackend {
    fn name(&self) -> &str { "go" }
    fn can_compile(&self, project_dir: &Path) -> bool {
        project_dir.join("go.mod").exists()
    }
    fn compile(&self, config: &CompileConfig) -> Result<PathBuf, SealError> {
        compile_with_command("go", config)
    }
}
```

### Compile Command

```bash
cd $PROJECT_DIR && \
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -ldflags '-s -w -extldflags "-static"' \
  -o $OUTPUT_DIR/agent.bin .
```

- `CGO_ENABLED=0`: Pure Go, no libc dependency
- `-s -w`: Strip debug info and symbol tables
- `-extldflags "-static"`: Fully static binary (no dynamic linker)

### Project Requirements

- `go.mod` must exist
- Must have a `package main` with `func main()`
- No CGO dependencies (static linking requirement)

---

## Cargo Workspace Changes

```
crates/
  agent-seal-core/          # UNCHANGED
  agent-seal-fingerprint/   # UNCHANGED (additive RuntimeKind only)
  agent-seal-compiler/
    src/
      backend/              # NEW: CompileBackend trait + registry
        mod.rs
        nuitka.rs           # MOVED from compile.rs
        pyinstaller.rs       # MOVED from compile.rs
  agent-seal-launcher/
    src/
      exec/                  # NEW: ExecutionOps trait
        mod.rs
        linux.rs             # RENAMED from memfd_exec.rs
        macos.rs             # NEW
        windows.rs           # NEW
      protection/           # NEW
        mod.rs
        linux.rs
        macos.rs
        windows.rs
      cleanup/              # NEW
        mod.rs
        linux.rs
        macos.rs
        windows.rs
      anti_debug.rs         # MOVED to protection/linux.rs
      self_delete.rs        # MOVED to cleanup/linux.rs
  agent-seal-server/
    src/
      sandbox/
        mod.rs              # NEW: SandboxBackend trait
        docker.rs           # MOVED from sandbox.rs
        firecracker.rs      # NEW
  agent-seal/               # UNCHANGED (umbrella CLI)
```

---

## Implementation Sequencing

| Phase | Effort | Ships independently | Unblocks | Risk |
|-------|--------|---------------------|-----------|------|
| 1. Sandbox trait | 1-2d | Yes | Firecracker | Low — pure refactor |
| 2. Compiler trait | 1-2d | Yes | New languages | Low — pure refactor |
| 3. macOS launcher | 3-5d | Yes | macOS users | Medium — code signing complexity |
| 4. Firecracker backend | 2-3d | No (needs Phase 1) | MicroVM isolation | Medium — copy_into challenge |
| 5. Go backend | 1d | No (needs Phase 2) | Go language support | Low — straightforward |
| 6. Windows launcher | 3-5d | Yes | Windows users | Medium — Defender/ACL issues |

Total: ~12-18 days for all six phases.

---

## Open Questions

1. **macOS code signing**: Ad-hoc signing (`codesign -s -`) requires user interaction on first run. Is this acceptable for the "zero config" goal, or do we need an Apple Developer ID?
2. **Firecracker rootfs strategy**: Bake-into-rootfs (simpler) or vsock-transfer (more flexible)? This affects the `copy_into` trait method design.
3. **Node.js SEA vs pkg**: Which produces more reliable standalone binaries? Need to evaluate before implementing.
4. **Windows launcher: should it be a standalone EXE or use the `seal` umbrella binary?** The umbrella binary is designed for Linux. Windows users might expect `seal.exe`.
