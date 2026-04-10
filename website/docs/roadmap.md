---
sidebar_position: 7
---

# Roadmap

This document outlines implemented features and planned development directions for Snapfzz Seal.

## Currently Implemented

### Compilation Backends

| Backend | Status | Notes |
|---------|--------|-------|
| **Nuitka** | ✅ Implemented | Default Python backend |
| **PyInstaller** | ✅ Implemented | Alternative Python backend |
| **Go** | ✅ Implemented | `--backend go` available |

### Sandboxes

| Backend | Status | Notes |
|---------|--------|-------|
| **Docker** | ✅ Implemented | Primary sandbox backend with hardening |

### Security Features

| Feature | Status | Notes |
|---------|--------|-------|
| Shamir Secret Sharing | ✅ Implemented | 5 shares, threshold 3 |
| Anti-Analysis | ✅ Implemented | Debugger/VM detection |
| Integrity Binding | ✅ Implemented | Linux only |
| White-Box Tables | ⚠️ Partial | Tables generated, runtime integration in progress |
| Decoy Markers | ⚠️ Partial | Markers generated, embedding in progress |

### CLI Commands

| Command | Status |
|---------|--------|
| `seal compile` | ✅ Implemented |
| `seal launch` | ✅ Implemented |
| `seal keygen` | ✅ Implemented |
| `seal sign` | ✅ Implemented |
| `seal verify` | ✅ Implemented |
| `seal server` | ✅ Implemented |

---

## Planned Features

:::info

Features below are **planned** and not yet implemented. They may change based on research, user feedback, and development priorities.

:::

## Compilation Backends

### Native Backend

**Goal**: Seal pre-compiled binaries directly without Python/Go compilation.

**Planned features**:
- `--backend native` option
- `--binary <path>` flag for existing executables
- Direct sealing of any Linux ELF binary
- Support for Rust, C/C++, and other native-compiled agents

**Use case**: Integrate with existing build systems without Python shims.

### Rust Backend

**Goal**: Native Rust agent compilation via Cargo.

**Planned features**:
- Automatic Cargo project detection
- `--backend rust` option
- Static linking for minimal binaries
- Cross-compilation support

### Node.js Backend

**Goal**: JavaScript/TypeScript agent compilation.

**Planned features**:
- `--backend nodejs` option
- pkg or nexe integration
- TypeScript support
- npm dependency bundling

### JVM Backend

**Goal**: Java/Kotlin agent compilation via GraalVM.

**Planned features**:
- `--backend graalvm` option
- Native-image compilation
- JVM agent support

### .NET Backend

**Goal**: C#/F# agent compilation.

**Planned features**:
- `--backend dotnet` option
- Native AOT compilation
- .NET 8+ support

## Sandboxes

### Native Sandbox

**Goal**: Server-side native process sandboxing.

**Planned features**:
- `NativeBackend` implementation
- seccomp-bpf filtering
- ulimit-based resource controls
- Zero container overhead

**Use case**: Development environments, trusted agents, performance-critical workloads.

### Firecracker Sandbox

**Goal**: MicroVM isolation for maximum security.

**Planned features**:
- `FirecrackerBackend` implementation
- KVM-based microVM provisioning
- Custom kernel/rootfs management
- Hardware-level isolation

**Use case**: Multi-tenant SaaS, untrusted agent execution, high-security deployments.

### Additional Sandbox Backends

**gVisor** — User-space kernel for enhanced container isolation

**Kata Containers** — Lightweight VM-based containers

**AWS Nitro Enclaves** — Hardware-isolated compute environments

**Azure Confidential Computing** — SGX-based secure enclaves

## Platform Support

### macOS Execution

**Goal**: Native sealed agent execution on macOS.

**Challenges**:
- No memfd_create/fexecve equivalent
- Different sandboxing model (Seatbelt)
- Code signing requirements

**Possible approaches**:
- Ramdisk-based execution
- Temporary file + immediate unlink
- Integration with macOS sandbox APIs

### Windows Execution

**Goal**: Native sealed agent execution on Windows.

**Challenges**:
- No memfd equivalent
- Different security model
- PE binary format

**Possible approaches**:
- Memory-mapped execution
- Named pipes with execute access
- Windows sandbox integration

## CLI Enhancements

### Backend Options Passthrough

**Planned**: `--backend-opts` flag

Allow passing custom options to backend tools:
```bash
seal compile --backend nuitka --backend-opts="--enable-plugin=numpy"
```

### Backend Auto-Detection

**Planned**: Automatic backend selection based on project type.

Detection logic:
- `go.mod` → Go backend
- `Cargo.toml` → Rust backend
- `requirements.txt`/`setup.py` → Python backend

### Backend Chain Configuration

**Planned**: `--backend-chain` for fallback behavior.

```bash
seal compile --backend-chain nuitka,pyinstaller --project ./agent
```

## API Enhancements

### Log Streaming

**Goal**: Real-time execution log streaming.

**Planned features**:
- WebSocket/SSE endpoint for live logs
- `GET /api/v1/jobs/{job_id}/logs/stream`
- Configurable log buffering

### Authentication & Authorization

**Goal**: Built-in API security.

**Planned features**:
- JWT token authentication
- API key support
- Role-based access control (RBAC)
- Rate limiting middleware

### OpenAPI Specification

**Goal**: Auto-generated API documentation.

**Planned features**:
- OpenAPI 3.0 spec generation
- Swagger UI integration
- Client SDK generation

## Security Features

### Hardware Attestation

**Goal**: TPM/SGX integration for hardware-bound keys.

**Planned features**:
- TPM 2.0 key sealing
- Intel SGX enclaves
- Remote attestation support

### Key Rotation

**Goal**: Built-in key management and rotation.

**Planned features**:
- Key versioning
- Automatic re-signing workflow
- Key distribution API

### Secure Key Distribution

**Goal**: Safe master secret and signing key distribution.

**Planned features**:
- Key wrapping with operator public keys
- Integration with HashiCorp Vault
- Cloud KMS support (AWS KMS, GCP KMS, Azure Key Vault)

## Orchestration Features

### Job Scheduling

**Goal**: Advanced job management.

**Planned features**:
- Priority queues
- Resource-based scheduling
- Job dependencies
- Cron-style scheduling

### Distributed Execution

**Goal**: Multi-node agent execution.

**Planned features**:
- Worker node registration
- Load balancing
- Fault tolerance
- Result aggregation

### Artifact Registry

**Goal**: Sealed artifact storage and versioning.

**Planned features**:
- Artifact storage backend (S3, GCS, local)
- Version management
- Signature verification on retrieval
- Access control

## Developer Experience

### Language SDKs

**Goal**: Native SDKs for common languages.

**Planned**:
- Python SDK
- TypeScript/Node.js SDK
- Go SDK
- Rust SDK

### VS Code Extension

**Goal**: IDE integration for Snapfzz Seal.

**Planned features**:
- Syntax highlighting for seal manifests
- Compile/launch commands
- Debug integration
- Key management UI

## Timeline

These features are under research and development. No specific timeline is committed. Priority is determined by:

1. **Security impact** — Features that significantly improve security posture
2. **User demand** — Features requested by the community
3. **Implementation complexity** — Balancing effort vs. value

For the latest development status, see [GitHub Issues](https://github.com/0xtrou/snapfzz-seal/issues) and [GitHub Discussions](https://github.com/0xtrou/snapfzz-seal/discussions).