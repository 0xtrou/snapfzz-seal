---
sidebar_position: 3
---

# Capabilities

Snapfzz Seal provides a comprehensive set of security capabilities designed to protect AI agent deployments in production environments. This document outlines the core capabilities and their operational characteristics.

## Cryptographic Capabilities

### Encryption at Rest

**Specification**: AES-256-GCM with 96-bit nonces

All agent payloads are encrypted using AES-256-GCM (Galois/Counter Mode), providing both confidentiality and authenticity. The encryption envelope includes:

- 256-bit encryption key derived via HKDF-SHA256
- 96-bit nonce generated per encryption operation
- 128-bit authentication tag verified on decryption
- Streaming encryption for large payloads (chunked at 64KB boundaries)

**Security properties**:
- Confidentiality under chosen plaintext attacks (IND-CPA)
- Integrity and authenticity verification
- Resistance to nonce reuse when proper key derivation is used

### Key Derivation

**Specification**: HKDF-SHA256 with dual fingerprint binding

The decryption key is derived using HKDF (HMAC-based Key Derivation Function) with the following inputs:

1. **Master secret** — 256-bit random value generated at compile time
2. **User fingerprint** — Arbitrary identifier provided by operator
3. **Sandbox fingerprint** — Runtime environment measurements

The derivation process:

```
PRK = HKDF-Extract(salt=user_fingerprint, IKM=master_secret)
Key = HKDF-Expand(PRK, info=sandbox_fingerprint, L=32)
```

**Security properties**:
- Key is cryptographically bound to both fingerprints
- Different fingerprint combinations produce independent keys
- Master secret never appears in plaintext in the final binary

### Digital Signatures

**Specification**: Ed25519 (EdDSA over Curve25519)

All sealed binaries must carry a valid Ed25519 signature from a trusted key. The signature covers:

- Encrypted payload
- Fingerprint metadata
- Launcher executable

**Security properties**:
- 128-bit security level against forgery attacks
- Small signature size (64 bytes)
- Fast verification (suitable for constrained environments)

## Execution Capabilities

### Memory-Only Execution

**Specification**: memfd_create + fexecve (Linux), ramdisk execution (macOS)

The sealed payload is decrypted and executed entirely in memory, without intermediate disk storage. The implementation:

1. Creates an anonymous memory file via `memfd_create()`
2. Writes decrypted payload to the memory file
3. Executes via `fexecve()` (file descriptor execution)
4. Memory file is automatically cleaned up on process exit

**Security properties**:
- No persistent artifacts on filesystem
- Forensic analysis of disk reveals only encrypted payload
- Protection against disk-based extraction attacks

### Runtime Verification

**Specification**: Multi-stage verification before execution

Before any payload execution, the launcher performs:

1. **Signature verification** — Ed25519 signature validated against trusted public key
2. **Fingerprint derivation** — Runtime environment measured and key derived
3. **Decryption attempt** — Payload decrypted using derived key
4. **Integrity check** — Authentication tag verified

If any stage fails, execution is aborted with an appropriate error code.

### Anti-Debugging Protections

**Specification**: ptrace scope restrictions, timing checks

The launcher implements several anti-debugging mechanisms:

- **ptrace scope** — Sets `PR_SET_DUMPABLE` to 0, preventing ptrace attachment
- **Timing checks** — Detects abnormal execution timing indicative of debugging
- **Tracer detection** — Checks `/proc/self/status` for tracer presence
- **Parent verification** — Validates parent process characteristics

**Security properties**:
- Raises the cost of dynamic analysis
- Detection of common debugging attempts
- May be bypassed by sophisticated adversaries with elevated privileges

### System Call Filtering

**Specification**: seccomp-bpf with strict allowlist

The launcher installs a seccomp filter that restricts the set of allowed system calls. The default allowlist includes:

- Memory operations: `mmap`, `munmap`, `mprotect`, `brk`
- File operations: `read`, `write`, `open`, `close`, `stat`, `lstat`, `fstat`
- Process operations: `exit`, `exit_group`, `arch_prctl`
- Network operations: `socket`, `connect`, `bind`, `listen`, `accept`, `send`, `recv`

Blocked syscall categories:
- Process creation: `fork`, `clone`, `vfork` (unless required by agent)
- Kernel module operations: `init_module`, `delete_module`
- io_uring operations: `io_uring_setup`, `io_uring_enter`, `io_uring_register` (removed due to security concerns)

**Security properties**:
- Reduces kernel attack surface
- Prevents certain privilege escalation techniques
- Limits capabilities of compromised agents

## Fingerprinting Capabilities

### Host Signal Collection

**Specification**: Multi-source host measurement

The fingerprinting module collects signals from various sources:

| Source | Linux | macOS | Stability |
|--------|-------|-------|-----------|
| Kernel version | ✓ | ✓ | Stable |
| CPU model | ✓ | ✓ | Stable |
| CPU feature flags | ✓ | ✓ | Stable |
| Memory total | ✓ | ✓ | Semi-stable |
| Mount points | ✓ | — | Ephemeral |
| Network interfaces | ✓ | ✓ | Semi-stable |
| Machine ID | ✓ | — | Stable |

### Canonicalization

**Specification**: Deterministic canonical representation

Collected signals are canonicalized into a consistent format:

1. Sort signals by key name (lexicographic order)
2. Normalize values (trim whitespace, consistent case)
3. Concatenate key-value pairs with delimiter
4. Hash the concatenated string (SHA-256)

This ensures identical environments produce identical fingerprints, while different environments produce distinct fingerprints.

### Ephemeral vs Stable Signals

**Ephemeral signals** — Change frequently (e.g., mount points, running processes)
- Used for short-lived execution bindings
- Suitable for one-time execution scenarios
- May break across container restarts

**Stable signals** — Change rarely (e.g., kernel version, CPU model)
- Used for long-term binding
- Suitable for persistent deployment scenarios
- Survive container restarts on same host

## Orchestration Capabilities

### REST API

**Specification**: OpenAPI 3.0 compatible

Snapfzz Seal provides an orchestration API for automated workflows:

- **POST /compile** — Compile and seal an agent from source
- **POST /sign** — Sign a sealed binary
- **POST /launch** — Launch a sealed agent in a sandbox
- **GET /status/{id}** — Check execution status
- **GET /logs/{id}** — Retrieve execution logs

All endpoints support:
- JSON request/response bodies
- JWT authentication (when configured)
- Rate limiting (governor-based)

### Sandbox Integration

**Specification**: Docker container isolation (primary)

The orchestration API can provision isolated execution environments:

- **Docker** — Full container isolation with resource limits
- **Firecracker** — MicroVM isolation (planned)
- **Native** — Direct execution with seccomp (development only)

Sandbox capabilities:
- Resource limits (CPU, memory, disk I/O)
- Network isolation (optional)
- Automatic cleanup on completion
- Timeout enforcement

## Platform Support

### Linux x86_64

**Full support** — All capabilities available

- Native memfd execution
- seccomp filtering
- All fingerprinting sources
- Full encryption and signing
- Docker and Firecracker sandbox options

### macOS arm64

**Partial support** — Decryption and verification only

- Ramdisk-based execution (not true memfd)
- No seccomp (macOS uses different sandboxing)
- Limited fingerprinting sources
- Encryption and signing supported
- Native sandbox only

### Windows x86_64

**No-op stub** — Compatibility layer only

- Execution disabled by default
- Returns success without running agent
- Suitable for cross-platform builds
- No security guarantees

## Operational Characteristics

### Performance Overhead

| Operation | Overhead |
|-----------|----------|
| Encryption (per MB) | ~5-10ms |
| Decryption (per MB) | ~5-10ms |
| Signature verification | ~1ms |
| Fingerprint collection | ~50-100ms |
| memfd setup | ~1ms |

### Resource Requirements

- **Minimum RAM**: 64MB for launcher
- **Disk space**: 2x payload size during compilation
- **CPU**: x86_64 with SSE2 (AES-NI recommended for performance)

### Scalability Limits

- **Maximum payload size**: 2GB (limited by memory and address space)
- **Maximum concurrent executions**: Limited by host resources and sandbox backend
- **Key rotation**: Manual process, requires re-compilation

## Security Guarantees and Limitations

### What Snapfzz Seal Provides

1. **Encryption** — Strong encryption of agent payloads using AES-256-GCM
2. **Binding** — Cryptographic binding to runtime environment fingerprints
3. **Verification** — Mandatory signature verification before execution
4. **Anti-extraction** — Memory-only execution prevents disk-based extraction
5. **Sandboxing** — Process-level isolation via seccomp and container backends

### What Snapfzz Seal Does NOT Provide

1. **Hardware attestation** — No TPM/SGX integration
2. **Perfect security** — Determined adversaries with sufficient privileges can extract keys from memory
3. **Network security** — Agent network traffic is not encrypted or authenticated by Snapfzz Seal
4. **Key distribution** — Secure distribution of signing keys and master secrets is the operator's responsibility
5. **Runtime integrity** — Once executing, the agent process is not monitored for tampering

### Threat Model Summary

Snapfzz Seal is effective against:

- Casual extraction attempts from disk
- Execution on unauthorized machines
- Supply chain tampering (with proper key management)
- Simple dynamic analysis attempts

Snapfzz Seal is NOT effective against:

- Privileged adversaries with physical access
- Nation-state level attacks
- Compromised signing keys
- Memory dumping by privileged processes
- Runtime introspection by root users

For comprehensive threat analysis, see [Threat Model](../security/threat-model.md).