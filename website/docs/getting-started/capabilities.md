---
sidebar_position: 4
---

# Capabilities

Snapfzz Seal provides security capabilities designed to protect AI agent deployments in production environments.

## Cryptographic Capabilities

### Encryption at Rest

**Specification**: AES-256-GCM with 7-byte stream nonces

All agent payloads are encrypted using AES-256-GCM (Galois/Counter Mode), providing both confidentiality and authenticity. The encryption envelope includes:

- 256-bit encryption key derived via HKDF-SHA256
- 7-byte stream nonce per encryption operation (not 12-byte standard nonce)
- 128-bit authentication tag verified on decryption
- Streaming encryption for large payloads (chunked at 64KB boundaries)

**Security properties**:
- Confidentiality under chosen plaintext attacks (IND-CPA)
- Integrity and authenticity verification
- Resistance to nonce reuse when proper key derivation is used

### Key Derivation

**Specification**: HKDF-SHA256 with dual fingerprint binding

The decryption key is derived using HKDF (HMAC-based Key Derivation Function) with the following inputs:

1. **Master secret** — Protected by 6-layer defense-in-depth security
2. **Stable hash** — Hash of stable environment signals
3. **User fingerprint** — Arbitrary identifier provided by operator

The derivation process:

```
salt = stable_hash || user_fingerprint
PRK = HKDF-Extract(salt=salt, IKM=master_secret)
Key = HKDF-Expand(PRK, info="snapfzz-seal/env/v1", L=32)
```

**Session mode** adds a second HKDF step with an ephemeral hash.

**Security properties**:
- Key is cryptographically bound to environment and user fingerprint
- Different fingerprint combinations produce independent keys
- Master secret protected by white-box cryptography (not stored in plaintext)

### Digital Signatures

**Specification**: Ed25519 (EdDSA over Curve25519)

All sealed binaries must carry a valid Ed25519 signature. The signature covers the **entire binary content**.

**Security properties**:
- 128-bit security level against forgery attacks
- Small signature size (64 bytes)
- Fast verification (suitable for constrained environments)

:::warning[Signature Trust Model]

The launcher verifies signatures using the **public key embedded in the artifact itself**. This means:

- ✅ Detects tampering with signed content
- ✅ Prevents accidental corruption
- ❌ Does **NOT** verify the signer's identity
- ❌ An attacker can replace content, re-sign with their own key, and pass verification

For production use, you must implement **external key pinning** or trust policies. The signature provides integrity, not authenticity to a trusted identity.

:::

## Execution Capabilities

### Memory-Only Execution

**Specification**: memfd_create + fexecve (Linux only)

The sealed payload is decrypted and executed entirely in memory on Linux, without intermediate disk storage. The implementation:

1. Creates an anonymous memory file via `memfd_create()`
2. Writes decrypted payload to the memory file
3. Executes via `fexecve()` (file descriptor execution)
4. Memory file is automatically cleaned up on process exit

**Security properties**:
- No persistent artifacts on filesystem
- Forensic analysis of disk reveals only encrypted payload
- Protection against disk-based extraction attacks

**Platform limitations**:
- ✅ Linux x86_64: Full memfd execution
- ❌ macOS: **NOT IMPLEMENTED** — Returns "memfd unsupported" error
- ❌ Windows: **NOT IMPLEMENTED** — Returns error

### Runtime Verification

**Specification**: Multi-stage verification before execution

Before any payload execution, the launcher performs:

1. **Signature verification** — Ed25519 signature validated (using embedded public key)
2. **Fingerprint derivation** — Runtime environment measured and key derived
3. **Decryption attempt** — Payload decrypted using derived key
4. **Integrity check** — Authentication tag verified

If any stage fails, execution is aborted with an appropriate error code.

### Anti-Debugging Protections

**Specification**: Limited ptrace restrictions (Linux only)

The launcher implements basic anti-debugging on Linux:

- ✅ **PR_SET_DUMPABLE=0** — Prevents ptrace attachment
- ✅ **ptrace(TRACEME)** — Claims tracer slot

**NOT IMPLEMENTED**:
- ❌ Timing checks for debugging detection
- ❌ Tracer detection via `/proc/self/status`
- ❌ Parent process verification

**Security properties**:
- Raises the cost of casual debugging attempts
- May be bypassed by sophisticated adversaries with elevated privileges

### System Call Filtering

**Specification**: seccomp-bpf with allowlist (Linux only)

The launcher attempts to install a seccomp filter that restricts allowed system calls. The default allowlist includes:

- Memory operations: `mmap`, `munmap`, `mprotect`, `brk`
- File operations: `read`, `write`, `open`, `close`, `stat`, `lstat`, `fstat`
- Process operations: `exit`, `exit_group`, `arch_prctl`
- Network operations: `socket`, `connect`, `bind`, `listen`, `accept`, `send`, `recv`
- Process creation: `clone`, `clone3` (allowed)

**NOT blocked**: `fork`, `vfork`

:::caution[Best-Effort Enforcement]

If seccomp application fails, the launcher **logs a warning and continues without seccomp**. This is not a hard security boundary.

:::

**Security properties**:
- Reduces kernel attack surface (when successfully applied)
- Limits capabilities of compromised agents
- Not guaranteed — can be bypassed if application fails

## Fingerprinting Capabilities

### Host Signal Collection

**Specification**: Multi-source host measurement (Linux only)

The fingerprinting module collects signals from various Linux-specific sources:

| Source | Implemented | Stability |
|--------|-------------|-----------|
| Machine ID hash | ✅ | Stable |
| Hostname | ✅ | Semi-stable |
| Kernel release | ✅ | Stable |
| cgroup path | ✅ | Semi-stable |
| proc cmdline hash | ✅ | Ephemeral |
| MAC address (first non-loopback) | ✅ | Semi-stable |
| DMI product UUID HMAC | ✅ | Stable |
| Namespace inodes | ✅ | Ephemeral |

**NOT IMPLEMENTED**:
- ❌ CPU model
- ❌ CPU feature flags
- ❌ Memory total
- ❌ Mount points table
- ❌ Full network interface inventory

**Platform limitations**:
- ✅ Linux: Full fingerprinting support
- ❌ macOS: **NOT IMPLEMENTED** (uses Linux-only paths like `/proc`, `/sys`)
- ❌ Windows: **NOT IMPLEMENTED**

### Canonicalization

**Specification**: Deterministic canonical representation

Collected signals are canonicalized using:

1. Sort signal IDs lexicographically
2. Encode with length-prefixed binary format
3. Hash the encoded data (SHA-256)

This ensures identical environments produce identical fingerprints.

## Orchestration Capabilities

### REST API

**Implemented endpoints**:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/compile` | POST | Compile and seal an agent |
| `/api/v1/dispatch` | POST | Launch a sealed agent in sandbox |
| `/api/v1/jobs/{job_id}` | GET | Check job status |
| `/api/v1/jobs/{job_id}/results` | GET | Get execution results |
| `/health` | GET | Health check |

For complete API documentation with request/response schemas, see [API Reference](../reference/api.md).

**Request/Response schemas**:

`POST /api/v1/compile`:
```json
{
  "project_dir": "./my_agent",
  "user_fingerprint": "64-hex-string",
  "sandbox_fingerprint": "auto"
}
```

Response (202):
```json
{
  "job_id": "uuid",
  "status": "pending"
}
```

`POST /api/v1/dispatch`:
```json
{
  "job_id": "uuid",
  "sandbox": {
    "image": "ubuntu:22.04",
    "timeout_secs": 3600,
    "memory_mb": 512,
    "env": [["KEY", "value"]]
  }
}
```

**NOT IMPLEMENTED**:
- ❌ `POST /sign` endpoint
- ❌ `POST /launch` endpoint (use `/dispatch`)
- ❌ `GET /status/{id}` (use `/api/v1/jobs/{id}`)
- ❌ `GET /logs/{id}` endpoint
- ❌ Real-time log streaming
- ❌ JWT authentication
- ❌ Rate limiting
- ❌ OpenAPI spec generation

:::warning

The server API has **no built-in authentication or authorization**. Deploy behind an authenticated gateway.

:::

### Sandbox Integration

**Current implementation**: Docker container isolation only

For detailed sandbox documentation, see [Supported Sandboxes](../architecture/supported-sandboxes.md).

The orchestration API provisions Docker containers with:

- ✅ Container isolation with namespace/cgroup separation
- ✅ Memory limit (optional)
- ✅ Timeout enforcement
- ✅ Automatic cleanup on completion
- ✅ Hardened flags: `--security-opt no-new-privileges`, `--cap-drop ALL`, `--read-only`, `--tmpfs /tmp`
- ✅ Fixed pids limit (64)

**NOT IMPLEMENTED in server sandbox**:
- ❌ CPU quota/period configuration
- ❌ Disk I/O limits
- ❌ Network disable/isolation flag
- ❌ Volume mounting
- ❌ Custom seccomp profiles
- ❌ AppArmor/SELinux profiles
- ❌ Log streaming (post-execution capture only)
- ❌ Firecracker backend
- ❌ Native backend

## Platform Support

### Linux x86_64

**Full support** — All core capabilities available

- ✅ Native memfd execution
- ✅ seccomp filtering (best-effort)
- ✅ All fingerprinting sources
- ✅ Full encryption and signing
- ✅ Docker sandbox execution

**NOT IMPLEMENTED**:
- ❌ Firecracker sandbox (planned only)

### macOS arm64

**NOT SUPPORTED** — Cannot execute sealed agents

- ❌ No memfd execution (returns error)
- ❌ No seccomp (different OS)
- ❌ No fingerprinting (Linux-only paths)
- ✅ Can compile and sign (build-side operations)
- ❌ Cannot launch sealed agents

### Windows x86_64

**NOT SUPPORTED** — Cannot execute sealed agents

- ❌ No memfd execution (returns error)
- ❌ No seccomp
- ❌ No fingerprinting
- ✅ Can compile and sign (build-side operations)
- ❌ Cannot launch sealed agents

:::warning[Platform Reality]

There is **no "no-op stub"** for Windows/macOS that returns success. Execution on non-Linux platforms **fails with an error**.

:::

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
- **Maximum concurrent executions**: Limited by host resources and Docker
- **Key rotation**: Manual process, requires re-compilation

## Security Guarantees and Limitations

### What Snapfzz Seal Provides

1. **Encryption** — Strong encryption of agent payloads using AES-256-GCM
2. **Binding** — Cryptographic binding to runtime environment fingerprints
3. **Verification** — Signature verification before execution (integrity, not identity)
4. **Anti-extraction** — Memory-only execution on Linux prevents disk-based extraction
5. **Sandboxing** — Docker container isolation with resource limits

### What Snapfzz Seal Does NOT Provide

1. **Hardware attestation** — No TPM/SGX integration
2. **Trusted signer identity** — Signatures verify integrity, not identity (attacker can re-sign)
3. **Perfect security** — Expert-level reverse engineering can extract master secret
4. **Network security** — Agent network traffic is not encrypted or authenticated
5. **Key distribution** — Secure distribution of signing keys is operator's responsibility
6. **Runtime integrity** — Once executing, the agent process is not monitored for tampering
7. **Cross-platform execution** — Only Linux supports sealed agent execution

### Threat Model Summary

Snapfzz Seal is effective against:

- Casual extraction attempts from disk
- Execution on unauthorized machines (if fingerprints differ)
- Accidental artifact corruption
- Simple dynamic analysis attempts

Snapfzz Seal is NOT effective against:

- Privileged adversaries with memory access
- Attackers who can re-sign modified artifacts
- Nation-state level attacks
- Compromised signing keys
- Memory dumping by privileged processes
- Runtime introspection by root users

For comprehensive threat analysis, see [Threat Model](../security/threat-model.md).