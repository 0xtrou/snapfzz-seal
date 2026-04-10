# Threat Model

This document defines the explicit adversary model and security boundaries for Snapfzz Seal.

## Security objectives

The system is designed to:

1. Increase effort required to extract sensitive payload data from distributed artifacts.
2. Bind decryption to environment-derived inputs.
3. Enforce signature validation before execution.
4. Reduce plaintext disk artifacts during launch.
5. **Protect master secrets with defense-in-depth security layers.**

## Defense-in-Depth Security

Snapfzz Seal implements 6 independent security layers to protect master secrets:

### Layer 1: No Observable Patterns
- Random markers generated at compile time
- No searchable strings ("SECRET", "MARKER", etc.)
- 5 real markers + 50 decoy markers per binary

### Layer 2: Shamir Secret Sharing
- Master secret split into 5 shares
- Requires minimum 3 shares to reconstruct
- Prime field arithmetic (secp256k1 modulus)

### Layer 3: Decoy Secrets
- 10 fake secret sets
- Position obfuscation with salt
- 55 total potential markers in binary

### Layer 4: Anti-Analysis
- Debugger detection (ptrace, TracerPid, breakpoints)
- VM detection (VMware, VirtualBox, QEMU, Xen)
- Timing checks and environment poisoning

### Layer 5: Integrity Binding
- Decryption key depends on binary hash
- ELF parsing for code/data sections
- Exclusion of secret regions from hash

### Layer 6: White-Box Cryptography
- Key spread across ~165KB of lookup tables
- T-boxes + Type I/II mixing tables
- No single table reveals the key
- Requires expert-level cryptanalysis

**Security Impact:**
- Before: Master secret trivially extractable
- After: Requires expert-level reverse engineering

## Adversary model

### In-scope adversaries

- Operators with read access to artifact files.
- Attackers attempting replay across unintended environments.
- Attackers attempting artifact tampering in transit or at rest.
- Analysts performing static inspection without full host privilege.

### Out-of-scope adversaries

- Attackers with persistent root control of execution host.
- Attackers with kernel-level instrumentation and memory extraction capability.
- Physical adversaries with hardware-level invasive access.

## Security guarantees

### Integrity

- Signature verification is required by launcher path for accepted payload execution.
- Payload header integrity is protected via HMAC over core metadata.
- Launcher hash in footer is checked for tamper evidence in Linux path.

:::warning Signature Trust Model

**Critical limitation**: The launcher verifies signatures using the **public key embedded in the artifact itself**, not a separately-trusted key store.

This means:
- ✅ Detects **unsigned** modifications (tampering without re-signing)
- ✅ Detects accidental corruption
- ❌ Does **NOT** verify the signer's identity
- ❌ An attacker who can replace the artifact can also **re-sign it with their own key**

**Attack scenario**:
1. Attacker obtains sealed artifact
2. Attacker modifies payload content
3. Attacker signs with their own Ed25519 key
4. Attacker embeds matching public key
5. Launcher verification **PASSES**

This is **integrity verification, not authenticity verification**. For production use, you must:
- Implement external key pinning
- Use a trusted key distribution mechanism
- Verify against a known-good public key out-of-band

:::

### Confidentiality

- Payload confidentiality relies on AES-256-GCM with derived keys.
- Decryption keys are bound to supplied fingerprint components.
- **Master secret protected by 6-layer defense-in-depth security.**

:::caution[Master Secret Protection]

The master secret is protected by **white-box cryptography and 6 security layers**:

**What this means:**
- ✅ Master secret is **NOT** stored in plaintext
- ✅ Key is embedded in mathematical structure of lookup tables
- ✅ Extracting key requires reverse-engineering entire table structure
- ✅ Attacker cost: Expert-level cryptanalysis required

**Attack scenarios prevented:**
- ❌ Simple grep + dd extraction (Layer 1: random markers)
- ❌ Direct share extraction (Layer 2: Shamir + Layer 3: decoys)
- ❌ Dynamic analysis (Layer 4: anti-debug/anti-VM)
- ❌ Binary modification (Layer 5: integrity binding)
- ❌ Key extraction from tables (Layer 6: white-box cryptography)

**Remaining considerations:**
- Hardware-based attacks (out of scope)
- Side-channel attacks (mitigated but not eliminated)
- Long-term cryptanalysis (requires sustained expert effort)

:::

### Execution controls

- Linux runtime path applies process protection hooks and seccomp filtering (**best-effort**, may fail silently).
- Decrypted payload bytes are executed from memory-backed file descriptors.

**Platform limitations**:
- ✅ Linux x86_64: Full execution controls
- ❌ macOS: No memfd execution, no seccomp
- ❌ Windows: No execution support at all

## Attack surface analysis

### Build and sign phase

- Signing key storage and CI runner trust
- Compiler backend supply chain dependencies
- Artifact handling and publication channels

**Key considerations**:
- Signing key compromise allows attacker to sign malicious artifacts
- No key rotation mechanism built into system
- Key distribution security is operator's responsibility

### Distribution phase

- Artifact interception and replacement
- Public key distribution integrity

:::warning[Identity Verification Gap]

Since signatures use embedded public keys, distribution-phase attacks can succeed if:

1. Attacker intercepts artifact in transit
2. Attacker modifies and re-signs with own key
3. Recipient has no external way to verify signer identity

**Mitigation**: Use authenticated artifact repositories, signed commit chains, or out-of-band key verification.

:::

### Launch phase

:::warning[`seal verify` Exit Code]

The `seal verify` command returns exit code `0` even for `INVALID` or `WARNING: unsigned` results.

**Implication**:
- CI/CD pipelines relying solely on exit code will pass incorrectly
- Must parse output text or use `--pubkey` for pinned key verification

**Best practice**:
```bash
seal verify --binary ./artifact.sealed --pubkey trusted.key
# Check output for "VALID (pinned to explicit public key)"
```

:::

### Launch phase

- Input parameter manipulation (`--user-fingerprint`, environment secret values)
- Runtime host drift affecting fingerprint matching
- Memory and process introspection by privileged local actors

**Anti-debugging reality**:
- Multi-layer protections implemented (ptrace, TracerPid, timing checks, breakpoint scanning)
- Sophisticated adversaries with elevated privileges can bypass
- Protections raise attacker cost but do not guarantee prevention

**Seccomp reality**:
- Applied on best-effort basis
- Application failure is logged but not fatal
- May not be enforced on all platforms

### Server API phase

- API misuse if exposed without authentication
- Sandbox backend command execution pathways
- Artifact retrieval and job state manipulation

**No built-in auth/authz**:
- Server has no JWT, API keys, or RBAC
- Must be deployed behind authenticated gateway
- Rate limiting not implemented

:::danger No Transport Security

The built-in server has **no TLS/mTLS implementation**. It binds and serves plain HTTP.

**Required for production**:
- Deploy behind TLS-terminating reverse proxy
- Use authenticated API gateway
- Never expose server directly to untrusted networks

:::

## Known limitations

### Technical Limitations

1. **Master secret in binary** — Necessary for self-contained execution but extractable by determined adversaries.

2. **Signature is self-validating** — Verifies integrity, not identity. Attacker can re-sign modified artifacts.

3. **Seccomp is best-effort** — Application failures are non-fatal; protection may be absent.

4. **Non-Linux launcher integrity check** — Footer hash verification skipped on macOS/Windows; only warning logged.

5. **No cross-platform execution** — Only Linux x86_64 can actually launch sealed agents.

5. **Fingerprinting is software-based** — Not remote attestation; spoofable by privileged attackers.

6. **`auto` fingerprint mode** — Convenience feature, not high-assurance binding.

### Operational Limitations

1. **No key rotation** — Manual re-compilation required for key changes.

2. **No built-in auth** — Server API requires external authentication layer.

3. **No log streaming** — Logs captured post-execution only.

4. **No hardware attestation** — No TPM/SGX integration.

### Deployment Responsibilities

The following are **outside** Snapfzz Seal's security boundary:

- Signing key custody and rotation
- Master secret distribution
- Server authentication and authorization
- Network segmentation
- Host hardening
- Monitoring and alerting

## What Snapfzz Seal Protects Against

✅ **Casual extraction attempts** — Encrypted payload prevents trivial extraction from disk

✅ **Unauthorized execution** — Fingerprint binding prevents execution on mismatched environments

✅ **Accidental corruption** — Signature verification detects bit flips and truncation

✅ **Supply chain tampering** (with proper key management) — Detects modified artifacts

✅ **Simple dynamic analysis** — Memory-only execution, ptrace protections raise bar

## What Snapfzz Seal Does NOT Protect Against

❌ **Privileged adversaries** — Root can extract secrets from memory

❌ **Re-signing attacks** — Attacker with own signing key can create valid artifacts

❌ **Nation-state attacks** — Not designed for adversary model

❌ **Memory dumping** — Privileged processes can read decrypted payload

❌ **Runtime introspection** — Root can attach debuggers

❌ **Hardware attacks** — No TPM/SGX protection

❌ **Fingerprint spoofing** — Privileged attacker can fake environment signals

## Recommended controls beyond Snapfzz Seal

### Critical

- **Key custody through HSM or managed KMS** — Protect signing keys
- **Authenticated artifact distribution** — Prevent MITM/re-signing attacks
- **External key pinning** — Verify signer identity out-of-band

### Important

- **Host hardening and least-privilege service accounts**
- **Strong network segmentation and authenticated service perimeter**
- **Continuous monitoring of verification failures and unusual launch patterns**

### Recommended

- **Short artifact lifetimes** — Limit exposure window if key compromised
- **Audit logging** — Track compilation and execution events
- **Incident response plan** — Define process for key compromise

## Threat Model Summary

| Threat | Mitigation | Limitation |
|--------|------------|------------|
| Disk extraction | AES-256-GCM encryption | Master secret in binary |
| Unauthorized execution | Fingerprint binding | Privileged spoofing possible |
| Artifact tampering | Ed25519 signature | Self-validating, not identity-binding |
| Dynamic analysis | memfd + anti-debug | Sophisticated bypass possible |
| Memory extraction | Memory-only execution | Root can dump memory |

**Bottom line**: Snapfzz Seal raises the cost of attacks but does not provide perfect security. Use defense-in-depth with additional controls appropriate to your threat model.

## References

### Cryptographic Standards

- **AES-256-GCM**: Dworkin, M. (2007). "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC". NIST Special Publication 800-38D. [doi:10.6028/NIST.SP.800-38D](https://doi.org/10.6028/NIST.SP.800-38D)

- **HKDF**: Krawczyk, H. (2010). "Cryptographic Extraction and Key Derivation: The HKDF Scheme". RFC 5869. [doi:10.17487/RFC5869](https://doi.org/10.17487/RFC5869)

- **Ed25519**: Bernstein, D. et al. (2012). "High-speed high-security signatures". Journal of Cryptographic Engineering 4(2). [doi:10.1007/s13389-012-0007-1](https://doi.org/10.1007/s13389-012-0007-1)

### Secret Sharing

- **Shamir Secret Sharing**: Shamir, A. (1979). "How to Share a Secret". Communications of the ACM 22(11):612-613. [doi:10.1145/359168.359176](https://doi.org/10.1145/359168.359176)

### White-Box Cryptography

- **White-Box AES**: Chow, S. et al. (2002). "White-Box Cryptography and an AES Implementation". Selected Areas in Cryptography (SAC 2002), LNCS 2595. [doi:10.1007/3-540-36492-7_17](https://doi.org/10.1007/3-540-36492-7_17)

### Security Principles

- **Defense-in-Depth**: Saltzer, J. & Schroeder, M. (1975). "The Protection of Information in Computer Systems". Proceedings of the IEEE 63(9). [doi:10.1109/PROC.1975.9939](https://doi.org/10.1109/PROC.1975.9939)