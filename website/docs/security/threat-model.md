# Threat Model

This document defines the explicit adversary model and security boundaries for Snapfzz Seal.

## Security objectives

The system is designed to:

1. Increase effort required to extract sensitive payload data from distributed artifacts.
2. Bind decryption to environment-derived inputs.
3. Enforce signature validation before execution.
4. Reduce plaintext disk artifacts during launch.

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

:::caution Master Secret Exposure

The **master secret is embedded in plaintext** in the sealed binary. This is necessary for self-contained execution but creates a fundamental limitation:

- An attacker with binary access can extract the master secret
- Combined with known fingerprints, this enables decryption
- This is a design trade-off, not a bug

For high-security deployments, consider:
- Hardware-based key protection (not currently implemented)
- External key provisioning
- Short-lived artifacts

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

:::warning Identity Verification Gap

Since signatures use embedded public keys, distribution-phase attacks can succeed if:

1. Attacker intercepts artifact in transit
2. Attacker modifies and re-signs with own key
3. Recipient has no external way to verify signer identity

**Mitigation**: Use authenticated artifact repositories, signed commit chains, or out-of-band key verification.

:::

### Launch phase

- Input parameter manipulation (`--user-fingerprint`, environment secret values)
- Runtime host drift affecting fingerprint matching
- Memory and process introspection by privileged local actors

**Anti-debugging reality**:
- Only basic ptrace protections implemented
- No timing-based debugger detection
- No tracer process detection
- Sophisticated adversaries can bypass easily

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

## Known limitations

### Technical Limitations

1. **Master secret in binary** — Necessary for self-contained execution but extractable by determined adversaries.

2. **Signature is self-validating** — Verifies integrity, not identity. Attacker can re-sign modified artifacts.

3. **Seccomp is best-effort** — Application failures are non-fatal; protection may be absent.

4. **No cross-platform execution** — Only Linux x86_64 can actually launch sealed agents.

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