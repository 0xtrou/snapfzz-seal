---
sidebar_position: 3
---

# How It Works

This section describes the internal execution path of Snapfzz Seal from source compilation to in-memory launch.

## End-to-end flow

```text
project source
  -> compiler backend selection
  -> compiled agent binary
  -> key derivation
  -> encrypted payload packing
  -> launcher assembly and footer write
  -> signature append
  -> runtime verification and decryption
  -> memfd execution
```

## Detailed technical sequence

### 1. Compilation stage

A compile backend is selected (`nuitka`, `pyinstaller`, or internal backend chain logic in compiler crate). The project is compiled into an executable payload candidate.

### 2. Key derivation stage

An environment key is derived using HKDF-SHA256.

```text
env_key = HKDF(master_secret, stable_fingerprint || user_fingerprint, "snapfzz-seal/env/v1")
```

When session mode is enabled:

```text
session_key = HKDF(env_key, ephemeral_fingerprint, "snapfzz-seal/session/v1")
```

### 3. Payload packing stage

The payload packer creates:

- Header (46 bytes)
- Mode byte (1 byte)
- Encrypted stream bytes (nonce plus chunk ciphertext)

### 4. Assembly stage

The launcher binary is read and patched with marker-based embed operations:

- **Layer 1**: Marker generation from BUILD_ID (build time) ✅
- **Layer 2**: Shamir secret share embedding (5 shares, 3 threshold) ✅
- **Layer 3**: Decoy marker generation ⚠️ (generated, embedding in progress)
- **Layer 5**: Launcher tamper hash replacement ✅
- **Layer 6**: White-box table embedding (~165KB) ⚠️ (tables embedded, runtime integration in progress)

The assembled binary is then written as:

```text
[launcher_with_embeds (including white-box tables)]
[LAUNCHER_PAYLOAD_SENTINEL]
[encrypted_payload]
[payload_footer]
```

White-box tables are embedded into the launcher binary before the payload sentinel.

### 5. Signing stage

`seal sign` appends the signature block to the assembled output.

### 6. Launch stage

`seal launch` or launcher runtime performs:

1. Payload header validation
2. Signature verification
3. **Layer 4**: Anti-analysis checks (debugger, VM detection) ✅
4. **Layer 5**: Launcher integrity check against footer hash ✅
5. Runtime fingerprint collection
6. **Layer 2**: Shamir secret reconstruction (from 3+ shares) ✅
7. Key derivation with integrity binding ✅
8. In-memory decrypt (currently AES-GCM; white-box integration in progress)
9. `memfd` execution path

**Note on Layer 6**: White-box tables are generated and embedded during compilation, but the launcher currently uses standard AES-GCM decryption. Full white-box decryption integration is in progress.

## Cryptographic primitives

- **AES-256-GCM** for authenticated encryption
- **HKDF-SHA256** for key derivation
- **SHA-256** for integrity hashes
- **Ed25519** for artifact signatures
- **HMAC-SHA256** for header authentication field

## Memory layout during runtime

The launcher keeps critical material in process memory only for the shortest practical interval.

```text
+-----------------------------------------------------------+
| launcher process                                           |
|                                                           |
| payload bytes -> verify -> derive keys -> decrypt buffer  |
|                                  |                        |
|                                  v                        |
|                           memfd write and seal            |
|                                  |                        |
|                                  v                        |
|                             fexecve child                 |
+-----------------------------------------------------------+
```

Operational notes:

- Decryption key buffers are zeroized after use where implemented.
- Output collection is bounded by configurable limits in executor logic.

## Security considerations

- Signature validation occurs before decryption and execution.
- Integrity checks are tied to launcher hash stored in payload footer.
- Linux seccomp policy is applied in supported execution paths.

## Security Architecture

Snapfzz Seal implements defense-in-depth security with multiple protection layers:

### Layer Breakdown

**Layer 1: Deterministic Markers ✅**
- Markers derived from BUILD_ID at compile time
- 5 real markers + 50 decoy markers
- Not truly random, but opaque

**Layer 2: Shamir Secret Sharing ✅**
- Master secret split into 5 shares
- Requires minimum 3 shares to reconstruct
- Prime field arithmetic (secp256k1 modulus)

**Layer 3: Decoy Markers ⚠️**
- 10 decoy marker sets generated
- Position obfuscation with salt
- **Status**: Generated during compile, embedding in progress

**Layer 4: Anti-Analysis ✅**
- Debugger detection (ptrace, TracerPid)
- VM detection (VMware, VirtualBox, QEMU)
- Timing checks and environment poisoning

**Layer 5: Integrity Binding**
- Decryption key depends on binary hash
- ELF parsing for code/data sections
- Detects binary modifications

**Layer 6: White-Box Cryptography**
- Key spread across ~165KB of lookup tables
- T-boxes + Type I/II mixing tables
- No single table reveals the key

### Security Impact

| Metric | Before | After |
|--------|--------|-------|
| Extraction difficulty | Trivial | Expert-level |
| Required skill | Basic CLI usage | Expert cryptanalyst |
| Tools needed | Standard utilities | Custom reverse engineering |

## Limitations

- Complete resistance to runtime memory inspection is not provided.
- Platform behavior differs, especially outside Linux.
- Security properties depend on trustworthy host kernel and userspace boundary.

## References

### Cryptographic Foundations

- **AES-GCM**: Dworkin, M. (2007). NIST SP 800-38D. Galois/Counter Mode specification.

- **HKDF**: Krawczyk, H. (2010). RFC 5869. HMAC-based Extract-and-Expand Key Derivation Function.

- **Shamir Secret Sharing**: Shamir, A. (1979). "How to Share a Secret". CACM 22(11):612-613.

- **White-Box Cryptography**: Chow, S. et al. (2002). "White-Box Cryptography and an AES Implementation". SAC 2002, LNCS 2595.

### Security Engineering

- **Defense-in-Depth**: Saltzer & Schroeder (1975). "The Protection of Information in Computer Systems". Proc. IEEE 63(9).