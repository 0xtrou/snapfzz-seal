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

- master secret marker replacement
- launcher tamper hash replacement

The assembled binary is then written as:

```text
[launcher_with_embeds]
[LAUNCHER_PAYLOAD_SENTINEL]
[encrypted_payload]
[payload_footer]
```

### 5. Signing stage

`seal sign` appends the signature block to the assembled output.

### 6. Launch stage

`seal launch` or launcher runtime performs:

1. Payload header validation
2. Signature verification
3. Launcher integrity check against footer hash
4. Runtime fingerprint collection
5. Key derivation
6. In-memory decrypt
7. `memfd` execution path

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

## Limitations

- Complete resistance to runtime memory inspection is not provided.
- Platform behavior differs, especially outside Linux.
- Security properties depend on trustworthy host kernel and userspace boundary.