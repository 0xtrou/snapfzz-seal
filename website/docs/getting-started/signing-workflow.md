---
sidebar_position: 5
---

# Signing Workflow

This document specifies key lifecycle and signature verification procedures for Snapfzz Seal artifacts.

## Key generation

```bash
seal keygen
```

Generated files:

- `~/.snapfzz-seal/keys/builder_secret.key`
- `~/.snapfzz-seal/keys/builder_public.key`

The private key is required for `seal sign`. The public key is distributed to verifiers.

## Signing procedure

```bash
seal sign \
  --key ~/.snapfzz-seal/keys/builder_secret.key \
  --binary ./agent.sealed
```

A signature block is appended to the binary:

- Magic marker: `ASL\x02`
- Signature: 64 bytes (Ed25519)
- Embedded public key: 32 bytes

## Verification workflow

### Pinned verification

Pinned verification is recommended for production.

```bash
seal verify \
  --binary ./agent.sealed \
  --pubkey ~/.snapfzz-seal/keys/builder_public.key
```

### TOFU verification

TOFU uses the embedded public key from the artifact itself.

```bash
seal verify --binary ./agent.sealed
```

TOFU can detect corruption, but it does not provide independent builder identity assurance.

## Key management procedures

### Storage policy

- Store private keys in dedicated secret backends or HSM-backed systems when available.
- Restrict file permissions to the signing principal.
- Keep production and non-production key material isolated.

### Distribution policy

- Publish public keys through authenticated channels.
- Version public keys and attach validity intervals in deployment metadata.

### Incident response

If key compromise is suspected:

1. Revoke the compromised key in deployment policy.
2. Generate a replacement key pair.
3. Re-sign active release artifacts.
4. Update all verifiers to trust the new key set.

## Key rotation strategy

A staged rotation procedure is recommended.

### Phase A: introduce new key

- Generate `K2` while `K1` remains active.
- Distribute `K2` public key to all verifiers.

### Phase B: dual acceptance window

- Accept signatures from `K1` and `K2` at policy layer.
- Sign new artifacts with `K2` only.

### Phase C: retire old key

- Remove `K1` from trusted verifier configuration.
- Archive `K1` records for audit traceability.

## Security considerations

- Signing should be performed in controlled CI runners with restricted outbound access.
- Signature verification should be mandatory in pre-deploy and pre-launch checks.
- Build provenance logs should include key identifiers and artifact digests.

## Limitations

- The current CLI appends one signature block per run and does not expose multi-signer metadata.
- Verifier output is human-readable text and should be wrapped by policy automation for strict CI enforcement.
