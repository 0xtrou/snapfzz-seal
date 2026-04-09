# Encryption Design

## AES-256-GCM

- Streaming encryption
- 64 KiB chunks
- 16-byte auth tag per chunk

## HKDF Derivation

```
K_env = HKDF(master_secret, stable || user_fp, "agent-seal/env/v1")
K_session = HKDF(K_env, ephemeral_fp, "agent-seal/session/v1")
```

## Master Secret

Embedded in binary via known marker (`ASL_SECRET_MRK_v1...`). Extractable by determined attackers.
