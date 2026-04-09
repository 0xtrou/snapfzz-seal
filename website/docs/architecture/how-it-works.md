# How It Works

1. **Compile** — Source → ELF → encrypted payload
2. **Encrypt** — AES-256-GCM with HKDF-derived keys
3. **Assemble** — Launcher + payload combined
4. **Sign** — Ed25519 signature appended
5. **Launch** — Verify → decrypt → execute from memory

```
compile → sign → launch → agent runs
```
