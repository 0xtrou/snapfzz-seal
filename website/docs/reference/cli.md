# CLI Commands

This reference describes the `seal` command-line interface.

## Global behavior

- Binary name: `seal`
- Configuration root in examples: `~/.snapfzz-seal/`
- On command failure, process exits with non-zero status.

## Command summary

| Command | Purpose |
|---|---|
| `seal compile` | Compile project, derive keys, assemble sealed artifact |
| `seal keygen` | Generate builder signing key pair |
| `seal launch` | Verify and launch sealed artifact |
| `seal server` | Start orchestration API service |
| `seal sign` | Append signature block to binary |
| `seal verify` | Verify signature with embedded or pinned key |

## `seal compile`

```bash
seal compile \
  --project <path> \
  --user-fingerprint <64-hex> \
  --sandbox-fingerprint <auto|64-hex> \
  --output <path> \
  [--launcher <path>] \
  [--backend <nuitka|pyinstaller>] \
  [--mode <batch|interactive>]
```

Flags:

- `--project`: source project directory
- `--user-fingerprint`: 32-byte fingerprint in hex (64 hex characters)
- `--sandbox-fingerprint`: `auto` or 32-byte hex value (64 hex characters)
- `--output`: destination file path
- `--launcher`: explicit launcher path override (or use `SNAPFZZ_SEAL_LAUNCHER_PATH`)
- `--backend`: compile backend selection (`nuitka` or `pyinstaller`, default: `nuitka`)
- `--mode`: payload mode byte selection (`batch` or `interactive`)

**Requirements**:
- Backend tool must be pre-installed (`pip install nuitka` or `pip install pyinstaller`)
- Launcher binary must exist (build with `cargo build --release`)

## `seal keygen`

```bash
seal keygen [--keys-dir <path>]
```

Flags:

- `--keys-dir`: destination directory for `builder_secret.key` and `builder_public.key`

Default:

- `~/.snapfzz-seal/keys`

Output:

```text
secret: /home/<user>/.snapfzz-seal/keys/builder_secret.key
public: /home/<user>/.snapfzz-seal/keys/builder_public.key
builder id: <16-hex-prefix>
```

## `seal sign`

```bash
seal sign --key <path> --binary <path>
```

Flags:

- `--key`: builder secret key path (hex-encoded 32-byte key)
- `--binary`: target artifact to sign in place

No output on success.

## `seal verify`

```bash
seal verify --binary <path> [--pubkey <path>]
```

Flags:

- `--binary`: artifact path
- `--pubkey`: optional pinned public key path

Output modes:

- `VALID (pinned to explicit public key)` — Signature matches pinned key
- `VALID (TOFU: using embedded key — use --pubkey for pinned builder identity)` — Signature valid but using embedded key
- `INVALID` — Signature verification failed
- `WARNING: unsigned` — No signature block found

:::note

`INVALID` result still exits with code `0`. Check output for verification status.

:::

## `seal launch`

```bash
seal launch \
  [--payload <path>] \
  [--fingerprint-mode <stable|session>] \
  [--user-fingerprint <64-hex>] \
  [--verbose]
```

Flags:

- `--payload`: explicit payload path
- `--fingerprint-mode`: `stable` or `session` (default: `stable`)
- `--user-fingerprint`: required for key derivation (64 hex characters)
- `--verbose`: enables detailed logging

### Flags Parsed but NOT Currently Wired

The following flags are **accepted by the CLI but NOT forwarded to the launcher**:

- `--mode` — Parsed but ignored at runtime
- `--max-lifetime` — Parsed but ignored at runtime
- `--grace-period` — Parsed but ignored at runtime

The launcher uses hardcoded values:
- `grace_period_secs: 30` (not configurable)

These flags may be implemented in future versions. Currently, they have no effect.

### Environment Variables for Launch

| Variable | Required | Purpose |
|----------|----------|---------|
| `SNAPFZZ_SEAL_MASTER_SECRET_HEX` | Optional* | 32-byte secret in hex for key derivation fallback |
| `SNAPFZZ_SEAL_LAUNCHER_SIZE` | Optional | Launcher-size hint for embedded payload extraction |

\* Only required if no embedded secret is available. Normal `seal compile` output includes embedded secret.

### Output

On success, outputs JSON:

```json
{
  "exit_code": 0,
  "stdout": "...",
  "stderr": ""
}
```

## `seal server`

```bash
seal server \
  [--bind <host:port>] \
  [--compile-dir <path>] \
  [--output-dir <path>]
```

Flags:

- `--bind`: listening socket (default: `0.0.0.0:9090` in wrapper, `127.0.0.1:9090` in standalone binary)
- `--compile-dir`: working directory for compile jobs (default: `./.snapfzz-seal/compile`)
- `--output-dir`: artifact output directory (default: `./.snapfzz-seal/output`)

:::warning No Authentication

The server has **no built-in authentication or authorization**. Deploy behind an authenticated gateway.

:::

## Exit codes

Current CLI behavior:

- `0`: command completed without error
- `1`: command returned an error (runtime error)
- `2`: CLI argument parse error (clap default)

Note: `seal verify` returns `0` even for `INVALID` results. Check output text.

Subprocess exit codes from launched payloads are returned in JSON output, not as CLI exit codes.

## Environment variables

| Variable | Purpose |
|----------|---------|
| `SNAPFZZ_SEAL_MASTER_SECRET_HEX` | 32-byte secret in hex for launch key derivation (fallback if no embedded secret) |
| `SNAPFZZ_SEAL_LAUNCHER_PATH` | Launcher path used by compile when `--launcher` is omitted |
| `SNAPFZZ_SEAL_LAUNCHER_SIZE` | Optional launcher-size hint for embedded payload extraction |
| `RUST_LOG` | Tracing verbosity (`error`, `warn`, `info`, `debug`, `trace`) |
| `DOCKER_BIN` | Explicit Docker binary path for server sandbox backend |

## Practical examples

### Complete workflow

```bash
# 1. Build the launcher first
cargo build --release

# 2. Generate keys
seal keygen

# 3. Generate user fingerprint
USER_FP=$(openssl rand -hex 32)

# 4. Compile and seal
seal compile \
  --project ./examples/demo_agent \
  --user-fingerprint "$USER_FP" \
  --sandbox-fingerprint auto \
  --output ./agent.sealed \
  --launcher ./target/release/snapfzz-seal-launcher

# 5. Sign
seal sign \
  --key ~/.snapfzz-seal/keys/builder_secret.key \
  --binary ./agent.sealed

# 6. Verify
seal verify \
  --binary ./agent.sealed \
  --pubkey ~/.snapfzz-seal/keys/builder_public.key

# 7. Launch
seal launch \
  --payload ./agent.sealed \
  --user-fingerprint "$USER_FP"
```

### Using environment variables

```bash
# Set launcher path globally
export SNAPFZZ_SEAL_LAUNCHER_PATH=./target/release/snapfzz-seal-launcher

# Now compile without --launcher flag
seal compile \
  --project ./agent \
  --user-fingerprint "$USER_FP" \
  --sandbox-fingerprint auto \
  --output ./agent.sealed
```

## Security considerations

- **Use pinned key verification** in production automation, not TOFU mode.
- **Avoid passing secrets via shell history** in shared terminals environments.
- **Restrict server network exposure** to authenticated local interfaces or protected tunnels.
- **Treat compile logs as potentially sensitive** — they may contain operational details.

## Limitations

- Exit code taxonomy is currently binary for CLI command success/failure.
- Structured machine-readable command output is limited to selected commands.
- `--backend-opts` for passing flags to backend tools is NOT implemented.
- Backend auto-install is NOT implemented — tools must be pre-installed.