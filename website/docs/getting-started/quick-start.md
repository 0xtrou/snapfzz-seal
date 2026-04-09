# Quick Start

This section provides a complete end-to-end example with expected output and operational checks.

:::warning Platform Requirement

Sealed agents can **only be executed on Linux x86_64**. macOS and Windows are supported for building/signing only, not for execution.

:::

## Prerequisites

Before starting, ensure you have:

1. **Rust toolchain** — For building the launcher
2. **Python 3.7+** — For the demo agent
3. **Nuitka or PyInstaller** — For compiling the agent (`pip install nuitka`)
4. **Linux x86_64** — For execution (macOS/Windows can only build)

## Step 0: Build the launcher

The launcher binary must be built before compiling agents:

```bash
cargo build --release
```

This creates `./target/release/snapfzz-seal-launcher`, which is required for the compile step.

:::note

Without this step, `seal compile` will fail with "launcher path missing" error.

:::

## Step 1: Generate builder keys

```bash
seal keygen
```

Expected output pattern:

```text
secret: /home/<user>/.snapfzz-seal/keys/builder_secret.key
public: /home/<user>/.snapfzz-seal/keys/builder_public.key
builder id: <16-hex-prefix>
```

## Step 2: Compile and seal an agent

```bash
USER_FP=$(openssl rand -hex 32)

seal compile \
  --project ./examples/demo_agent \
  --user-fingerprint "$USER_FP" \
  --sandbox-fingerprint auto \
  --output ./agent.sealed \
  --launcher ./target/release/snapfzz-seal-launcher
```

Expected output pattern:

```text
compiled and assembled binary: ./agent.sealed (<N> bytes)
```

### Alternative: Use environment variable for launcher

```bash
export SNAPFZZ_SEAL_LAUNCHER_PATH=./target/release/snapfzz-seal-launcher

seal compile \
  --project ./examples/demo_agent \
  --user-fingerprint "$USER_FP" \
  --sandbox-fingerprint auto \
  --output ./agent.sealed
```

## Step 3: Sign the sealed artifact

```bash
seal sign \
  --key ~/.snapfzz-seal/keys/builder_secret.key \
  --binary ./agent.sealed
```

No output indicates successful completion.

## Step 4: Verify signature

```bash
seal verify --binary ./agent.sealed --pubkey ~/.snapfzz-seal/keys/builder_public.key
```

Expected output:

```text
VALID (pinned to explicit public key)
```

## Step 5: Launch

```bash
seal launch --payload ./agent.sealed --user-fingerprint "$USER_FP"
```

Expected output shape:

```json
{
  "exit_code": 0,
  "stdout": "...",
  "stderr": ""
}
```

### About SNAPFZZ_SEAL_MASTER_SECRET_HEX

:::note

The `SNAPFZZ_SEAL_MASTER_SECRET_HEX` environment variable is shown in some examples but is **optional for normal usage**.

- **Normal case**: `seal compile` embeds the master secret in the artifact. No env var needed.
- **Fallback case**: Only needed if the embedded secret is missing or corrupted.

You can omit it in the standard workflow shown above.

:::

If you do need it (e.g., for manually constructed artifacts):

```bash
export SNAPFZZ_SEAL_MASTER_SECRET_HEX=$(openssl rand -hex 32)
seal launch --payload ./agent.sealed --user-fingerprint "$USER_FP"
```

## Step-by-step explanation

1. **`cargo build --release`** — Builds the launcher binary required for sealed artifacts.
2. **`keygen`** — Creates Ed25519 key material for builder identity.
3. **`compile`** — Builds the project, encrypts payload bytes, embeds master secret, and assembles launcher plus payload structure.
4. **`sign`** — Appends a detached verification block to the artifact.
5. **`verify`** — Checks signature with either embedded key or pinned public key.
6. **`launch`** — Performs signature verification, derives keys from runtime state, decrypts in memory, and executes.

## Troubleshooting

### `launcher path missing` during compile

**Cause**: `--launcher` flag and `SNAPFZZ_SEAL_LAUNCHER_PATH` were both absent.

**Solution**:

```bash
# Option 1: Build the launcher
cargo build --release

# Option 2: Set environment variable
export SNAPFZZ_SEAL_LAUNCHER_PATH=./target/release/snapfzz-seal-launcher
```

### `pyinstaller not found` or `nuitka not found`

**Cause**: Backend tool not installed.

**Solution**:

```bash
# For Nuitka (default backend)
pip install nuitka

# Or for PyInstaller
pip install pyinstaller
```

### `missing signature` during launch

**Cause**: Artifact was not signed, or signature block was truncated.

**Action**:

```bash
seal sign --key ~/.snapfzz-seal/keys/builder_secret.key --binary ./agent.sealed
seal verify --binary ./agent.sealed --pubkey ~/.snapfzz-seal/keys/builder_public.key
```

### `fingerprint mismatch`

**Cause**: Runtime context differs from compile-time binding input.

**Action**:

- Confirm `--user-fingerprint` exactly matches compile-time value.
- Rebuild with current environment parameters when intentional drift occurred.

### `memfd unsupported` (macOS/Windows)

**Cause**: Trying to launch on non-Linux platform.

**Solution**:

Sealed agents can only run on Linux x86_64. Build on macOS/Windows, but execute on Linux.

### `SNAPFZZ_SEAL_MASTER_SECRET_HEX is required`

**Cause**: No embedded secret was usable and environment secret was absent.

**Note**: This should not happen with normal `seal compile` output. If it does:

```bash
export SNAPFZZ_SEAL_MASTER_SECRET_HEX=$(openssl rand -hex 32)
```

But the compiled artifact should have the secret embedded already.

## Platform Support Reality

| Platform | Build/Sign | Execute |
|----------|------------|---------|
| Linux x86_64 | ✅ | ✅ |
| macOS arm64 | ✅ | ❌ |
| macOS x86_64 | ✅ | ❌ |
| Windows x86_64 | ✅ | ❌ |

**Key point**: You can compile and sign on any platform, but **execution requires Linux**.

## Security considerations

- **Use pinned public key verification** in all production paths.
- **Treat compile logs as potentially sensitive** operational data.
- **Store build artifacts** in access-controlled locations.
- **Remember**: Signatures verify integrity, not identity. Implement external key pinning for production.

## Limitations

- `auto` sandbox fingerprint mode is intended for convenience, not high-assurance remote identity.
- Runtime protection depends on host integrity and cannot resist full host compromise.
- No cross-platform execution — Linux only for sealed agent execution.