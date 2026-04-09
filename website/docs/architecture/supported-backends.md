---
sidebar_position: 4
---

# Supported Backends

Snapfzz Seal supports compilation backends for transforming agent source code into sealed executables. This document describes **currently implemented** backends and their limitations.

:::warning

Some features documented elsewhere (auto-install, `--backend-opts`, `--backend-chain`) are **NOT implemented**. This document reflects reality.

:::

## Backend Overview

Backends are responsible for compiling agent source code into standalone executables that can be sealed and encrypted. The choice of backend affects:

- **Execution performance** — Native vs interpreted execution
- **Binary size** — Compiled size overhead
- **Dependency handling** — Static vs dynamic linking
- **Platform support** — Target OS and architecture

## Currently Implemented Backends

### PyInstaller Backend

**Status**: Implemented

Compiles Python agents into standalone executables using PyInstaller's bundling mechanism.

**Supported platforms**:
- Linux x86_64
- macOS arm64, x86_64
- Windows x86_64

**Features**:
- ✅ Single-file bundling (`--onefile`)
- ✅ Basic dependency detection
- ❌ NO auto-install (requires pre-installed PyInstaller)
- ❌ NO `--backend-opts` passthrough
- ❌ NO UPX compression via CLI

**Configuration**:

```bash
seal compile \
  --backend pyinstaller \
  --project ./my_agent \
  --user-fingerprint "$USER_FP" \
  --sandbox-fingerprint auto \
  --output ./agent.sealed
```

**Requirements**:
- Python 3.7 or later
- **PyInstaller must be pre-installed** (`pip install pyinstaller`)
- Target platform Python environment

**Limitations**:
- Larger binary size (includes Python runtime)
- Slower startup compared to native code
- Returns error if `pyinstaller` command not found

**Best for**:
- Python-based agents with complex dependencies
- Cross-platform deployment requirements
- Rapid prototyping and development

### Nuitka Backend

**Status**: Implemented (Default)

Compiles Python agents into optimized native executables using Nuitka's ahead-of-time compilation.

**Supported platforms**:
- Linux x86_64
- macOS arm64, x86_64
- Windows x86_64

**Features**:
- ✅ Python-to-C compilation
- ✅ Better performance than PyInstaller
- ✅ Smaller binary footprint
- ❌ NO auto-install (requires pre-installed Nuitka)
- ❌ NO `--backend-opts` passthrough
- ❌ NO plugin flags via CLI

**Configuration**:

```bash
seal compile \
  --backend nuitka \
  --project ./my_agent \
  --user-fingerprint "$USER_FP" \
  --sandbox-fingerprint auto \
  --output ./agent.sealed
```

**Requirements**:
- Python 3.7 or later
- C compiler (gcc, clang, or MSVC)
- **Nuitka must be pre-installed** (`pip install nuitka`)
- Development headers for compiled dependencies

**Compilation time**: Significantly longer than PyInstaller due to full compilation pass

**Limitations**:
- Longer compilation times
- Returns error if `nuitka` command not found

**Best for**:
- Performance-critical Python agents
- Production deployments requiring minimal overhead
- Agents with computationally intensive workloads

## Backends NOT Exposed to Users

### Go Backend

**Status**: Implemented internally, **NOT user-accessible**

The Go backend exists in the compiler crate but is **not exposed via `seal compile` CLI**.

**Why not accessible**:
- `seal compile` only accepts `--backend nuitka` or `--backend pyinstaller`
- No `--backend go` option in current CLI
- Hardcoded for internal use with `GOOS=linux`, `GOARCH=amd64`

**Do NOT attempt**:
```bash
# This will FAIL - go backend not exposed
seal compile --backend go --project ./agent
```

## Backends NOT Implemented

### Native Backend

**Status**: NOT IMPLEMENTED

Contrary to some documentation, there is **no native backend** for sealing pre-compiled binaries.

**What doesn't exist**:
- ❌ No `--backend native` option
- ❌ No `--binary` flag for pre-compiled executables
- ❌ No direct sealing of arbitrary binaries

**If you need this**:
- Build your executable separately
- Use a Python shim that calls your binary
- Compile with PyInstaller/Nuitka wrapping your tool

## Backend Selection

### Manual Selection

Specify backend explicitly:

```bash
seal compile --backend <nuitka|pyinstaller> --project ./agent --user-fingerprint "$FP" --sandbox-fingerprint auto --output ./agent.sealed
```

### Default Behavior

When `--backend` is omitted, defaults to `nuitka`.

### What DOESN'T Exist

**Auto-detection**: NOT IMPLEMENTED
- No automatic detection of project type
- No fallback chain between backends
- Manual selection required if default fails

**Backend chain**: NOT IMPLEMENTED
- No `--backend-chain` option
- No fallback behavior

**Backend options**: NOT IMPLEMENTED
- No `--backend-opts` passthrough
- Cannot pass custom flags to backend tools

## Backend Performance Comparison

| Backend | Compilation Time | Binary Size | Runtime Performance |
|---------|-----------------|-------------|---------------------|
| PyInstaller | Fast (30s-2m) | Large (50-200MB) | Slower (interpreter) |
| Nuitka | Slow (2-10m) | Medium (30-100MB) | Fast (native) |

## Troubleshooting

### Backend Tool Not Found

**Symptom**: `pyinstaller not found` or `nuitka not found`

**Cause**: Backend tool not installed

**Solution**:
```bash
# For PyInstaller
pip install pyinstaller

# For Nuitka
pip install nuitka
```

### Missing Dependencies

**Symptom**: Compilation fails with import errors

**Cause**: Dynamic imports not detected by backend

**Solution**:
- For PyInstaller: Manually create a spec file with hidden imports
- For Nuitka: Use a `nuitka.config` file in your project
- Note: Cannot pass these via `seal compile` CLI (no `--backend-opts`)

### Cross-Compilation Issues

**Symptom**: Binary fails to execute on target platform

**Cause**: Backend compiled for wrong platform

**Solution**:
- Run compilation on target platform
- Or use appropriate cross-compilation setup for the backend tool

## Future Backends

The following backends are **planned** but NOT implemented:

- **Rust** — Native Rust compilation via Cargo
- **Node.js** — JavaScript/TypeScript agents
- **Java** — JVM agents via GraalVM
- **.NET** — C#/F# agents via Native AOT
- **Native** — Direct binary sealing

These appear in planning documents but have no implementation. Do not rely on them.