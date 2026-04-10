---
sidebar_position: 4
---

# Supported Backends

Snapfzz Seal supports compilation backends for transforming agent source code into sealed executables.

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

### Go Backend

**Status**: ✅ Implemented

Compiles Go agents into statically-linked native executables.

**Supported platforms**:
- Linux x86_64, arm64
- macOS arm64, x86_64 (for build only)

**Features**:
- ✅ Statically-linked binaries (zero runtime dependencies)
- ✅ Minimal binary size
- ✅ Fast execution
- ❌ NO auto-install (requires pre-installed Go toolchain)
- ❌ NO `--backend-opts` passthrough

**Configuration**:

```bash
seal compile \
  --backend go \
  --project ./my_go_agent \
  --user-fingerprint "$USER_FP" \
  --sandbox-fingerprint auto \
  --output ./agent.sealed
```

**Requirements**:
- Go 1.21 or later
- `go.mod` file in project root

**Compilation behavior**:
- Sets `GOOS=linux`, `CGO_ENABLED=0`
- Auto-detects `GOARCH` from host architecture (arm64 or amd64)
- Produces statically-linked Linux binary

**Best for**:
- Performance-critical agents
- Minimal dependency footprint
- High-performance networking or compute workloads

---

## Backends NOT Implemented

### Native Backend

**Status**: NOT IMPLEMENTED

There is **no native backend** for sealing pre-compiled binaries.

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
seal compile --backend <nuitka|pyinstaller|go> --project ./agent --user-fingerprint "$FP" --sandbox-fingerprint auto --output ./agent.sealed
```

### Default Behavior

When `--backend` is omitted, defaults to `nuitka`.

### What DOESN'T Exist

**Auto-detection**: NOT IMPLEMENTED
- No automatic detection of project type
- Manual selection required if default fails

**Backend chain**: NOT IMPLEMENTED for users
- No `--backend-chain` CLI option
- Internal fallback chain exists in compiler library (Nuitka → PyInstaller → Go)
- Not user-configurable

**Backend options**: NOT IMPLEMENTED
- No `--backend-opts` passthrough
- Cannot pass custom flags to backend tools

## Backend Performance Comparison

| Backend | Compilation Time | Binary Size | Runtime Performance |
|---------|-----------------|-------------|---------------------|
| PyInstaller | Fast (30s-2m) | Large (50-200MB) | Slower (interpreter) |
| Nuitka | Slow (2-10m) | Medium (30-100MB) | Fast (native) |
| Go | Fast (10s-1m) | Small (10-50MB) | Fast (native) |

## Execution Modes

Different backends use different execution strategies based on their technical requirements:

### Memory Execution (Go Backend)

**Backend**: Go

**Execution Mode**: `memfd` — in-memory execution via file descriptor

**How it works**:
- Launcher creates anonymous memory file (`memfd_create`)
- Decrypts payload into memory
- Executes directly from memory via `fexecve`
- No disk files created during execution

**Security advantages**:
- ✅ Zero disk artifacts — no temp files
- ✅ No forensic recovery — deleted immediately after use
- ✅ Maximum stealth — process appears only in memory

**Technical requirement**:
- Go binaries are statically-linked ELF executables
- Can execute from memory file descriptors without filesystem dependencies

### Temp-File Execution (Python Backends)

**Backends**: PyInstaller, Nuitka

**Execution Mode**: temp-file with immediate unlink

**How it works**:
- Launcher creates temp file in `/dev/shm` (RAM filesystem)
- Decrypts payload to temp file
- Immediately unlinks file (removes from filesystem)
- Executes via fork/exec
- File exists only briefly during execution

**Security characteristics**:
- ⚠️ Brief disk visibility during execution
- ✅ Immediate unlink prevents persistence
- ⚠️ Forensic recovery possible during active execution

**Technical requirement**:
- Python bundlers (PyInstaller, Nuitka) use bootloader that reads attached data via `fopen()`
- Bootloader needs real filesystem path for `/proc/self/exe` → PKG archive access
- Cannot use memfd execution (bootloader incompatible)

### Why Different Modes?

**Root cause**: Python bootloader architecture

PyInstaller and Nuitka embed payload data inside the executable:
1. Bootloader reads `/proc/self/exe` path
2. Opens executable with `fopen()` to read attached PKG archive
3. Memory file descriptors (`/memfd:snapfzz-seal-payload`) cannot be reopened with `fopen()`

**Trade-off table**:

| Execution Mode | Disk Visibility | Persistence | Forensic Recovery |
|----------------|-----------------|-------------|-------------------|
| memfd (Go) | NONE | NONE | IMPOSSIBLE |
| temp-file (Python) | MEDIUM (brief `/dev/shm` visible) | LOW (immediate unlink) | LOW (possible during execution) |

**Mitigations for temp-file execution**:
- `/dev/shm` preferred over `/tmp` (RAM filesystem)
- `O_EXCL | O_CREAT` prevents symlink attacks
- Random UUID filename prevents prediction
- Immediate unlink after fork
- `PDEATHSIG` terminates child if launcher dies

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

For planned backends (Rust, Node.js, JVM, .NET, Native), see the [Roadmap](../roadmap.md).