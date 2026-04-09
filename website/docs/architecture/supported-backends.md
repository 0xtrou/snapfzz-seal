---
sidebar_position: 4
---

# Supported Backends

Snapfzz Seal supports multiple compilation backends for transforming agent source code into sealed executables. Each backend is optimized for specific runtime environments and agent architectures.

## Backend Overview

Backends are responsible for compiling agent source code into standalone executables that can be sealed and encrypted. The choice of backend affects:

- **Execution performance** — Native vs interpreted execution
- **Binary size** — Compiled size overhead
- **Dependency handling** — Static vs dynamic linking
- **Platform support** — Target OS and architecture

## Built-in Backends

### PyInstaller Backend

**Status**: Stable

Compiles Python agents into standalone executables using PyInstaller's bundling mechanism.

**Supported platforms**:
- Linux x86_64
- macOS arm64, x86_64
- Windows x86_64

**Features**:
- Automatic dependency detection
- Single-file bundling (`--onefile`)
- Support for Python 3.7+
- Optional UPX compression

**Configuration**:

```bash
seal compile \
  --backend pyinstaller \
  --project ./my_agent \
  --output ./agent.sealed \
  --backend-opts="--onefile --noconsole"
```

**Requirements**:
- Python 3.7 or later
- PyInstaller 5.0+ (auto-installed if missing)
- Target platform Python environment

**Limitations**:
- Larger binary size (includes Python runtime)
- Slower startup compared to native code
- May require additional hidden imports for dynamic imports

**Best for**:
- Python-based agents with complex dependencies
- Cross-platform deployment requirements
- Rapid prototyping and development

### Nuitka Backend

**Status**: Stable

Compiles Python agents into optimized native executables using Nuitka's ahead-of-time compilation.

**Supported platforms**:
- Linux x86_64
- macOS arm64, x86_64
- Windows x86_64

**Features**:
- Full Python-to-C compilation
- Significant performance improvements over PyInstaller
- Smaller binary footprint
- Optional LLVM-based optimizations
- Plugin support for common frameworks

**Configuration**:

```bash
seal compile \
  --backend nuitka \
  --project ./my_agent \
  --output ./agent.sealed \
  --backend-opts="--enable-plugin=numpy --follow-imports"
```

**Requirements**:
- Python 3.7 or later
- C compiler (gcc, clang, or MSVC)
- Nuitka 1.5+ (auto-installed if missing)
- Development headers for compiled dependencies

**Compilation time**: Significantly longer than PyInstaller due to full compilation pass

**Limitations**:
- Longer compilation times
- May require additional compilation flags for specific dependencies
- Debugging is more complex

**Best for**:
- Performance-critical Python agents
- Production deployments requiring minimal overhead
- Agents with computationally intensive workloads

### Go Backend

**Status**: Stable

Compiles Go agents directly using the Go compiler.

**Supported platforms**:
- Linux x86_64, arm64
- macOS x86_64, arm64
- Windows x86_64

**Features**:
- Native Go compilation
- Static binary generation
- Cross-compilation support
- Minimal runtime dependencies
- Small binary footprint

**Configuration**:

```bash
seal compile \
  --backend go \
  --project ./my_agent \
  --output ./agent.sealed \
  --backend-opts="-ldflags '-s -w'"
```

**Requirements**:
- Go 1.18 or later
- Go module support (`go.mod`)

**Limitations**:
- Go-specific only
- Requires proper module configuration

**Best for**:
- Go-based agents
- Minimal binary size requirements
- High-performance networking agents

### Native Backend

**Status**: Stable

Direct sealing of pre-compiled binaries without additional compilation.

**Supported platforms**:
- All platforms (uses existing binary)

**Features**:
- No compilation overhead
- Full control over build process
- Support for any executable format
- Ideal for CI/CD integration

**Configuration**:

```bash
seal compile \
  --backend native \
  --binary ./pre-built-agent \
  --output ./agent.sealed
```

**Requirements**:
- Pre-compiled executable matching target platform
- Binary must be compatible with target execution environment

**Limitations**:
- No automatic dependency handling
- Operator responsible for binary compatibility

**Best for**:
- Pre-compiled agents from external build systems
- Custom compilation pipelines
- Integration with existing build processes

## Backend Selection

### Automatic Selection

When no backend is specified, Snapfzz Seal attempts automatic selection:

1. **Go detection** — Checks for `go.mod` in project root
2. **Python detection** — Checks for `requirements.txt`, `setup.py`, or `.py` files
   - Prefers Nuitka if available (better performance)
   - Falls back to PyInstaller
3. **Native fallback** — Uses existing binary if provided

### Manual Selection

Specify backend explicitly for deterministic behavior:

```bash
seal compile --backend <backend-name> --project ./agent
```

### Backend Chain

Multiple backends can be chained for fallback behavior:

```bash
seal compile \
  --backend-chain nuitka,pyinstaller,native \
  --project ./agent
```

The chain attempts each backend in order until one succeeds.

## Custom Backends

Organizations can implement custom backends for specialized compilation requirements.

### Backend Interface

```rust
pub trait CompileBackend: Send + Sync {
    fn name(&self) -> &str;
    fn can_compile(&self, project_dir: &Path) -> bool;
    fn compile(&self, config: &CompileConfig) -> Result<PathBuf, SealError>;
}
```

### Implementation Requirements

1. **Deterministic detection** — `can_compile()` must return consistent results for identical inputs
2. **Artifact path** — `compile()` must return path to valid executable
3. **Error handling** — Use descriptive `SealError` variants for diagnostics
4. **Thread safety** — Backend must be `Send + Sync` for concurrent compilation

### Registration

Custom backends are registered at initialization:

```rust
let backend = MyCustomBackend::new();
seal::register_backend(Box::new(backend));
```

## Backend Performance Comparison

| Backend | Compilation Time | Binary Size | Runtime Performance | Dependencies |
|---------|-----------------|-------------|---------------------|--------------|
| PyInstaller | Fast (30s-2m) | Large (50-200MB) | Slower (interpreter) | Python runtime |
| Nuitka | Slow (2-10m) | Medium (30-100MB) | Fast (native) | None |
| Go | Fast (10-30s) | Small (5-20MB) | Fast (native) | None |
| Native | Instant | Variable | Native | Variable |

## Backend Configuration Options

### Common Options

| Option | Description | Applies To |
|--------|-------------|------------|
| `--backend` | Specify backend name | All |
| `--backend-opts` | Pass options to backend | All |
| `--backend-chain` | Fallback chain | All |

### PyInstaller-Specific

| Option | Description |
|--------|-------------|
| `--onefile` | Bundle into single executable |
| `--noconsole` | Hide console window (Windows) |
| `--hidden-import` | Specify additional imports |
| `--add-data` | Include data files |

### Nuitka-Specific

| Option | Description |
|--------|-------------|
| `--enable-plugin` | Enable framework plugin |
| `--follow-imports` | Include imported modules |
| `--nofollow-import-to` | Exclude specific modules |
| `--include-package` | Include entire package |

## Troubleshooting

### Missing Dependencies

**Symptom**: Compilation fails with import errors

**Solution**: Specify hidden imports or packages:

```bash
# PyInstaller
--backend-opts="--hidden-import=my_module"

# Nuitka
--backend-opts="--include-package=my_package"
```

### Large Binary Size

**Symptom**: Sealed binary exceeds expected size

**Solution**: Use Nuitka for Python, or enable compression:

```bash
# Nuitka with optimizations
--backend-opts="--nofollow-import-to=tests --follow-imports"

# PyInstaller with UPX
--backend-opts="--onefile --upx-dir=/path/to/upx"
```

### Cross-Compilation Issues

**Symptom**: Binary fails to execute on target platform

**Solution**: Use appropriate backend for target platform:

```bash
# Go cross-compilation
GOOS=linux GOARCH=amd64 seal compile --backend go --project ./agent
```

## Future Backends

The following backends are planned for future releases:

- **Rust** — Native Rust compilation via Cargo
- **Node.js** — JavaScript/TypeScript agents via pkg or nexe
- **Java** — JVM agents via GraalVM native-image
- **.NET** — C#/F# agents via Native AOT