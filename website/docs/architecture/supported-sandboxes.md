---
sidebar_position: 5
---

# Supported Sandboxes

Snapfzz Seal uses sandbox backends for isolated agent execution. This document describes the **currently implemented** sandbox capabilities.

:::warning

Only **Docker** is currently implemented. Native and Firecracker sandboxes documented elsewhere are **NOT implemented**. This document reflects reality.

:::

## Sandbox Overview

Sandbox backends create isolated execution environments where sealed agents run. The choice of sandbox affects:

- **Isolation level** — Process, container, or VM isolation
- **Resource overhead** — Memory and CPU overhead
- **Security guarantees** — Attack surface and escape resistance
- **Startup latency** — Time to provision sandbox

## Implemented Sandboxes

### Docker Sandbox

**Status**: Implemented (Primary and only backend)

Executes sealed agents in Docker containers with security hardening and resource controls.

**Supported platforms**:
- Linux x86_64 (native Docker)
- macOS arm64, x86_64 (Docker Desktop)
- Windows x86_64 (WSL2 Docker)

**Actually Implemented Features**:

| Feature | Status | Notes |
|---------|--------|-------|
| Container isolation | ✅ | Namespace/cgroup separation |
| Memory limit | ✅ | Optional via `memory_mb` |
| Timeout enforcement | ✅ | Via `timeout_secs` |
| Automatic cleanup | ✅ | Container removed after execution |
| No-new-privileges | ✅ | Hardcoded |
| Capabilities dropped | ✅ | `--cap-drop ALL` |
| Read-only rootfs | ✅ | Hardcoded |
| tmpfs /tmp | ✅ | Hardcoded |
| PIDs limit | ✅ | Fixed at 64 |
| Environment variables | ✅ | Pass custom env |

**NOT Implemented** (despite claims elsewhere):

| Feature | Status | Notes |
|---------|--------|-------|
| CPU quota/period | ❌ | Not configurable |
| Disk I/O limits | ❌ | Not implemented |
| Network isolation toggle | ❌ | No disable flag |
| Volume mounting | ❌ | Not in API schema |
| Custom seccomp profile | ❌ | Not configurable |
| AppArmor/SELinux profile | ❌ | Not configurable |
| User namespace/rootless | ❌ | Not configurable |
| Log streaming | ❌ | Post-execution capture only |

**Configuration**:

The actual API schema for sandbox configuration:

```json
{
  "sandbox": {
    "image": "ubuntu:22.04",
    "timeout_secs": 3600,
    "memory_mb": 512,
    "env": [["KEY", "value"]]
  }
}
```

**Example dispatch request**:

```bash
curl -X POST http://localhost:9090/api/v1/dispatch \
  -H "Content-Type: application/json" \
  -d '{
    "job_id": "uuid-from-compile",
    "sandbox": {
      "image": "ubuntu:22.04",
      "timeout_secs": 3600,
      "memory_mb": 512
    }
  }'
```

**Execution flow**:

1. Pull specified Docker image
2. Create container with hardened flags:
   - `--security-opt no-new-privileges:true`
   - `--cap-drop ALL`
   - `--read-only`
   - `--tmpfs /tmp`
   - `--pids-limit 64`
   - `--memory` (if specified)
3. Copy sealed binary into container
4. Execute: `chmod +x /tmp/snapfzz-sealed && /tmp/snapfzz-sealed`
5. Capture stdout/stderr
6. Destroy container
7. Return execution results

**Security properties**:
- ✅ Namespace isolation (PID, network, mount, UTS)
- ✅ cgroup resource limits
- ✅ Reduced capability set
- ✅ Read-only root filesystem
- ✅ Prevents privilege escalation (no-new-privileges)

**Requirements**:
- Docker Engine 20.10+
- Sufficient disk space for images
- Network access for image pulls (or pre-pulled images)

**Limitations**:
- Higher resource overhead than native execution
- Docker daemon dependency
- No network isolation (containers have network access)
- Logs captured post-execution, not streamed

**Best for**:
- Production deployments
- Multi-tenant environments
- Untrusted agent execution
- Workloads requiring container isolation

## NOT Implemented Sandboxes

### Native Sandbox

**Status**: NOT IMPLEMENTED

Contrary to some documentation, there is **no native sandbox backend** in the server.

**What doesn't exist**:
- ❌ No `NativeBackend` implementation
- ❌ No server-side seccomp sandbox
- ❌ No ulimit-based resource controls
- ❌ No `type: native` in sandbox config

**Why it's mentioned**:
- Seccomp exists in the **launcher** (client-side execution)
- This is different from server sandbox backends
- Planning documents reference future native sandbox

**Do not attempt**:
```json
// This will NOT work
{
  "sandbox": {
    "type": "native"
  }
}
```

### Firecracker Sandbox

**Status**: NOT IMPLEMENTED (Planned only)

Firecracker microVM execution is documented as "planned" but has **no implementation**.

**What doesn't exist**:
- ❌ No `FirecrackerBackend` implementation
- ❌ No microVM provisioning
- ❌ No VM configuration schema
- ❌ No KVM integration

**What exists**:
- ✅ `RuntimeKind::Firecracker` enum for detection
- ✅ Detection heuristics in fingerprint module
- ✅ Planning documents

**If you need this**:
- Wait for future implementation
- Use Docker backend currently
- Consider external Firecracker orchestration

## Sandbox Selection

### Current State

**No selection possible** — Docker is hardcoded as the only backend.

The server initializes with:
```rust
pub type SandboxProvisioner = DockerBackend;
```

There is no runtime backend selection.

### Future Roadmap

Planned sandbox backends (NOT currently available):

| Backend | Status | Isolation | Target Use Case |
|---------|--------|-----------|-----------------|
| Docker | ✅ Implemented | Container | Production |
| gVisor | 🔜 Planned | User-space kernel | Enhanced isolation |
| Firecracker | 🔜 Planned | MicroVM | High-security |
| Kata Containers | 🔜 Planned | VM-container | Strong isolation |

## Resource Management

### What's Actually Configurable

**Memory limit**:
```json
{
  "sandbox": {
    "memory_mb": 512
  }
}
```

**Timeout**:
```json
{
  "sandbox": {
    "timeout_secs": 3600
  }
}
```

**Environment variables**:
```json
{
  "sandbox": {
    "env": [["API_KEY", "secret"], ["DEBUG", "true"]]
  }
}
```

### What's NOT Configurable

- ❌ CPU quota/period
- ❌ Disk I/O limits
- ❌ Network enable/disable
- ❌ Process limits (fixed at 64)
- ❌ Custom security profiles
- ❌ Volume mounts

## Timeout Enforcement

Timeout is enforced via async timeout wrapper around `docker exec`:

- If execution exceeds `timeout_secs`, the async call times out
- Container is destroyed via `docker rm -f`
- Job status set to `failed`

**NOT implemented**:
- ❌ SIGTERM → grace period → SIGKILL escalation
- ❌ Graceful shutdown signaling
- ❌ Custom grace period configuration

## Log Handling

**Implementation**: Post-execution capture only

Logs are **NOT streamed** during execution. They are captured after the process completes:

1. Process executes to completion (or timeout)
2. stdout/stderr captured from container
3. Results returned in job result object

**Result schema**:
```json
{
  "job_id": "uuid",
  "status": "completed",
  "result": {
    "exit_code": 0,
    "stdout": "...",
    "stderr": "..."
  }
}
```

**What doesn't exist**:
- ❌ No `stream_logs` API
- ❌ No SSE/WebSocket streaming
- ❌ No real-time log endpoint
- ❌ No `GET /logs/{id}` route

## Performance Characteristics

| Metric | Docker Backend |
|--------|---------------|
| Startup latency | ~500ms |
| Memory overhead | ~50MB |
| CPU overhead | ~2% |
| Isolation strength | Container-level |

## Troubleshooting

### Sandbox Provisioning Failures

**Symptom**: Container creation fails

**Solutions**:
- Check Docker daemon: `docker ps`
- Verify disk space: `df -h`
- Check image availability: `docker images`
- Review Docker logs: `journalctl -u docker`

### Timeout Issues

**Symptom**: Agent terminated before completion

**Solutions**:
- Increase `timeout_secs` in dispatch request
- Optimize agent performance
- Profile execution to identify bottlenecks

### Resource Limit Violations

**Symptom**: Agent killed unexpectedly

**Diagnosis**:
- Check if memory limit was exceeded
- Check logs for OOM killer: `dmesg | grep -i "out of memory"`

**Solutions**:
- Increase `memory_mb` in dispatch request
- Optimize agent memory usage

## Custom Sandboxes

The sandbox trait exists in code, but **no registration mechanism is exposed** for custom backends.

**Trait definition** (internal):
```rust
#[async_trait]
pub trait SandboxBackend: Send + Sync {
    async fn provision(&self, config: &SandboxConfig) -> Result<SandboxHandle, SealError>;
    async fn copy_into(&self, handle: &SandboxHandle, host_path: &Path, target: &str) -> Result<(), SealError>;
    async fn exec(&self, handle: &SandboxHandle, command: &str, timeout_secs: u64) -> Result<ExecutionResult, SealError>;
    async fn destroy(&self, handle: &SandboxHandle) -> Result<(), SealError>;
    fn runtime_kind(&self) -> RuntimeKind;
}
```

**Not user-extensible**:
- ❌ No `register_sandbox` API
- ❌ No plugin system
- ❌ Backend hardcoded at compile time