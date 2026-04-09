---
sidebar_position: 5
---

# Supported Sandboxes

Snapfzz Seal supports multiple sandbox backends for isolated agent execution. Sandboxes provide resource isolation, security boundaries, and controlled execution environments for sealed agents.

## Sandbox Overview

Sandbox backends are responsible for creating isolated execution environments where sealed agents run. The choice of sandbox affects:

- **Isolation level** — Process, container, or VM isolation
- **Resource overhead** — Memory and CPU overhead of sandbox
- **Security guarantees** — Attack surface and escape resistance
- **Startup latency** — Time to provision sandbox

## Built-in Sandboxes

### Docker Sandbox

**Status**: Stable (Primary backend)

Executes sealed agents in Docker containers with configurable resource limits and network isolation.

**Supported platforms**:
- Linux x86_64 (native Docker)
- macOS arm64, x86_64 (Docker Desktop)
- Windows x86_64 (WSL2 Docker)

**Features**:
- Full container isolation
- Resource limits (CPU, memory, disk I/O)
- Network isolation (optional)
- Volume mounting for input/output
- Automatic cleanup on completion
- Timeout enforcement
- Log streaming

**Configuration**:

```yaml
sandbox:
  type: docker
  image: ubuntu:22.04
  resources:
    cpu_quota: 50000      # 50% of CPU
    memory: "512m"        # 512MB RAM limit
    pids_limit: 100       # Max 100 processes
  network:
    disabled: true        # No network access
  timeout_secs: 3600      # 1 hour max execution
```

**Execution flow**:

1. Pull or build container image
2. Create container with resource limits
3. Copy sealed binary into container
4. Execute with timeout
5. Stream logs to orchestration API
6. Cleanup container on completion

**Security properties**:
- Namespace isolation (PID, network, mount, UTS)
- Control group (cgroup) resource limits
- Optional seccomp profiles
- Optional AppArmor/SELinux profiles
- User namespace support (rootless containers)

**Requirements**:
- Docker Engine 20.10+
- Sufficient disk space for images
- Network access for image pulls (or pre-pulled images)

**Limitations**:
- Higher resource overhead than native execution
- Docker daemon dependency
- Potential privilege escalation via Docker socket (mitigated by best practices)

**Best for**:
- Production deployments
- Multi-tenant environments
- Untrusted agent execution
- Workloads requiring strong isolation

### Native Sandbox

**Status**: Stable (Development use only)

Executes sealed agents directly on the host with seccomp-based isolation.

**Supported platforms**:
- Linux x86_64 (full support)
- macOS arm64, x86_64 (limited support)
- Windows x86_64 (no-op stub)

**Features**:
- Zero virtualization overhead
- Direct hardware access
- seccomp syscall filtering
- Resource limits via ulimit
- Fast startup (< 10ms)

**Configuration**:

```yaml
sandbox:
  type: native
  seccomp_profile: "default"  # or path to custom profile
  ulimits:
    cpu_time: 3600            # CPU time limit in seconds
    memory: "1g"              # Memory limit
    processes: 100            # Max processes
  timeout_secs: 3600
```

**Security properties**:
- seccomp-bpf syscall filtering
- Resource limits via ulimit
- No filesystem isolation (agent can access host filesystem)
- No network isolation
- No PID namespace isolation

**Requirements**:
- Linux kernel with seccomp support
- Appropriate privileges for seccomp setup

**Limitations**:
- **NOT suitable for untrusted agents**
- Minimal isolation compared to containers
- Agent can access host resources
- No protection against malicious syscalls not in seccomp filter

**Best for**:
- Development and testing
- Trusted agents in controlled environments
- Performance benchmarking
- CI/CD pipelines with controlled access

### Firecracker Sandbox

**Status**: Planned (Experimental)

Executes sealed agents in lightweight microVMs using Firecracker.

**Supported platforms**:
- Linux x86_64 (requires KVM)

**Features**:
- Hardware-level isolation (VM)
- Microsecond startup times
- Minimal resource overhead (~5MB per VM)
- Strong security boundaries
- Resource limits via cgroups

**Configuration**:

```yaml
sandbox:
  type: firecracker
  vm:
    vcpus: 1
    memory: "512m"
    kernel: "/path/to/vmlinux"
    rootfs: "/path/to/rootfs.ext4"
  timeout_secs: 3600
```

**Security properties**:
- Hardware virtualization boundary
- Independent kernel instance
- No shared kernel with host
- Stronger isolation than containers
- VM escape requires hypervisor vulnerability

**Requirements**:
- KVM support
- Firecracker binary
- Custom kernel and rootfs images

**Limitations**:
- Linux-only (requires KVM)
- Requires custom VM images
- Longer startup than containers (~125ms)
- Higher memory overhead than containers

**Best for**:
- High-security deployments
- Multi-tenant SaaS platforms
- Untrusted agent execution
- Strong isolation requirements

## Sandbox Selection

### Selection Criteria

| Criteria | Docker | Native | Firecracker |
|----------|--------|--------|-------------|
| Isolation strength | Strong | Weak | Strongest |
| Resource overhead | Medium | None | Low |
| Startup latency | ~500ms | <10ms | ~125ms |
| Security | Good | Poor | Excellent |
| Platform support | Broad | Linux | Linux (KVM) |
| Complexity | Medium | Low | High |

### Recommendation Matrix

| Use Case | Recommended Sandbox |
|----------|---------------------|
| Production, multi-tenant | Docker |
| Production, high-security | Firecracker (when available) |
| Development, testing | Native |
| Trusted agents | Native |
| Untrusted agents | Docker or Firecracker |
| Performance-critical | Native (if trusted) |
| Maximum isolation | Firecracker |

## Custom Sandboxes

Organizations can implement custom sandboxes for specialized execution requirements.

### Sandbox Interface

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

### Implementation Requirements

1. **Provisioning** — Create isolated execution environment
2. **File operations** — Support copying files into/out of sandbox
3. **Execution** — Run commands with timeout enforcement
4. **Cleanup** — Destroy all resources on completion
5. **Thread safety** — Backend must be `Send + Sync`
6. **Error handling** — Use descriptive `SealError` variants

### Registration

Custom sandboxes are registered at initialization:

```rust
let sandbox = MyCustomSandbox::new();
seal::register_sandbox(Box::new(sandbox));
```

## Resource Management

### CPU Limits

Control CPU allocation to prevent runaway agents:

```yaml
# Docker
resources:
  cpu_quota: 50000      # 50% of one CPU core
  cpu_period: 100000    # Period in microseconds

# Native
ulimits:
  cpu_time: 3600        # CPU time in seconds
```

### Memory Limits

Prevent memory exhaustion:

```yaml
# Docker
resources:
  memory: "512m"        # Hard limit
  memory_swap: "1g"     # Include swap

# Native
ulimits:
  memory: "1g"          # Virtual memory limit
```

### Process Limits

Limit number of processes to prevent fork bombs:

```yaml
# Docker
resources:
  pids_limit: 100

# Native
ulimits:
  processes: 100
```

### Timeout Enforcement

All sandboxes support execution timeouts:

```yaml
timeout_secs: 3600      # Kill after 1 hour
```

Timeout behavior:
- Process receives SIGTERM
- 10-second grace period
- Then SIGKILL if still running
- Logs capture timeout event

## Security Profiles

### Docker Security Profiles

Apply additional security restrictions:

```yaml
security:
  seccomp_profile: "/path/to/seccomp.json"
  apparmor_profile: "snapfzz-seal-profile"
  capabilities:
    drop: ["ALL"]
    add: ["NET_BIND_SERVICE"]
  no_new_privileges: true
  read_only_rootfs: true
```

### Custom seccomp Profiles

Define allowed syscalls:

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": ["read", "write", "exit", "mmap"],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

## Monitoring and Logging

### Log Streaming

All sandboxes support real-time log streaming:

```rust
let logs = sandbox.stream_logs(&handle).await?;
while let Some(line) = logs.next().await {
    println!("{}", line);
}
```

### Resource Monitoring

Monitor resource usage during execution:

```yaml
monitoring:
  enabled: true
  metrics:
    - cpu_usage
    - memory_usage
    - network_io
    - disk_io
  interval_secs: 5
```

## Troubleshooting

### Sandbox Provisioning Failures

**Symptom**: Timeout or error when creating sandbox

**Docker solutions**:
- Check Docker daemon is running: `docker ps`
- Verify sufficient disk space: `df -h`
- Check image availability: `docker images`
- Review Docker logs: `journalctl -u docker`

**Native solutions**:
- Verify seccomp support: `grep SECCOMP /boot/config-$(uname -r)`
- Check ulimit settings: `ulimit -a`
- Verify sufficient memory: `free -h`

### Resource Limit Violations

**Symptom**: Agent killed unexpectedly

**Diagnosis**:
- Check logs for OOM killer: `dmesg | grep -i "out of memory"`
- Review cgroup limits: `cat /sys/fs/cgroup/.../memory.limit_in_bytes`
- Monitor resource usage during execution

**Solutions**:
- Increase memory limits
- Optimize agent code
- Reduce parallelism

### Timeout Issues

**Symptom**: Agent terminated before completion

**Solutions**:
- Increase timeout: `timeout_secs: 7200`
- Optimize agent performance
- Profile execution to identify bottlenecks
- Use incremental checkpointing for long-running agents

## Performance Comparison

| Sandbox | Startup Time | Memory Overhead | CPU Overhead | Isolation |
|---------|--------------|-----------------|--------------|-----------|
| Docker | ~500ms | ~50MB | ~2% | Strong |
| Native | <10ms | ~5MB | ~0% | Weak |
| Firecracker | ~125ms | ~5MB | ~1% | Strongest |

## Future Sandboxes

Planned sandbox backends:

- **gVisor** — User-space kernel for enhanced container isolation
- **Kata Containers** — Lightweight VM-based containers
- **AWS Nitro Enclaves** — Hardware-isolated compute environments
- **Azure Confidential Computing** — SGX-based secure enclaves