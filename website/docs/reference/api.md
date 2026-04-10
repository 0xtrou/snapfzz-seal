---
sidebar_position: 2
---

# API Reference

This document describes the REST API for Snapfzz Seal orchestration server.

## Base URL

Default: `http://0.0.0.0:9090`

Standalone binary default: `http://127.0.0.1:9090`

## Authentication

**None.** The server has no built-in authentication or authorization.

:::danger

Deploy the server behind an authenticated gateway (reverse proxy, API gateway, etc.). Do not expose directly to untrusted networks.

:::

## Endpoints

### POST /api/v1/compile

Compile and seal an agent from source.

**Request**:

```json
{
  "project_dir": "./my_agent",
  "user_fingerprint": "64-hex-string",
  "sandbox_fingerprint": "auto"
}
```

**Fields**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `project_dir` | string | Yes | Path to agent project (must be within `compile_dir`) |
| `user_fingerprint` | string | Yes | 64 hex characters (32 bytes) |
| `sandbox_fingerprint` | string | Yes | `auto` or 64 hex characters |

**Response** (202 Accepted):

```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "pending"
}
```

**Notes**:
- Compilation runs asynchronously
- Request returns `202 Accepted` immediately
- `project_dir` validation happens synchronously (returns `400` if invalid path)
- Fingerprint format validation happens synchronously (returns `400` if invalid)
- Backend tool availability checked during async compilation (causes `failed` state)
- Use `GET /api/v1/jobs/\{job_id\}` to check progress

**Synchronous validation errors** (immediate `400` response):
- `project_dir` outside `compile_dir` or doesn't exist
- Invalid `user_fingerprint` format (not 64 hex chars)
- Invalid `sandbox_fingerprint` format (not `auto` or 64 hex chars)

**Async failures** (job transitions to `failed` state):
- Backend tool (Nuitka/PyInstaller/Go) not installed
- Compilation errors during backend execution

---

### POST /api/v1/dispatch

Launch a compiled agent in a Docker sandbox.

**Request**:

```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "sandbox": {
    "image": "ubuntu:22.04",
    "timeout_secs": 3600,
    "memory_mb": 512,
    "env": [["API_KEY", "secret"], ["DEBUG", "true"]]
  }
}
```

**Fields**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `job_id` | string | Yes | Job ID from compile step |
| `sandbox.image` | string | Yes | Docker image name |
| `sandbox.timeout_secs` | number | Yes | Execution timeout in seconds |
| `sandbox.memory_mb` | number | No | Memory limit in megabytes |
| `sandbox.env` | array | No | Array of `[key, value]` pairs |

**Response** (202 Accepted):

```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "dispatched"
}
```

**Errors**:

| Status | Condition | Response Body |
|--------|-----------|---------------|
| 404 | Job not found | `job not found` (plain text) |
| 400 | Job not ready for dispatch | `job is not ready for dispatch` (plain text) |

**Notes**:
- Job must be in `ready` state (compile completed successfully)
- Docker image will be pulled if not present (may trigger implicit pull by Docker daemon)
- Execution runs asynchronously after `202` response
- Provisioning/execution failures occur in background task and update job status to `failed`

---

### GET /api/v1/jobs/\{job_id\}

Get job status and details.

**Response**:

```json
{
  "id": "job-1705312800-0-abc12345",
  "status": "completed",
  "project_dir": "./my_agent",
  "output_path": "/path/to/artifact",
  "error": null,
  "created_at": 1705312800,
  "updated_at": 1705312920,
  "sandbox_id": "container-id-or-null",
  "result": {
    "exit_code": 0,
    "stdout": "Hello, World!",
    "stderr": ""
  }
}
```

**Field types**:

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Job ID (format: `job-<timestamp>-<sequence>-<hex>`) |
| `status` | string | Current job state |
| `created_at` | number | Unix timestamp (seconds since epoch) |
| `updated_at` | number | Unix timestamp (seconds since epoch) |

**Job States**:

| State | Description |
|-------|-------------|
| `pending` | Job created, waiting for compilation |
| `compiling` | Compilation in progress |
| `ready` | Compilation complete, ready for dispatch |
| `dispatched` | Sent to sandbox, not yet running |
| `running` | Currently executing in sandbox |
| `completed` | Execution finished successfully |
| `failed` | Compilation or execution failed |

**Errors**:

| Status | Error |
|--------|-------|
| 404 | `job not found` |

---

### GET /api/v1/jobs/\{job_id\}/results

Get execution results for a completed job.

**Response**:

```json
{
  "job_id": "job-1705312800-0-abc12345",
  "status": "completed",
  "result": {
    "exit_code": 0,
    "stdout": "Hello, World!",
    "stderr": ""
  }
}
```

**Result Fields**:

| Field | Type | Description |
|-------|------|-------------|
| `exit_code` | number | Process exit code |
| `stdout` | string | Standard output |
| `stderr` | string | Standard error |

**Behavior**:

- Returns `200 OK` for any existing job
- `result` may be `null` if job hasn't completed
- Check `status` field to determine if execution finished

**Errors**:

| Status | Error |
|--------|-------|
| 404 | `job not found` |

---

### GET /health

Health check endpoint.

**Response**:

```json
{
  "status": "ok",
  "jobs_count": 5
}
```

**Fields**:

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | Health status (`"ok"`) |
| `jobs_count` | number | Number of tracked jobs |

## NOT Implemented Endpoints

These endpoints do **NOT exist**:

| Endpoint | Status |
|----------|--------|
| `POST /compile` | ❌ Use `/api/v1/compile` |
| `POST /sign` | ❌ Not an API endpoint (use CLI) |
| `POST /launch` | ❌ Use `/api/v1/dispatch` |
| `GET /status/\{id\}` | ❌ Use `/api/v1/jobs/\{job_id\}` |
| `GET /logs/{id}` | ❌ Not implemented (no log streaming) |
| Any `/api/v1/logs` | ❌ Not implemented |

## Complete Workflow Example

```bash
# 1. Start the server
seal server --bind 0.0.0.0:9090

# 2. Compile an agent
curl -X POST http://localhost:9090/api/v1/compile \
  -H "Content-Type: application/json" \
  -d '{
    "project_dir": "./examples/demo_agent",
    "user_fingerprint": "'"$(openssl rand -hex 32)"'",
    "sandbox_fingerprint": "auto"
  }'

# Response: {"job_id": "uuid", "status": "pending"}

# 3. Check compilation status
curl http://localhost:9090/api/v1/jobs/\{job_id\}

# Wait until status is "ready"

# 4. Dispatch to sandbox
curl -X POST http://localhost:9090/api/v1/dispatch \
  -H "Content-Type: application/json" \
  -d '{
    "job_id": "\{job_id\}",
    "sandbox": {
      "image": "ubuntu:22.04",
      "timeout_secs": 3600,
      "memory_mb": 512
    }
  }'

# Response: {"job_id": "uuid", "status": "dispatched"}

# 5. Check execution status
curl http://localhost:9090/api/v1/jobs/\{job_id\}

# Wait until status is "completed" or "failed"

# 6. Get results
curl http://localhost:9090/api/v1/jobs/\{job_id\}/results
```

## Rate Limiting

**Not implemented.** Implement at the gateway layer if needed.

## CORS

**Not configured.** Implement at the gateway layer if needed.

## OpenAPI Specification

**Not generated.** Use this document as the API reference.

## Error Response Format

All errors return JSON:

```json
{
  "error": "descriptive error message"
}
```

## Timeout Behavior

- **Compile timeout**: Backend-dependent (Nuitka/PyInstaller)
- **Dispatch timeout**: Docker container timeout via `timeout_secs`
- **API timeout**: No global timeout on API requests

## Security Considerations

1. **No authentication** — Server **MUST** be deployed behind an authenticated gateway
2. **Project path validation** — Only projects inside `compile_dir` allowed
3. **Docker execution** — Runs with hardened flags but has network access
4. **No TLS** — **MUST** use reverse proxy for HTTPS
5. **No input sanitization** — **MUST** validate user-provided values at gateway layer

## References

- **REST API Design**: Fielding, R. (2000). "Architectural Styles and the Design of Network-based Software Architectures". Doctoral dissertation, University of California, Irvine.
- **HTTP Semantics**: RFC 9110 (2022). HTTP Semantics.