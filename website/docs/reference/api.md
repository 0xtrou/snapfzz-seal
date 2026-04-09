---
sidebar_position: 2
---

# API Reference

This document describes the **currently implemented** REST API for Snapfzz Seal orchestration server.

:::warning

This reflects the **actual implementation**. Endpoints documented elsewhere (like `/sign`, `/launch`, `/status/{id}`) do not exist.

:::

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

**Errors**:

| Status | Error |
|--------|-------|
| 400 | `project_dir must be inside compile_dir` |
| 400 | `invalid user_fingerprint: expected 64 hex chars` |
| 500 | Internal compilation error |

**Notes**:
- Compilation runs asynchronously
- Use `GET /api/v1/jobs/\{job_id\}` to check progress
- Project must be inside configured `compile_dir`

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

| Status | Error |
|--------|-------|
| 400 | `job not found` |
| 400 | `job is not ready for dispatch` (not in `ready` state) |
| 500 | Docker provisioning error |

**Notes**:
- Job must be in `ready` state (compile completed successfully)
- Docker image will be pulled if not present
- Execution runs asynchronously

---

### GET /api/v1/jobs/\{job_id\}

Get job status and details.

**Response**:

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "project_dir": "./my_agent",
  "output_path": "/path/to/artifact",
  "error": null,
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:32:00Z",
  "sandbox_id": "container-id-or-null",
  "result": {
    "exit_code": 0,
    "stdout": "Hello, World!",
    "stderr": ""
  }
}
```

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
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
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

**Errors**:

| Status | Error |
|--------|-------|
| 404 | `job not found` |
| 400 | Job not yet completed |

---

### GET /health

Health check endpoint.

**Response**:

```json
{
  "status": "ok"
}
```

## NOT Implemented Endpoints

The following endpoints are **documented elsewhere but do NOT exist**:

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

1. **No authentication** — Must be deployed behind auth gateway
2. **Project path validation** — Only projects inside `compile_dir` allowed
3. **Docker execution** — Runs with hardened flags but has network access
4. **No TLS** — Use reverse proxy for HTTPS
5. **No input sanitization** — Be careful with user-provided values