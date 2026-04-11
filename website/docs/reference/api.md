---
sidebar_position: 2
---

# API Reference

This document describes the HTTP API exposed by the Snapfzz Seal orchestration server. Routes are registered in `crates/snapfzz-seal-server/src/routes.rs`.

## Base URL

| Binary | Default bind address |
|--------|---------------------|
| `seal server` (CLI wrapper) | `http://0.0.0.0:9090` |
| `snapfzz-seal-server` (standalone) | `http://127.0.0.1:9090` |

## Authentication

**None.** The server has no built-in authentication or authorization.

:::danger

Deploy the server behind an authenticated reverse proxy or API gateway. Do not expose it directly to untrusted networks.

:::

---

## Endpoints

### POST /api/v1/compile

Compile and seal an agent from source. Returns immediately with a job identifier; compilation runs asynchronously.

**Request body** (`application/json`):

```json
{
  "project_dir": "./my_agent",
  "user_fingerprint": "64-hex-string",
  "sandbox_fingerprint": "auto"
}
```

**Request fields**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `project_dir` | string | Yes | Path to the agent project directory. Must resolve to a path inside the server's configured `compile_dir`. |
| `user_fingerprint` | string | Yes | 64 hex characters (32 bytes) |
| `sandbox_fingerprint` | string | Yes | `auto` to fingerprint the current environment, or 64 hex characters to bind to a specific sandbox |

**Response** (202 Accepted):

```json
{
  "job_id": "job-1705312800-0-abc12345",
  "status": "pending"
}
```

**Synchronous validation errors** (400 Bad Request, JSON body):

| Condition | Error message |
|-----------|---------------|
| `project_dir` does not exist or cannot be resolved | `project_dir does not exist or cannot be resolved: <detail>` |
| `project_dir` is outside `compile_dir` | `project_dir must be within the configured compile directory (<path>)` |

All error responses use the format `{"error": "<message>"}`.

**Asynchronous failures** (job transitions to `failed` state):

- Backend tool (Nuitka, PyInstaller, or Go) not installed or not in `PATH`
- Compilation errors produced by the backend tool

Use `GET /api/v1/jobs/{job_id}` to poll job progress.

---

### POST /api/v1/dispatch

Dispatch a compiled and ready artifact to a Docker sandbox for execution.

**Request body** (`application/json`):

```json
{
  "job_id": "job-1705312800-0-abc12345",
  "sandbox": {
    "image": "ubuntu:22.04",
    "timeout_secs": 3600,
    "memory_mb": 512,
    "env": [["API_KEY", "secret"], ["DEBUG", "true"]]
  }
}
```

**Request fields**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `job_id` | string | Yes | Job ID returned from `POST /api/v1/compile` |
| `sandbox.image` | string | Yes | Docker image to run the artifact in |
| `sandbox.timeout_secs` | integer | Yes | Maximum execution time in seconds |
| `sandbox.memory_mb` | integer | No | Container memory limit in megabytes |
| `sandbox.env` | array | No | Environment variables as an array of `["KEY", "VALUE"]` pairs |

**Response** (202 Accepted):

```json
{
  "job_id": "job-1705312800-0-abc12345",
  "status": "dispatched"
}
```

**Errors**:

| HTTP Status | Condition | Response body |
|-------------|-----------|---------------|
| 404 | Job not found | `{"error": "job not found"}` |
| 400 | Job is not in `ready` state | `{"error": "job is not ready for dispatch"}` |

**Notes**:

- The job must be in the `ready` state (compilation completed successfully) before dispatch.
- The artifact is copied into the container at `/tmp/snapfzz-sealed` and executed.
- Sandbox provisioning and execution run asynchronously after the `202` response.
- If the sandbox destroy step fails after a successful execution the job is still marked `completed` but the error field records the destroy failure.

---

### GET /api/v1/jobs/&#123;job_id&#125;

Retrieve the current status and metadata for a job.

**Response** (200 OK):

```json
{
  "id": "job-1705312800-0-abc12345",
  "status": "completed",
  "project_dir": "/path/to/compile/dir/my_agent",
  "output_path": "/path/to/output/job-1705312800-0-abc12345.sealed",
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
| `id` | string | Job ID (format: `job-<unix-seconds>-<sequence>-<8-hex-chars>`) |
| `status` | string | Current job state (see Job states below) |
| `project_dir` | string or null | Resolved absolute path to the project directory |
| `output_path` | string or null | Absolute path to the compiled artifact; present once compilation succeeds |
| `error` | string or null | Error message; present on failure or partial failure |
| `created_at` | integer | Unix timestamp in seconds |
| `updated_at` | integer | Unix timestamp in seconds |
| `sandbox_id` | string or null | Docker container ID; present once execution begins |
| `result` | object or null | Execution result; present once execution completes |

**Job states**:

| State | Description |
|-------|-------------|
| `pending` | Job created, waiting for compilation to begin |
| `compiling` | Compilation in progress |
| `ready` | Compilation succeeded; artifact available for dispatch |
| `dispatched` | Submitted to the sandbox; not yet running |
| `running` | Executing inside the Docker container |
| `completed` | Execution finished |
| `failed` | Compilation or execution failed; see `error` field |

**Errors**:

| HTTP Status | Condition | Response body |
|-------------|-----------|---------------|
| 404 | Job not found | `{"error": "job not found"}` |

---

### GET /api/v1/jobs/&#123;job_id&#125;/results

Retrieve the execution result for a job. Returns the same job for any existing job ID regardless of state; `result` is `null` until execution completes.

**Response** (200 OK):

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

**Result fields**:

| Field | Type | Description |
|-------|------|-------------|
| `exit_code` | integer | Process exit code from the sealed agent |
| `stdout` | string | Captured standard output |
| `stderr` | string | Captured standard error |

**Errors**:

| HTTP Status | Condition | Response body |
|-------------|-----------|---------------|
| 404 | Job not found | `{"error": "job not found"}` |

---

### GET /health

Server health check.

**Response** (200 OK):

```json
{
  "status": "ok",
  "jobs_count": 5
}
```

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | Always `"ok"` when the server is running |
| `jobs_count` | integer | Number of jobs currently tracked in memory |

---

## Error response format

All error responses use JSON:

```json
{
  "error": "descriptive error message"
}
```

---

## Endpoints that do NOT exist

| Path | Note |
|------|------|
| `POST /compile` | Use `POST /api/v1/compile` |
| `POST /sign` | Not an API endpoint; use the `seal sign` CLI command |
| `POST /launch` | Use `POST /api/v1/dispatch` |
| `GET /status/{id}` | Use `GET /api/v1/jobs/{job_id}` |
| `GET /logs/{id}` | Not implemented; no log streaming endpoint exists |
| Any `/api/v1/logs` | Not implemented |

---

## Complete workflow example

```bash
# 1. Start the server
seal server --bind 127.0.0.1:9090

# 2. Compile an agent
JOB=$(curl -s -X POST http://localhost:9090/api/v1/compile \
  -H "Content-Type: application/json" \
  -d "{
    \"project_dir\": \"./examples/demo_agent\",
    \"user_fingerprint\": \"$(openssl rand -hex 32)\",
    \"sandbox_fingerprint\": \"auto\"
  }" | jq -r .job_id)

# 3. Poll until status is "ready"
curl -s http://localhost:9090/api/v1/jobs/$JOB | jq .status

# 4. Dispatch to sandbox
curl -s -X POST http://localhost:9090/api/v1/dispatch \
  -H "Content-Type: application/json" \
  -d "{
    \"job_id\": \"$JOB\",
    \"sandbox\": {
      \"image\": \"ubuntu:22.04\",
      \"timeout_secs\": 3600,
      \"memory_mb\": 512
    }
  }"

# 5. Poll until status is "completed" or "failed"
curl -s http://localhost:9090/api/v1/jobs/$JOB | jq .status

# 6. Retrieve results
curl -s http://localhost:9090/api/v1/jobs/$JOB/results | jq .
```

---

## Operational notes

- **Rate limiting**: Not implemented. Apply rate limiting at the gateway layer.
- **CORS**: Not configured. Apply CORS headers at the gateway layer.
- **TLS**: Not provided. Use a reverse proxy for HTTPS.
- **Persistence**: Job state is held in memory only. All jobs are lost on server restart.
- **OpenAPI specification**: Not generated. This document is the authoritative API reference.

---

## Security considerations

1. **No authentication** — The server must be deployed behind an authenticated gateway.
2. **Project path validation** — Only projects inside the configured `compile_dir` are accepted; requests with paths outside that boundary receive `400`.
3. **Docker execution** — The sealed artifact runs inside a Docker container. The container has network access unless restricted externally.
4. **No TLS** — Use a reverse proxy for HTTPS termination.

---

## References

- **HTTP Semantics**: RFC 9110 (2022).
- **REST**: Fielding, R. (2000). "Architectural Styles and the Design of Network-based Software Architectures". Doctoral dissertation, University of California, Irvine.
