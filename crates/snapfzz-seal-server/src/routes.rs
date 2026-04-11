use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::json;
use snapfzz_seal_compiler::{Cli as CompilerCli, CliBackend};
use tracing::debug;

use crate::sandbox::{SandboxConfig, copy_into_sandbox, exec_in_sandbox};
use crate::state::{JobState, ServerState};

static NEXT_JOB_SEQ: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Deserialize)]
pub struct CompileRequest {
    pub project_dir: String,
    pub user_fingerprint: String,
    pub sandbox_fingerprint: String,
}

/// Validate that a user-supplied project_dir is within the allowed compile directory.
fn validate_project_dir(
    project_dir: &str,
    compile_dir: &std::path::Path,
) -> Result<std::path::PathBuf, (axum::http::StatusCode, String)> {
    let path = std::path::PathBuf::from(project_dir);

    let canonical = path.canonicalize().map_err(|e| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            format!("project_dir does not exist or cannot be resolved: {e}"),
        )
    })?;

    let base = compile_dir.canonicalize().map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("compile_dir does not exist or cannot be resolved: {e}"),
        )
    })?;

    if !canonical.starts_with(&base) {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            format!(
                "project_dir must be within the configured compile directory ({})",
                base.display()
            ),
        ));
    }

    Ok(canonical)
}

#[derive(Debug, Serialize)]
pub struct CompileResponse {
    pub job_id: String,
    pub status: JobState,
}

#[derive(Debug, Deserialize)]
pub struct DispatchRequest {
    pub job_id: String,
    pub sandbox: DispatchSandbox,
}

#[derive(Debug, Deserialize)]
pub struct DispatchSandbox {
    pub image: String,
    pub timeout_secs: u64,
    pub memory_mb: Option<u64>,
    pub env: Option<Vec<(String, String)>>,
}

#[derive(Debug, Serialize)]
pub struct JobResultResponse {
    pub job_id: String,
    pub status: JobState,
    pub result: Option<snapfzz_seal_core::types::ExecutionResult>,
}

pub fn build_router(state: ServerState) -> Router {
    Router::new()
        .route("/api/v1/compile", post(compile))
        .route("/api/v1/dispatch", post(dispatch))
        .route("/api/v1/jobs/{job_id}", get(get_job))
        .route("/api/v1/jobs/{job_id}/results", get(get_results))
        .route("/health", get(health))
        .with_state(state)
}

async fn compile(
    State(state): State<ServerState>,
    Json(req): Json<CompileRequest>,
) -> impl IntoResponse {
    let job_id = new_job_id();
    let validated_project_dir = match validate_project_dir(&req.project_dir, &state.compile_dir) {
        Ok(p) => p,
        Err((status, msg)) => return (status, msg).into_response(),
    };
    let created = state
        .create_job(
            job_id.clone(),
            Some(validated_project_dir.to_string_lossy().to_string()),
        )
        .await;

    let state_for_task = state.clone();
    let compile_output_dir = state.compile_dir.join(&job_id);
    let output_path = state.output_dir.join(format!("{job_id}.sealed"));
    let compile_options = compiler_options_from_request(
        validated_project_dir,
        req.user_fingerprint,
        req.sandbox_fingerprint,
        compile_output_dir.clone(),
        output_path,
    );
    let job_id_for_task = job_id.clone();

    tokio::spawn(async move {
        let _: Result<_, std::convert::Infallible> = state_for_task
            .update_job::<std::convert::Infallible>(&job_id_for_task, |job| {
                job.status = JobState::Compiling;
                job.error = None;
                Ok(())
            })
            .await;

        if let Err(err) = tokio::fs::create_dir_all(&compile_output_dir).await {
            let _: Result<_, std::convert::Infallible> = state_for_task
                .update_job(&job_id_for_task, |job| {
                    job.status = JobState::Failed;
                    job.error = Some(format!("failed to create compile directory: {err}"));
                    Ok(())
                })
                .await;
            return;
        }

        if let Err(err) = tokio::fs::create_dir_all(&state_for_task.output_dir).await {
            let _: Result<_, std::convert::Infallible> = state_for_task
                .update_job(&job_id_for_task, |job| {
                    job.status = JobState::Failed;
                    job.error = Some(format!("failed to create output directory: {err}"));
                    Ok(())
                })
                .await;
            return;
        }

        let output_path_str = compile_options.cli.output.to_string_lossy().to_string();
        let fingerprint_mode = compile_options.fingerprint_mode;
        let compile_result = tokio::task::spawn_blocking(move || {
            debug!(?fingerprint_mode, "resolved compile fingerprint mode");
            snapfzz_seal_compiler::run(compile_options.cli)
        })
        .await;

        match compile_result {
            Ok(Ok(())) => {
                let _: Result<_, std::convert::Infallible> = state_for_task
                    .update_job(&job_id_for_task, |job| {
                        job.status = JobState::Ready;
                        job.output_path = Some(output_path_str);
                        job.error = None;
                        Ok(())
                    })
                    .await;
            }
            Ok(Err(err)) => {
                let _: Result<_, std::convert::Infallible> = state_for_task
                    .update_job(&job_id_for_task, |job| {
                        job.status = JobState::Failed;
                        job.error = Some(err.to_string());
                        Ok(())
                    })
                    .await;
            }
            Err(join_err) => {
                let _: Result<_, std::convert::Infallible> = state_for_task
                    .update_job(&job_id_for_task, |job| {
                        job.status = JobState::Failed;
                        job.error = Some(format!("compile task join failure: {join_err}"));
                        Ok(())
                    })
                    .await;
            }
        }
    });

    (
        StatusCode::ACCEPTED,
        Json(CompileResponse {
            job_id,
            status: created.status,
        }),
    )
        .into_response()
}

async fn get_job(
    State(state): State<ServerState>,
    Path(job_id): Path<String>,
) -> Result<Json<crate::state::JobStatus>, Response> {
    match state.get_job(&job_id).await {
        Some(job) => Ok(Json(job)),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error":"job not found"})),
        )
            .into_response()),
    }
}

async fn dispatch(
    State(state): State<ServerState>,
    Json(req): Json<DispatchRequest>,
) -> Result<(StatusCode, Json<CompileResponse>), Response> {
    let Some(job) = state.get_job(&req.job_id).await else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error":"job not found"})),
        )
            .into_response());
    };

    if job.status != JobState::Ready {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"job is not ready for dispatch"})),
        )
            .into_response());
    }

    let sandbox_cfg = SandboxConfig {
        image: req.sandbox.image,
        env: req.sandbox.env.unwrap_or_default(),
        memory_mb: req.sandbox.memory_mb,
        timeout_secs: req.sandbox.timeout_secs,
    };

    let job_id = req.job_id;
    let job_id_for_task = job_id.clone();
    let state_for_task = state.clone();

    let _: Result<(), std::convert::Infallible> = state
        .update_job(&job_id, |job| {
            job.status = JobState::Dispatched;
            job.error = None;
            Ok(())
        })
        .await;

    tokio::spawn(async move {
        let provisioner = state_for_task.sandbox_backend.clone();
        let Some(job_snapshot) = state_for_task.get_job(&job_id_for_task).await else {
            return;
        };
        let Some(output_path) = job_snapshot.output_path else {
            let _: Result<_, std::convert::Infallible> = state_for_task
                .update_job::<std::convert::Infallible>(&job_id_for_task, |job| {
                    job.status = JobState::Failed;
                    job.error = Some("job has no output artifact".to_string());
                    Ok(())
                })
                .await;
            return;
        };

        let sandbox = match provisioner.provision(&sandbox_cfg).await {
            Ok(handle) => handle,
            Err(err) => {
                let _: Result<_, std::convert::Infallible> = state_for_task
                    .update_job(&job_id_for_task, |job| {
                        job.status = JobState::Failed;
                        job.error = Some(format!("sandbox provision failed: {err}"));
                        Ok(())
                    })
                    .await;
                return;
            }
        };

        let _: Result<_, std::convert::Infallible> = state_for_task
            .update_job(&job_id_for_task, |job| {
                job.status = JobState::Running;
                job.sandbox_id = Some(sandbox.id.clone());
                Ok(())
            })
            .await;

        let binary_path = PathBuf::from(&output_path);
        let copy_res = copy_into_sandbox(
            provisioner.as_ref(),
            &sandbox,
            &binary_path,
            "/tmp/snapfzz-sealed",
        )
        .await;

        if let Err(err) = copy_res {
            let _ = provisioner.destroy(&sandbox).await;
            let _: Result<_, std::convert::Infallible> = state_for_task
                .update_job(&job_id_for_task, |job| {
                    job.status = JobState::Failed;
                    job.error = Some(format!("sandbox copy failed: {err}"));
                    Ok(())
                })
                .await;
            return;
        }

        let exec_result = exec_in_sandbox(
            provisioner.as_ref(),
            &sandbox,
            "chmod +x /tmp/snapfzz-sealed && /tmp/snapfzz-sealed",
            sandbox_cfg.timeout_secs,
        )
        .await;
        let destroy_result = provisioner.destroy(&sandbox).await;

        match (exec_result, destroy_result) {
            (Ok(result), Ok(())) => {
                let _: Result<_, std::convert::Infallible> = state_for_task
                    .update_job(&job_id_for_task, |job| {
                        job.status = JobState::Completed;
                        job.result = Some(result);
                        job.error = None;
                        Ok(())
                    })
                    .await;
            }
            (Ok(result), Err(err)) => {
                let _: Result<_, std::convert::Infallible> = state_for_task
                    .update_job(&job_id_for_task, |job| {
                        job.status = JobState::Completed;
                        job.result = Some(result);
                        job.error = Some(format!("sandbox destroy failed: {err}"));
                        Ok(())
                    })
                    .await;
            }
            (Err(err), _) => {
                let _: Result<_, std::convert::Infallible> = state_for_task
                    .update_job(&job_id_for_task, |job| {
                        job.status = JobState::Failed;
                        job.error = Some(format!("sandbox exec failed: {err}"));
                        Ok(())
                    })
                    .await;
            }
        }
    });

    Ok((
        StatusCode::ACCEPTED,
        Json(CompileResponse {
            job_id,
            status: JobState::Dispatched,
        }),
    ))
}

async fn get_results(
    State(state): State<ServerState>,
    Path(job_id): Path<String>,
) -> Result<Json<JobResultResponse>, Response> {
    match state.get_job(&job_id).await {
        Some(job) => Ok(Json(JobResultResponse {
            job_id: job.id,
            status: job.status,
            result: job.result,
        })),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error":"job not found"})),
        )
            .into_response()),
    }
}

async fn health(State(state): State<ServerState>) -> impl IntoResponse {
    let jobs_count = state.jobs.read().await.len();
    (
        StatusCode::OK,
        Json(json!({"status":"ok","jobs_count":jobs_count})),
    )
}

fn random_hex_4() -> String {
    let mut bytes = [0_u8; 4];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn new_job_id() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs();
    let seq = NEXT_JOB_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("job-{now}-{seq}-{}", random_hex_4())
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum FingerprintMode {
    Stable,
    Session,
}

#[derive(Debug)]
struct CompileOptions {
    cli: CompilerCli,
    fingerprint_mode: FingerprintMode,
}

fn compiler_options_from_request(
    project_dir: PathBuf,
    user_fingerprint: String,
    sandbox_fingerprint: String,
    compile_output_dir: PathBuf,
    output_path: PathBuf,
) -> CompileOptions {
    let fingerprint_mode = match sandbox_fingerprint.as_str() {
        "ephemeral" => FingerprintMode::Session,
        _ => FingerprintMode::Stable,
    };

    CompileOptions {
        cli: CompilerCli {
            project: project_dir,
            user_fingerprint,
            sandbox_fingerprint,
            output: output_path,
            backend: CliBackend::Nuitka,
            mode: snapfzz_seal_compiler::CliMode::Batch,
            launcher: Some(compile_output_dir.join("snapfzz-seal-launcher")),
        },
        fingerprint_mode,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        fs,
        os::unix::fs::PermissionsExt,
        path::PathBuf,
        process::Command as StdCommand,
        time::{SystemTime, UNIX_EPOCH},
    };

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use serde_json::Value;
    use snapfzz_seal_core::types::ExecutionResult;
    use tower::ServiceExt;

    use crate::{
        create_app,
        state::{JobState, ServerState},
    };

    use super::{
        FingerprintMode, build_router, compiler_options_from_request, new_job_id, random_hex_4,
    };

    fn unique_temp_path(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
    }

    fn test_state() -> ServerState {
        let root = unique_temp_path("snapfzz-seal-server-tests");
        let compile_dir = root.join("compile");
        let output_dir = root.join("output");
        fs::create_dir_all(&compile_dir).expect("compile dir should be created");
        fs::create_dir_all(&output_dir).expect("output dir should be created");
        ServerState::new(compile_dir, output_dir)
    }

    fn create_project_under_compile_dir(state: &ServerState, name: &str) -> String {
        let project_dir = state.compile_dir.join(name);
        fs::create_dir_all(&project_dir).expect("project dir should be created");
        project_dir.to_string_lossy().to_string()
    }

    fn write_executable_script(path: &PathBuf, body: &str) {
        fs::write(path, body).expect("script should be written");
        let mut permissions = fs::metadata(path)
            .expect("script metadata should exist")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).expect("script should be executable");
    }

    fn run_dispatch_probe(mode: &str, envs: &[(&str, &str)]) -> std::process::Output {
        let mut cmd = StdCommand::new(std::env::current_exe().expect("test binary path"));
        cmd.arg("dispatch_subprocess_probe")
            .arg("--nocapture")
            .env("SNAPFZZ_SEAL_ROUTE_TEST_MODE", mode);
        for (key, value) in envs {
            cmd.env(key, value);
        }
        cmd.output().expect("subprocess should run")
    }

    fn assert_probe_success(output: std::process::Output) {
        assert!(
            output.status.success(),
            "probe failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    async fn response_json(response: axum::response::Response) -> Value {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response bytes should be readable");
        serde_json::from_slice(&body).expect("response must be json")
    }

    async fn wait_for_status(state: &ServerState, job_id: &str, expected: JobState) {
        for _ in 0..240 {
            #[allow(clippy::collapsible_if)]
            if let Some(job) = state.get_job(job_id).await {
                if job.status == expected {
                    return;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        panic!("job did not reach expected status");
    }

    #[test]
    fn compile_request_with_ephemeral_sandbox_uses_session_mode() {
        let project_dir = PathBuf::from("/tmp/project");
        let options = compiler_options_from_request(
            project_dir,
            "11".repeat(32),
            "ephemeral".to_string(),
            PathBuf::from("/tmp/project"),
            PathBuf::from("/tmp/output.bin"),
        );

        assert_eq!(options.fingerprint_mode, FingerprintMode::Session);
    }

    #[test]
    fn compile_request_with_auto_sandbox_uses_stable_mode() {
        let project_dir = PathBuf::from("/tmp/project");
        let options = compiler_options_from_request(
            project_dir,
            "11".repeat(32),
            "auto".to_string(),
            PathBuf::from("/tmp/project"),
            PathBuf::from("/tmp/output.bin"),
        );

        assert_eq!(options.fingerprint_mode, FingerprintMode::Stable);
    }

    #[test]
    fn compile_request_passes_explicit_user_fingerprint_to_compiler() {
        let project_dir = PathBuf::from("/tmp/project");
        let options = compiler_options_from_request(
            project_dir,
            "ab".repeat(32),
            "auto".to_string(),
            PathBuf::from("/tmp/project"),
            PathBuf::from("/tmp/output.bin"),
        );

        assert_eq!(options.cli.user_fingerprint, "ab".repeat(32));
    }

    #[tokio::test]
    async fn dispatch_subprocess_probe() {
        let Ok(mode) = std::env::var("SNAPFZZ_SEAL_ROUTE_TEST_MODE") else {
            return;
        };

        match mode.as_str() {
            "copy_failure" => {
                let binary_path = std::env::var("SNAPFZZ_SEAL_TEST_BINARY_PATH")
                    .expect("binary path should be set");
                let state = test_state();
                let job = state
                    .create_job("probe-copy-failure".to_string(), None)
                    .await;
                let _: Result<(), Infallible> = state
                    .update_job(&job.id, |job| {
                        job.status = JobState::Ready;
                        job.output_path = Some(binary_path.clone());
                        Ok(())
                    })
                    .await;
                let app = create_app(state.clone());

                let response = app
                    .oneshot(
                        Request::builder()
                            .method("POST")
                            .uri("/api/v1/dispatch")
                            .header("content-type", "application/json")
                            .body(Body::from(format!(
                                "{{\"job_id\":\"{}\",\"sandbox\":{{\"image\":\"python:3.11\",\"timeout_secs\":30}}}}",
                                job.id
                            )))
                            .expect("request must be valid"),
                    )
                    .await
                    .expect("dispatch should complete");

                assert_eq!(response.status(), StatusCode::ACCEPTED);
                wait_for_status(&state, &job.id, JobState::Failed).await;
                let updated = state.get_job(&job.id).await.expect("job should exist");
                assert!(
                    updated
                        .error
                        .as_deref()
                        .expect("job should include error")
                        .contains("sandbox copy failed")
                );
                assert!(
                    updated
                        .sandbox_id
                        .as_deref()
                        .is_some_and(|id| id.starts_with("sbx-"))
                );
            }
            "exec_failure" => {
                let binary_path = std::env::var("SNAPFZZ_SEAL_TEST_BINARY_PATH")
                    .expect("binary path should be set");
                let state = test_state();
                let job = state
                    .create_job("probe-exec-failure".to_string(), None)
                    .await;
                let _: Result<(), Infallible> = state
                    .update_job(&job.id, |job| {
                        job.status = JobState::Ready;
                        job.output_path = Some(binary_path.clone());
                        Ok(())
                    })
                    .await;
                let app = create_app(state.clone());

                let response = app
                    .oneshot(
                        Request::builder()
                            .method("POST")
                            .uri("/api/v1/dispatch")
                            .header("content-type", "application/json")
                            .body(Body::from(format!(
                                "{{\"job_id\":\"{}\",\"sandbox\":{{\"image\":\"python:3.11\",\"timeout_secs\":30}}}}",
                                job.id
                            )))
                            .expect("request must be valid"),
                    )
                    .await
                    .expect("dispatch should complete");

                assert_eq!(response.status(), StatusCode::ACCEPTED);
                wait_for_status(&state, &job.id, JobState::Failed).await;
                let updated = state.get_job(&job.id).await.expect("job should exist");
                assert!(
                    updated
                        .error
                        .as_deref()
                        .expect("job should include error")
                        .contains("sandbox exec failed")
                );
                assert!(
                    updated
                        .sandbox_id
                        .as_deref()
                        .is_some_and(|id| id.starts_with("sbx-"))
                );
            }
            "destroy_error" => {
                let binary_path = std::env::var("SNAPFZZ_SEAL_TEST_BINARY_PATH")
                    .expect("binary path should be set");
                let state = test_state();
                let job = state
                    .create_job("probe-destroy-error".to_string(), None)
                    .await;
                let _: Result<(), Infallible> = state
                    .update_job(&job.id, |job| {
                        job.status = JobState::Ready;
                        job.output_path = Some(binary_path.clone());
                        Ok(())
                    })
                    .await;
                let app = create_app(state.clone());

                let response = app
                    .oneshot(
                        Request::builder()
                            .method("POST")
                            .uri("/api/v1/dispatch")
                            .header("content-type", "application/json")
                            .body(Body::from(format!(
                                "{{\"job_id\":\"{}\",\"sandbox\":{{\"image\":\"python:3.11\",\"timeout_secs\":30}}}}",
                                job.id
                            )))
                            .expect("request must be valid"),
                    )
                    .await
                    .expect("dispatch should complete");

                assert_eq!(response.status(), StatusCode::ACCEPTED);
                wait_for_status(&state, &job.id, JobState::Completed).await;
                let updated = state.get_job(&job.id).await.expect("job should exist");
                assert_eq!(updated.result.as_ref().map(|r| r.exit_code), Some(0));
                assert!(
                    updated
                        .error
                        .as_deref()
                        .expect("job should include error")
                        .contains("sandbox destroy failed")
                );
                assert!(
                    updated
                        .sandbox_id
                        .as_deref()
                        .is_some_and(|id| id.starts_with("sbx-"))
                );
            }
            other => panic!("unknown probe mode: {other}"),
        }
    }

    #[tokio::test]
    async fn compile_returns_accepted_with_job_id() {
        let state = test_state();
        let project_dir = create_project_under_compile_dir(&state, "demo-agent");
        let app = create_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/compile")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        "{{\"project_dir\":\"{}\",\"user_fingerprint\":\"abcd\",\"sandbox_fingerprint\":\"auto\"}}",
                        project_dir
                    )))
                    .expect("request must be valid"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let payload = response_json(response).await;
        assert!(payload["job_id"].as_str().is_some());
        assert_eq!(payload["status"], "pending");
    }

    #[tokio::test]
    async fn get_job_returns_job_status() {
        let state = test_state();
        let project_dir = create_project_under_compile_dir(&state, "demo-agent-job-status");
        let app = create_app(state);

        let create_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/compile")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        "{{\"project_dir\":\"{}\",\"user_fingerprint\":\"abcd\",\"sandbox_fingerprint\":\"auto\"}}",
                        project_dir
                    )))
                    .expect("request must be valid"),
            )
            .await
            .expect("compile request should complete");
        let created = response_json(create_response).await;
        let job_id = created["job_id"]
            .as_str()
            .expect("job id string")
            .to_string();

        let get_response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/jobs/{job_id}"))
                    .body(Body::empty())
                    .expect("request must be valid"),
            )
            .await
            .expect("get request should complete");

        assert_eq!(get_response.status(), StatusCode::OK);
        let payload = response_json(get_response).await;
        assert_eq!(payload["id"], job_id);
    }

    #[tokio::test]
    async fn get_job_returns_404_for_missing_id() {
        let app = create_app(test_state());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/jobs/missing")
                    .body(Body::empty())
                    .expect("request must be valid"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn dispatch_non_ready_job_returns_bad_request() {
        let state = test_state();
        let project_dir = create_project_under_compile_dir(&state, "demo-agent-dispatch-non-ready");
        let app = create_app(state);

        let create_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/compile")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        "{{\"project_dir\":\"{}\",\"user_fingerprint\":\"abcd\",\"sandbox_fingerprint\":\"auto\"}}",
                        project_dir
                    )))
                    .expect("request must be valid"),
            )
            .await
            .expect("compile request should complete");
        let created = response_json(create_response).await;
        let job_id = created["job_id"].as_str().expect("job id string");

        let dispatch_response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/dispatch")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        "{{\"job_id\":\"{job_id}\",\"sandbox\":{{\"image\":\"python:3.11\",\"timeout_secs\":300}}}}"
                    )))
                    .expect("request must be valid"),
            )
            .await
            .expect("dispatch request should complete");

        assert_eq!(dispatch_response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn build_router_returns_router() {
        let _router = build_router(test_state());
    }

    #[test]
    fn random_hex_4_returns_eight_hex_chars() {
        let hex = random_hex_4();
        assert_eq!(hex.len(), 8);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn new_job_id_has_expected_prefix_and_is_unique() {
        let first = new_job_id();
        let second = new_job_id();

        assert!(first.starts_with("job-"));
        assert!(second.starts_with("job-"));
        assert_ne!(first, second);
    }

    #[tokio::test]
    async fn dispatch_missing_job_returns_404() {
        let app = create_app(test_state());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/dispatch")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"job_id":"missing","sandbox":{"image":"python:3.11","timeout_secs":30}}"#,
                    ))
                    .expect("request must be valid"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn dispatch_ready_job_without_output_path_transitions_to_failed() {
        let state = test_state();
        let job = state
            .create_job("job-ready-no-output".to_string(), None)
            .await;
        let _: Result<(), Infallible> = state
            .update_job(&job.id, |job| {
                job.status = JobState::Ready;
                job.output_path = None;
                Ok(())
            })
            .await;
        let app = create_app(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/dispatch")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        "{{\"job_id\":\"{}\",\"sandbox\":{{\"image\":\"python:3.11\",\"timeout_secs\":30}}}}",
                        job.id
                    )))
                    .expect("request must be valid"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::ACCEPTED);

        wait_for_status(&state, &job.id, JobState::Failed).await;
        let updated = state
            .get_job(&job.id)
            .await
            .expect("job should still exist");
        assert_eq!(updated.error.as_deref(), Some("job has no output artifact"));
    }

    #[tokio::test]
    async fn dispatch_ready_job_with_invalid_sandbox_config_fails() {
        let state = test_state();
        let job = state
            .create_job("job-ready-invalid-sandbox".to_string(), None)
            .await;
        let _: Result<(), Infallible> = state
            .update_job(&job.id, |job| {
                job.status = JobState::Ready;
                job.output_path = Some("/tmp/irrelevant".to_string());
                Ok(())
            })
            .await;
        let app = create_app(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/dispatch")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        "{{\"job_id\":\"{}\",\"sandbox\":{{\"image\":\"invalid image\",\"timeout_secs\":30}}}}",
                        job.id
                    )))
                    .expect("request must be valid"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::ACCEPTED);

        wait_for_status(&state, &job.id, JobState::Failed).await;
        let updated = state
            .get_job(&job.id)
            .await
            .expect("job should still exist");
        assert!(
            updated
                .error
                .as_deref()
                .expect("job should include error")
                .contains("sandbox provision failed")
        );
    }

    #[tokio::test]
    async fn dispatch_ready_job_copy_failure_marks_failed() {
        let root = unique_temp_path("snapfzz-seal-route-copy-failure");
        fs::create_dir_all(&root).expect("root dir should exist");
        let docker_script = root.join("docker-copy-fail.sh");
        write_executable_script(
            &docker_script,
            r##"#!/bin/sh
set -eu
cmd="$1"
shift || true
case "$cmd" in
  run)
    printf 'container-copy-fail\n'
    ;;
  cp)
    printf 'copy failed\n' >&2
    exit 7
    ;;
  rm)
    exit 0
    ;;
  *)
    printf 'unexpected command: %s\n' "$cmd" >&2
    exit 9
    ;;
esac
"##,
        );
        let binary_path = root.join("agent-bin");
        fs::write(&binary_path, b"binary").expect("binary fixture should be written");

        let docker_bin = docker_script.to_string_lossy().to_string();
        let binary = binary_path.to_string_lossy().to_string();
        let output = run_dispatch_probe(
            "copy_failure",
            &[
                ("DOCKER_BIN", docker_bin.as_str()),
                ("SNAPFZZ_SEAL_TEST_BINARY_PATH", binary.as_str()),
            ],
        );

        assert_probe_success(output);
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn dispatch_ready_job_exec_failure_marks_failed() {
        let root = unique_temp_path("snapfzz-seal-route-exec-failure");
        fs::create_dir_all(&root).expect("root dir should exist");
        let docker_script = root.join("docker-exec-fail.sh");
        write_executable_script(
            &docker_script,
            r##"#!/bin/sh
set -eu
cmd="$1"
shift || true
case "$cmd" in
  run)
    printf 'container-exec-fail\n'
    ;;
  cp)
    rm -- "$0"
    exit 0
    ;;
  exec)
    printf 'boom\n' >&2
    exit 23
    ;;
  rm)
    exit 0
    ;;
  *)
    printf 'unexpected command: %s\n' "$cmd" >&2
    exit 9
    ;;
esac
"##,
        );
        let binary_path = root.join("agent-bin");
        fs::write(&binary_path, b"binary").expect("binary fixture should be written");

        let docker_bin = docker_script.to_string_lossy().to_string();
        let binary = binary_path.to_string_lossy().to_string();
        let output = run_dispatch_probe(
            "exec_failure",
            &[
                ("DOCKER_BIN", docker_bin.as_str()),
                ("SNAPFZZ_SEAL_TEST_BINARY_PATH", binary.as_str()),
            ],
        );

        assert_probe_success(output);
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn dispatch_ready_job_destroy_error_keeps_completed_result() {
        let root = unique_temp_path("snapfzz-seal-route-destroy-error");
        fs::create_dir_all(&root).expect("root dir should exist");
        let docker_script = root.join("docker-destroy-error.sh");
        write_executable_script(
            &docker_script,
            r##"#!/bin/sh
set -eu
cmd="$1"
shift || true
case "$cmd" in
  run)
    printf 'container-destroy-error\n'
    ;;
  cp)
    exit 0
    ;;
  exec)
    printf 'probe-stdout\n'
    exit 0
    ;;
  rm)
    printf 'destroy failed\n' >&2
    exit 13
    ;;
  *)
    printf 'unexpected command: %s\n' "$cmd" >&2
    exit 9
    ;;
esac
"##,
        );
        let binary_path = root.join("agent-bin");
        fs::write(&binary_path, b"binary").expect("binary fixture should be written");

        let docker_bin = docker_script.to_string_lossy().to_string();
        let binary = binary_path.to_string_lossy().to_string();
        let output = run_dispatch_probe(
            "destroy_error",
            &[
                ("DOCKER_BIN", docker_bin.as_str()),
                ("SNAPFZZ_SEAL_TEST_BINARY_PATH", binary.as_str()),
            ],
        );

        assert_probe_success(output);
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn get_results_returns_404_for_missing_job() {
        let app = create_app(test_state());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/jobs/missing/results")
                    .body(Body::empty())
                    .expect("request must be valid"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_results_returns_result_payload_when_job_completed() {
        let state = test_state();
        let job = state.create_job("job-with-result".to_string(), None).await;
        let _: Result<(), Infallible> = state
            .update_job(&job.id, |job| {
                job.status = JobState::Completed;
                job.result = Some(ExecutionResult {
                    exit_code: 0,
                    stdout: "ok".to_string(),
                    stderr: String::new(),
                });
                Ok(())
            })
            .await;
        let app = create_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/jobs/{}/results", job.id))
                    .body(Body::empty())
                    .expect("request must be valid"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        let payload = response_json(response).await;
        assert_eq!(payload["job_id"], "job-with-result");
        assert_eq!(payload["status"], "completed");
        assert_eq!(payload["result"]["exit_code"], 0);
        assert_eq!(payload["result"]["stdout"], "ok");
    }

    #[tokio::test]
    async fn get_results_returns_null_result_when_job_has_none() {
        let state = test_state();
        let job = state.create_job("job-no-result".to_string(), None).await;
        let _: Result<(), Infallible> = state
            .update_job(&job.id, |job| {
                job.status = JobState::Ready;
                Ok(())
            })
            .await;
        let app = create_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/jobs/{}/results", job.id))
                    .body(Body::empty())
                    .expect("request must be valid"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        let payload = response_json(response).await;
        assert_eq!(payload["job_id"], "job-no-result");
        assert_eq!(payload["status"], "ready");
        assert_eq!(payload["result"], serde_json::Value::Null);
    }

    #[tokio::test]
    async fn health_returns_ok_with_jobs_count() {
        let app = create_app(test_state());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("request must be valid"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        let payload = response_json(response).await;
        assert_eq!(payload["status"], "ok");
        assert!(payload["jobs_count"].as_u64().is_some());
    }

    #[tokio::test]
    async fn compile_invalid_json_returns_400() {
        let app = create_app(test_state());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/compile")
                    .header("content-type", "application/json")
                    .body(Body::from("not-json"))
                    .expect("request must be valid"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn dispatch_invalid_json_returns_422() {
        let app = create_app(test_state());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/dispatch")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .expect("request must be valid"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn compile_missing_project_transitions_job_to_failed() {
        let state = test_state();
        let app = create_app(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/compile")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"project_dir":"/definitely/missing/project","user_fingerprint":"abcd","sandbox_fingerprint":"auto"}"#,
                    ))
                    .expect("request must be valid"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn compile_fails_when_compile_output_directory_cannot_be_created() {
        let root = std::env::temp_dir().join(format!(
            "snapfzz-seal-routes-compile-dir-file-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("root dir should be created");

        let compile_dir = root.join("compile-as-file");
        std::fs::write(&compile_dir, b"not-a-dir").expect("compile file should exist");
        let output_dir = root.join("output");

        let state = ServerState::new(compile_dir, output_dir);
        let app = create_app(state.clone());

        let project_dir = root.join("project");
        std::fs::create_dir_all(&project_dir).expect("project dir should be created");
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/compile")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        "{{\"project_dir\":\"{}\",\"user_fingerprint\":\"abcd\",\"sandbox_fingerprint\":\"auto\"}}",
                        project_dir.to_string_lossy()
                    )))
                    .expect("request must be valid"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let _ = std::fs::remove_dir_all(root);
    }
}

#[cfg(test)]
mod path_validation_tests {
    use super::validate_project_dir;
    use axum::http::StatusCode;

    #[test]
    fn rejects_nonexistent_path() {
        let tmp = std::env::temp_dir().join("snapfzz-seal-pv-reject");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let result = validate_project_dir("/nonexistent/path/12345", &tmp);
        assert_eq!(result.unwrap_err().0, StatusCode::BAD_REQUEST);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn accepts_path_within_base() {
        let tmp = std::env::temp_dir().join("snapfzz-seal-pv-accept");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let inner = tmp.join("project");
        std::fs::create_dir_all(&inner).unwrap();
        let result = validate_project_dir(inner.to_str().unwrap(), &tmp);
        assert!(result.is_ok());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rejects_symlink_pointing_outside_base() {
        let tmp = std::env::temp_dir().join("snapfzz-seal-pv-symlink");
        let outside = std::env::temp_dir().join("snapfzz-seal-pv-outside");
        let _ = std::fs::remove_dir_all(&tmp);
        let _ = std::fs::remove_dir_all(&outside);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret.txt"), b"secret").unwrap();
        #[cfg(target_os = "linux")]
        std::os::unix::fs::symlink(&outside, tmp.join("escape")).unwrap();
        #[cfg(target_os = "linux")]
        {
            let symlink_path = tmp.join("escape");
            let result = validate_project_dir(symlink_path.to_str().unwrap(), &tmp);
            assert_eq!(result.unwrap_err().0, StatusCode::BAD_REQUEST);
        }
        let _ = std::fs::remove_dir_all(&tmp);
        let _ = std::fs::remove_dir_all(&outside);
    }
}
