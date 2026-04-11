use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::auth::ApiKey;
use crate::sandbox::{DockerBackend, SandboxBackend};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobStatus {
    pub id: String,
    pub status: JobState,
    pub project_dir: Option<String>,
    pub output_path: Option<String>,
    pub error: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
    pub sandbox_id: Option<String>,
    pub result: Option<snapfzz_seal_core::types::ExecutionResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Pending,
    Compiling,
    Ready,
    Dispatched,
    Running,
    Completed,
    Failed,
}

#[derive(Clone)]
pub struct ServerState {
    pub jobs: Arc<RwLock<HashMap<String, JobStatus>>>,
    pub compile_dir: PathBuf,
    pub output_dir: PathBuf,
    pub sandbox_backend: Arc<dyn SandboxBackend>,
    /// API key used by the Bearer auth middleware.  `None` = dev mode.
    pub api_key: ApiKey,
}

impl ServerState {
    /// Create a new state with no API key (dev mode).  Use
    /// [`ServerState::with_api_key`] or set `api_key` directly to enable auth.
    pub fn new(compile_dir: PathBuf, output_dir: PathBuf) -> Self {
        Self {
            jobs: Arc::new(RwLock::new(HashMap::new())),
            compile_dir,
            output_dir,
            sandbox_backend: Arc::new(DockerBackend::new()),
            api_key: None,
        }
    }

    /// Create state with an explicit API key.
    pub fn with_api_key(mut self, api_key: ApiKey) -> Self {
        self.api_key = api_key;
        self
    }

    pub async fn get_job(&self, id: &str) -> Option<JobStatus> {
        self.jobs.read().await.get(id).cloned()
    }

    pub async fn create_job(&self, id: String, project_dir: Option<String>) -> JobStatus {
        let now = unix_ts_secs();
        let job = JobStatus {
            id: id.clone(),
            status: JobState::Pending,
            project_dir,
            output_path: None,
            error: None,
            created_at: now,
            updated_at: now,
            sandbox_id: None,
            result: None,
        };

        self.jobs.write().await.insert(id, job.clone());
        job
    }

    pub async fn update_job<E>(
        &self,
        id: &str,
        updater: impl FnOnce(&mut JobStatus) -> Result<(), E>,
    ) -> Result<(), E> {
        let mut jobs = self.jobs.write().await;
        let Some(current) = jobs.get(id).cloned() else {
            return Ok(());
        };

        let mut staged = current;
        updater(&mut staged)?;
        staged.updated_at = unix_ts_secs();
        jobs.insert(id.to_string(), staged);
        Ok(())
    }
}

fn unix_ts_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{JobState, JobStatus, ServerState, unix_ts_secs};
    use snapfzz_seal_core::{error::SealError, types::ExecutionResult};

    #[tokio::test]
    async fn create_and_get_job() {
        let state = ServerState::new("/tmp/compile".into(), "/tmp/output".into());
        let created = state
            .create_job("job-1".to_string(), Some("/agent".to_string()))
            .await;

        assert_eq!(created.status, JobState::Pending);

        let fetched = state.get_job("job-1").await.expect("job should exist");
        assert_eq!(fetched.id, "job-1");
        assert_eq!(fetched.project_dir.as_deref(), Some("/agent"));
    }

    #[tokio::test]
    async fn server_state_new_keeps_directories_and_starts_empty() {
        let state = ServerState::new("/tmp/custom-compile".into(), "/tmp/custom-output".into());

        assert_eq!(
            state.compile_dir,
            std::path::PathBuf::from("/tmp/custom-compile")
        );
        assert_eq!(
            state.output_dir,
            std::path::PathBuf::from("/tmp/custom-output")
        );
        assert!(state.jobs.read().await.is_empty());
    }

    #[tokio::test]
    async fn create_job_initializes_all_fields() {
        let state = ServerState::new("/tmp/compile".into(), "/tmp/output".into());
        let created = state.create_job("job-init".to_string(), None).await;

        assert_eq!(created.id, "job-init");
        assert_eq!(created.status, JobState::Pending);
        assert_eq!(created.project_dir, None);
        assert_eq!(created.output_path, None);
        assert_eq!(created.error, None);
        assert_eq!(created.sandbox_id, None);
        assert!(created.result.is_none());
        assert!(created.updated_at >= created.created_at);
    }

    #[tokio::test]
    async fn update_job_mutates_state() {
        let state = ServerState::new("/tmp/compile".into(), "/tmp/output".into());
        state
            .create_job("job-2".to_string(), Some("/agent".to_string()))
            .await;

        state
            .update_job::<SealError>("job-2", |job| {
                job.status = JobState::Ready;
                job.output_path = Some("/tmp/output/agent.bin".to_string());
                Ok(())
            })
            .await
            .expect("update should succeed");

        let updated = state.get_job("job-2").await.expect("job should exist");
        assert_eq!(updated.status, JobState::Ready);
        assert_eq!(
            updated.output_path.as_deref(),
            Some("/tmp/output/agent.bin")
        );
    }

    #[tokio::test]
    async fn update_job_updates_timestamp_and_allows_complex_changes() {
        let state = ServerState::new("/tmp/compile".into(), "/tmp/output".into());
        let created = state
            .create_job("job-complex".to_string(), Some("/agent".to_string()))
            .await;

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        state
            .update_job::<SealError>("job-complex", |job| {
                job.status = JobState::Completed;
                job.error = Some("warning".to_string());
                job.sandbox_id = Some("sbx-123".to_string());
                job.result = Some(ExecutionResult {
                    exit_code: 7,
                    stdout: "out".to_string(),
                    stderr: "err".to_string(),
                });
                Ok(())
            })
            .await
            .expect("update should succeed");

        let updated = state
            .get_job("job-complex")
            .await
            .expect("job should exist");
        assert_eq!(updated.status, JobState::Completed);
        assert_eq!(updated.error.as_deref(), Some("warning"));
        assert_eq!(updated.sandbox_id.as_deref(), Some("sbx-123"));
        assert_eq!(updated.result.expect("result should exist").exit_code, 7);
        assert!(updated.updated_at > created.updated_at);
    }

    #[tokio::test]
    async fn update_job_missing_job_is_noop_success() {
        let state = ServerState::new("/tmp/compile".into(), "/tmp/output".into());
        state
            .update_job::<SealError>("missing", |_job| Ok(()))
            .await
            .expect("missing job should be no-op success");
    }

    #[tokio::test]
    async fn update_job_rolls_back_when_updater_errors() {
        let state = ServerState::new("/tmp/compile".into(), "/tmp/output".into());
        state
            .create_job("job-3".to_string(), Some("/agent".to_string()))
            .await;

        let err = state
            .update_job("job-3", |job| {
                job.status = JobState::Running;
                Err(SealError::InvalidInput("reject".to_string()))
            })
            .await
            .expect_err("updater should fail");
        assert!(matches!(err, SealError::InvalidInput(_)));

        let persisted = state.get_job("job-3").await.expect("job exists");
        assert_eq!(persisted.status, JobState::Pending);
    }

    #[test]
    fn job_status_serializes_and_deserializes() {
        let job = JobStatus {
            id: "job-json".to_string(),
            status: JobState::Failed,
            project_dir: Some("/agent".to_string()),
            output_path: Some("/tmp/out".to_string()),
            error: Some("boom".to_string()),
            created_at: 10,
            updated_at: 11,
            sandbox_id: Some("sbx-9".to_string()),
            result: Some(ExecutionResult {
                exit_code: 1,
                stdout: "stdout".to_string(),
                stderr: "stderr".to_string(),
            }),
        };

        let value = serde_json::to_value(&job).expect("job should serialize");
        assert_eq!(value["status"], "failed");
        assert_eq!(value["sandbox_id"], "sbx-9");

        let round_trip: JobStatus = serde_json::from_value(value).expect("job should deserialize");
        assert_eq!(round_trip.id, "job-json");
        assert_eq!(round_trip.status, JobState::Failed);
        assert_eq!(
            round_trip.result.expect("result should exist").stderr,
            "stderr"
        );
    }

    #[test]
    fn unix_ts_secs_is_near_current_time() {
        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be after epoch")
            .as_secs();
        let ts = unix_ts_secs();
        let after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be after epoch")
            .as_secs();

        assert!(ts >= before);
        assert!(ts <= after);
    }
}
