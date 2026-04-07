use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

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
    pub result: Option<agent_seal_core::types::ExecutionResult>,
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
}

impl ServerState {
    pub fn new(compile_dir: PathBuf, output_dir: PathBuf) -> Self {
        Self {
            jobs: Arc::new(RwLock::new(HashMap::new())),
            compile_dir,
            output_dir,
        }
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
    use super::{JobState, ServerState};
    use agent_seal_core::error::SealError;

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
}
