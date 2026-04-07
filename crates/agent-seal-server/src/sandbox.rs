use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agent_seal_core::error::SealError;
use agent_seal_fingerprint::model::{FingerprintSnapshot, RuntimeKind, SourceValue, Stability};
use tokio::process::Command;

#[derive(Debug, Clone)]
pub struct SandboxConfig {
    pub image: String,
    pub env: Vec<(String, String)>,
    pub memory_mb: Option<u64>,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone)]
pub struct SandboxHandle {
    pub id: String,
    pub container_id: Option<String>,
    pub config: SandboxConfig,
}

pub struct SandboxProvisioner {
    docker_bin: Option<String>,
}

impl Default for SandboxProvisioner {
    fn default() -> Self {
        Self::new()
    }
}

impl SandboxProvisioner {
    pub fn new() -> Self {
        Self {
            docker_bin: find_docker_binary(),
        }
    }

    pub async fn provision(&self, config: &SandboxConfig) -> Result<SandboxHandle, SealError> {
        let docker = self.require_docker()?;
        let mut args: Vec<String> = vec!["run".to_string(), "-d".to_string()];

        for (key, value) in &config.env {
            args.push("-e".to_string());
            args.push(format!("{key}={value}"));
        }

        if let Some(memory_mb) = config.memory_mb {
            args.push("--memory".to_string());
            args.push(format!("{}m", memory_mb));
        }

        args.push(config.image.clone());
        args.push("sleep".to_string());
        args.push(config.timeout_secs.to_string());

        let output = run_command(docker, &args).await?;
        let container_id = parse_container_id(&output.stdout)?;

        Ok(SandboxHandle {
            id: new_sandbox_id(),
            container_id: Some(container_id),
            config: config.clone(),
        })
    }

    pub async fn destroy(&self, handle: &SandboxHandle) -> Result<(), SealError> {
        let docker = self.require_docker()?;
        if let Some(container_id) = &handle.container_id {
            let args = vec!["rm".to_string(), "-f".to_string(), container_id.clone()];
            run_command(docker, &args).await?;
        }
        Ok(())
    }

    pub async fn collect_fingerprint(
        &self,
        handle: &SandboxHandle,
    ) -> Result<FingerprintSnapshot, SealError> {
        self.require_docker()?;

        let hostname_value = handle.id.clone().into_bytes();
        Ok(FingerprintSnapshot {
            runtime: RuntimeKind::Docker,
            stable: vec![SourceValue {
                id: "linux.hostname",
                value: hostname_value,
                confidence: 70,
                stability: Stability::Stable,
            }],
            ephemeral: vec![],
            collected_at_unix_ms: unix_ts_millis(),
        })
    }

    pub fn docker_bin_path(&self) -> Option<&str> {
        self.docker_bin.as_deref()
    }

    fn require_docker(&self) -> Result<&str, SealError> {
        self.docker_bin.as_deref().ok_or_else(|| {
            let io_err = std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "docker binary not found in PATH; sandbox operations unavailable",
            );
            SealError::Other(io_err.into())
        })
    }
}

fn find_docker_binary() -> Option<String> {
    if let Ok(explicit) = std::env::var("DOCKER_BIN")
        && !explicit.trim().is_empty()
    {
        return Some(explicit);
    }

    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join("docker");
        if is_executable(&candidate) {
            return Some(candidate.to_string_lossy().to_string());
        }
    }

    None
}

fn is_executable(path: &Path) -> bool {
    path.is_file()
}

fn parse_container_id(stdout: &[u8]) -> Result<String, SealError> {
    let raw = String::from_utf8_lossy(stdout).trim().to_string();
    if raw.is_empty() {
        return Err(SealError::CompilationError(
            "docker run did not return a container id".to_string(),
        ));
    }
    Ok(raw)
}

async fn run_command(bin: &str, args: &[String]) -> Result<std::process::Output, SealError> {
    let output = Command::new(bin)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;

    if output.status.success() {
        Ok(output)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(SealError::CompilationError(format!(
            "command failed: {} {} ({})",
            bin,
            args.join(" "),
            stderr.trim()
        )))
    }
}

pub async fn copy_into_sandbox(
    provisioner: &SandboxProvisioner,
    handle: &SandboxHandle,
    host_path: &Path,
    target_path: &str,
) -> Result<(), SealError> {
    let docker = provisioner.require_docker()?;
    let container_id = handle
        .container_id
        .clone()
        .ok_or_else(|| SealError::InvalidInput("sandbox handle has no container id".to_string()))?;

    let args = vec![
        "cp".to_string(),
        host_path.to_string_lossy().to_string(),
        format!("{container_id}:{target_path}"),
    ];
    run_command(docker, &args).await.map(|_| ())
}

pub async fn exec_in_sandbox(
    provisioner: &SandboxProvisioner,
    handle: &SandboxHandle,
    command: &str,
) -> Result<agent_seal_core::types::ExecutionResult, SealError> {
    let docker = provisioner.require_docker()?;
    let container_id = handle
        .container_id
        .clone()
        .ok_or_else(|| SealError::InvalidInput("sandbox handle has no container id".to_string()))?;

    let args = vec![
        "exec".to_string(),
        container_id,
        "sh".to_string(),
        "-lc".to_string(),
        command.to_string(),
    ];

    let output = run_command_allow_nonzero(docker, &args).await?;
    Ok(agent_seal_core::types::ExecutionResult {
        exit_code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

async fn run_command_allow_nonzero(
    bin: &str,
    args: &[String],
) -> Result<std::process::Output, SealError> {
    let output = Command::new(bin)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;
    Ok(output)
}

fn unix_ts_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_millis(0))
        .as_millis() as u64
}

fn new_sandbox_id() -> String {
    let now = unix_ts_millis();
    format!("sbx-{now}")
}

#[cfg(test)]
mod tests {
    use super::{SandboxProvisioner, parse_container_id};

    #[test]
    fn parse_container_id_returns_trimmed_value() {
        let container = parse_container_id(b"abc123\n").expect("container id should parse");
        assert_eq!(container, "abc123");
    }

    #[test]
    fn parse_container_id_rejects_empty_output() {
        let err = parse_container_id(b"\n").expect_err("empty output should fail");
        assert!(err.to_string().contains("did not return a container id"));
    }

    #[test]
    fn provisioner_reports_missing_docker() {
        let provisioner = SandboxProvisioner { docker_bin: None };
        let err = provisioner
            .require_docker()
            .expect_err("missing docker should error");
        assert!(err.to_string().contains("docker binary not found"));
    }
}
