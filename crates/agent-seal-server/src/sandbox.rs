use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agent_seal_core::error::SealError;
use agent_seal_fingerprint::model::{FingerprintSnapshot, RuntimeKind, SourceValue, Stability};
use rand::{RngCore, rngs::OsRng};
use regex::Regex;
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
        validate_sandbox_config(config)?;

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
                id: "linux.hostname".to_string(),
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

fn validate_sandbox_config(config: &SandboxConfig) -> Result<(), SealError> {
    let env_key_regex = Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$").expect("valid env key regex");

    if config.image.trim().is_empty() || config.image.chars().any(char::is_whitespace) {
        return Err(SealError::InvalidInput(
            "sandbox image must be non-empty and contain no whitespace".to_string(),
        ));
    }

    for (key, value) in &config.env {
        if !env_key_regex.is_match(key) {
            return Err(SealError::InvalidInput(format!(
                "invalid environment variable key: {key}",
            )));
        }

        if value.contains('\n') || value.contains('\r') {
            return Err(SealError::InvalidInput(format!(
                "invalid environment variable value for key: {key}",
            )));
        }
    }

    Ok(())
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
    timeout_secs: u64,
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

    let output = tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        run_command_allow_nonzero(docker, &args),
    )
    .await
    .map_err(|_| SealError::InvalidInput("sandbox execution timed out".to_string()))??;

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

fn random_hex_4() -> String {
    let mut bytes = [0_u8; 4];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn new_sandbox_id() -> String {
    let now = unix_ts_millis();
    format!("sbx-{now}-{}", random_hex_4())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::Path,
        process::Command as StdCommand,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{
        SandboxConfig, SandboxHandle, SandboxProvisioner, exec_in_sandbox, find_docker_binary,
        is_executable, new_sandbox_id, parse_container_id, random_hex_4, unix_ts_millis,
        validate_sandbox_config,
    };

    fn temp_path(prefix: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
    }

    fn run_env_probe(mode: &str, envs: &[(&str, &str)]) -> std::process::Output {
        let mut cmd = StdCommand::new(std::env::current_exe().expect("test binary path"));
        cmd.arg("subprocess_env_probe")
            .arg("--nocapture")
            .env("AGENT_SEAL_SANDBOX_TEST_MODE", mode)
            .env_remove("DOCKER_BIN");
        for (key, value) in envs {
            cmd.env(key, value);
        }
        cmd.output().expect("subprocess should run")
    }

    fn fixture_sandbox_config() -> SandboxConfig {
        SandboxConfig {
            image: "python:3.11-slim".to_string(),
            env: vec![("FOO".to_string(), "bar".to_string())],
            memory_mb: Some(256),
            timeout_secs: 30,
        }
    }

    fn make_executable_script(contents: &str) -> std::path::PathBuf {
        let dir = temp_path("sandbox-script");
        fs::create_dir_all(&dir).expect("script temp dir should be created");
        let script = dir.join("docker-stub.sh");
        fs::write(&script, contents).expect("script should be written");
        let mut perms = fs::metadata(&script)
            .expect("script metadata should be readable")
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script, perms).expect("script should be executable");
        script
    }

    fn assert_probe_success(output: std::process::Output) {
        assert!(
            output.status.success(),
            "probe failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn fixture_sandbox_handle() -> SandboxHandle {
        SandboxHandle {
            id: "sbx-test".to_string(),
            container_id: Some("container-123".to_string()),
            config: fixture_sandbox_config(),
        }
    }

    #[test]
    fn subprocess_env_probe() {
        let Ok(mode) = std::env::var("AGENT_SEAL_SANDBOX_TEST_MODE") else {
            return;
        };

        match mode.as_str() {
            "new_uses_env" => {
                let expected = std::env::var("AGENT_SEAL_EXPECTED").expect("expected path env");
                let provisioner = SandboxProvisioner::new();
                assert_eq!(provisioner.docker_bin_path(), Some(expected.as_str()));
            }
            "new_none" => {
                let provisioner = SandboxProvisioner::new();
                assert_eq!(provisioner.docker_bin_path(), None);
            }
            "find_uses_env" => {
                let expected = std::env::var("AGENT_SEAL_EXPECTED").expect("expected path env");
                let found = find_docker_binary();
                assert_eq!(found.as_deref(), Some(expected.as_str()));
            }
            other => panic!("unknown probe mode: {other}"),
        }
    }

    #[test]
    fn sandbox_config_construction_keeps_fields() {
        let config = fixture_sandbox_config();

        assert_eq!(config.image, "python:3.11-slim");
        assert_eq!(config.env.len(), 1);
        assert_eq!(config.env[0].0, "FOO");
        assert_eq!(config.env[0].1, "bar");
        assert_eq!(config.memory_mb, Some(256));
        assert_eq!(config.timeout_secs, 30);
    }

    #[test]
    fn sandbox_handle_exposes_expected_fields() {
        let config = fixture_sandbox_config();
        let handle = SandboxHandle {
            id: "sbx-test".to_string(),
            container_id: Some("container-123".to_string()),
            config,
        };

        assert_eq!(handle.id, "sbx-test");
        assert_eq!(handle.container_id.as_deref(), Some("container-123"));
        assert_eq!(handle.config.image, "python:3.11-slim");
        assert_eq!(handle.config.timeout_secs, 30);
    }

    #[test]
    fn sandbox_provisioner_new_uses_explicit_docker_bin_env() {
        let expected = temp_path("docker-bin").to_string_lossy().to_string();
        let output = run_env_probe(
            "new_uses_env",
            &[
                ("DOCKER_BIN", expected.as_str()),
                ("AGENT_SEAL_EXPECTED", expected.as_str()),
            ],
        );

        assert_probe_success(output);
    }

    #[test]
    fn sandbox_provisioner_new_can_have_none_when_env_and_path_missing() {
        let path_dir = temp_path("empty-path-dir");
        fs::create_dir_all(&path_dir).expect("temp path dir should be created");
        let path = path_dir.to_string_lossy().to_string();
        let output = run_env_probe(
            "new_none",
            &[("DOCKER_BIN", "   "), ("PATH", path.as_str())],
        );

        assert_probe_success(output);
        fs::remove_dir_all(path_dir).expect("temp path dir should be removed");
    }

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

    #[tokio::test]
    async fn provision_fails_when_docker_binary_missing() {
        let provisioner = SandboxProvisioner { docker_bin: None };

        let err = provisioner
            .provision(&fixture_sandbox_config())
            .await
            .expect_err("missing docker binary should fail provision");

        assert!(err.to_string().contains("docker binary not found"));
    }

    #[tokio::test]
    async fn provision_fails_when_docker_command_returns_nonzero() {
        let script = make_executable_script("#!/bin/sh\necho docker exploded 1>&2\nexit 9\n");
        let provisioner = SandboxProvisioner {
            docker_bin: Some(script.to_string_lossy().to_string()),
        };

        let err = provisioner
            .provision(&fixture_sandbox_config())
            .await
            .expect_err("nonzero docker command should fail provision");

        assert!(err.to_string().contains("command failed:"));
        assert!(err.to_string().contains("docker exploded"));

        fs::remove_dir_all(script.parent().expect("script parent should exist"))
            .expect("script temp dir should be removed");
    }

    #[tokio::test]
    async fn provision_fails_when_docker_binary_path_is_invalid() {
        let missing_bin = temp_path("missing-docker-bin");
        let provisioner = SandboxProvisioner {
            docker_bin: Some(missing_bin.to_string_lossy().to_string()),
        };

        let err = provisioner
            .provision(&fixture_sandbox_config())
            .await
            .expect_err("invalid docker path should fail provision");

        assert!(
            err.to_string().contains("No such file")
                || err.to_string().contains("not found")
                || err.to_string().contains("os error")
        );
    }

    #[tokio::test]
    async fn run_fails_when_docker_binary_missing() {
        let provisioner = SandboxProvisioner { docker_bin: None };

        let err = exec_in_sandbox(&provisioner, &fixture_sandbox_handle(), "echo hi", 1)
            .await
            .expect_err("missing docker binary should fail run");

        assert!(err.to_string().contains("docker binary not found"));
    }

    #[tokio::test]
    async fn run_fails_when_docker_binary_path_is_invalid() {
        let missing_bin = temp_path("missing-docker-run");
        let provisioner = SandboxProvisioner {
            docker_bin: Some(missing_bin.to_string_lossy().to_string()),
        };

        let err = exec_in_sandbox(&provisioner, &fixture_sandbox_handle(), "echo hi", 1)
            .await
            .expect_err("invalid docker path should fail run");

        assert!(
            err.to_string().contains("No such file")
                || err.to_string().contains("not found")
                || err.to_string().contains("os error")
        );
    }

    #[tokio::test]
    async fn destroy_fails_when_docker_binary_missing() {
        let provisioner = SandboxProvisioner { docker_bin: None };

        let err = provisioner
            .destroy(&fixture_sandbox_handle())
            .await
            .expect_err("missing docker binary should fail destroy");

        assert!(err.to_string().contains("docker binary not found"));
    }

    #[tokio::test]
    async fn destroy_fails_when_docker_command_returns_nonzero() {
        let script = make_executable_script("#!/bin/sh\necho cannot remove 1>&2\nexit 3\n");
        let provisioner = SandboxProvisioner {
            docker_bin: Some(script.to_string_lossy().to_string()),
        };

        let err = provisioner
            .destroy(&fixture_sandbox_handle())
            .await
            .expect_err("nonzero docker command should fail destroy");

        assert!(err.to_string().contains("command failed:"));
        assert!(err.to_string().contains("cannot remove"));

        fs::remove_dir_all(script.parent().expect("script parent should exist"))
            .expect("script temp dir should be removed");
    }

    #[tokio::test]
    async fn destroy_fails_when_docker_binary_path_is_invalid() {
        let missing_bin = temp_path("missing-docker-destroy");
        let provisioner = SandboxProvisioner {
            docker_bin: Some(missing_bin.to_string_lossy().to_string()),
        };

        let err = provisioner
            .destroy(&fixture_sandbox_handle())
            .await
            .expect_err("invalid docker path should fail destroy");

        assert!(
            err.to_string().contains("No such file")
                || err.to_string().contains("not found")
                || err.to_string().contains("os error")
        );
    }

    #[test]
    fn find_docker_binary_uses_docker_bin_env_when_set() {
        let expected = temp_path("docker-explicit").to_string_lossy().to_string();
        let output = run_env_probe(
            "find_uses_env",
            &[
                ("DOCKER_BIN", expected.as_str()),
                ("AGENT_SEAL_EXPECTED", expected.as_str()),
            ],
        );

        assert_probe_success(output);
    }

    #[test]
    fn find_docker_binary_discovers_binary_from_path() {
        let dir = temp_path("sandbox-path-docker");
        fs::create_dir_all(&dir).expect("temp dir should be created");
        let docker_path = dir.join("docker");
        fs::write(&docker_path, b"#!/bin/sh\nexit 0\n").expect("docker stub should be written");
        let expected = docker_path.to_string_lossy().to_string();

        let output = run_env_probe(
            "find_uses_env",
            &[
                ("PATH", dir.to_string_lossy().as_ref()),
                ("AGENT_SEAL_EXPECTED", expected.as_str()),
            ],
        );
        assert_probe_success(output);

        fs::remove_dir_all(dir).expect("temp dir should be cleaned");
    }

    #[test]
    fn is_executable_checks_file_presence() {
        let dir = temp_path("sandbox-executable");
        fs::create_dir_all(&dir).expect("temp dir should be created");
        let file = dir.join("docker");
        fs::write(&file, b"#!/bin/sh\nexit 0\n").expect("temp file should be written");

        assert!(is_executable(Path::new(&file)));
        assert!(!is_executable(&dir.join("missing")));

        fs::remove_dir_all(dir).expect("temp dir should be cleaned");
    }

    #[test]
    fn validate_sandbox_config_accepts_valid_configuration() {
        let result = validate_sandbox_config(&fixture_sandbox_config());

        assert!(result.is_ok());
    }

    #[test]
    fn validate_sandbox_config_rejects_empty_or_whitespace_image() {
        let mut empty_image = fixture_sandbox_config();
        empty_image.image = "".to_string();
        let mut whitespace_image = fixture_sandbox_config();
        whitespace_image.image = "python:3.11 slim".to_string();

        let empty_err = validate_sandbox_config(&empty_image).expect_err("empty image must fail");
        let whitespace_err =
            validate_sandbox_config(&whitespace_image).expect_err("whitespace image must fail");

        assert!(
            empty_err
                .to_string()
                .contains("sandbox image must be non-empty")
        );
        assert!(
            whitespace_err
                .to_string()
                .contains("sandbox image must be non-empty")
        );
    }

    #[test]
    fn validate_sandbox_config_rejects_invalid_env_key() {
        let mut config = fixture_sandbox_config();
        config.env = vec![("BAD-KEY".to_string(), "value".to_string())];

        let err = validate_sandbox_config(&config).expect_err("invalid key must fail");

        assert!(
            err.to_string()
                .contains("invalid environment variable key: BAD-KEY")
        );
    }

    #[test]
    fn validate_sandbox_config_rejects_newline_in_env_value() {
        let mut config = fixture_sandbox_config();
        config.env = vec![("GOOD_KEY".to_string(), "line1\nline2".to_string())];

        let err = validate_sandbox_config(&config).expect_err("newline value must fail");

        assert!(
            err.to_string()
                .contains("invalid environment variable value for key: GOOD_KEY")
        );
    }

    #[test]
    fn unix_ts_millis_returns_currentish_timestamp() {
        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be after epoch")
            .as_millis() as u64;
        let ts = unix_ts_millis();
        let after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be after epoch")
            .as_millis() as u64;

        assert!(ts >= before);
        assert!(ts <= after);
    }

    #[test]
    fn random_hex_4_returns_eight_hex_chars() {
        let hex = random_hex_4();
        assert_eq!(hex.len(), 8);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn random_hex_4_produces_distinct_values_across_calls() {
        let first = random_hex_4();
        let second = random_hex_4();
        assert_ne!(first, second);
    }

    #[test]
    fn new_sandbox_id_starts_with_sbx_prefix() {
        let id = new_sandbox_id();
        assert!(id.starts_with("sbx-"));
        assert_eq!(id.split('-').count(), 3);
    }

    #[test]
    fn new_sandbox_id_is_unique() {
        let first = new_sandbox_id();
        let second = new_sandbox_id();
        assert_ne!(first, second);
    }
}
