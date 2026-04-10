use super::{CompileBackend, CompileConfig};
use snapfzz_seal_core::error::SealError;
use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[derive(Debug, Clone)]
pub struct GoConfig {
    pub project_dir: PathBuf,
    pub output_dir: PathBuf,
    pub timeout_secs: u64,
}

impl Default for GoConfig {
    fn default() -> Self {
        Self {
            project_dir: PathBuf::new(),
            output_dir: PathBuf::new(),
            timeout_secs: 600,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct GoBackend;

impl CompileBackend for GoBackend {
    fn name(&self) -> &str {
        "go"
    }

    fn can_compile(&self, project_dir: &Path) -> bool {
        project_dir.join("go.mod").exists()
    }

    fn compile(&self, config: &CompileConfig) -> Result<PathBuf, SealError> {
        let go_cfg = GoConfig {
            project_dir: config.project_dir.clone(),
            output_dir: config.output_dir.clone(),
            timeout_secs: config.timeout_secs,
        };
        compile_with_go(&go_cfg)
    }
}

pub fn compile_with_go(config: &GoConfig) -> Result<PathBuf, SealError> {
    let project_name = project_name(&config.project_dir)?;
    let output_path = config.output_dir.join(project_name);

    let mut command = Command::new("go");
    command
        .arg("build")
        .arg("-ldflags=-s -w")
        .arg("-o")
        .arg(&output_path)
        .arg(".");

    let goarch = std::env::var("GOARCH").unwrap_or_else(|_| {
        if cfg!(target_arch = "aarch64") {
            "arm64".to_string()
        } else {
            "amd64".to_string()
        }
    });

    command
        .env("CGO_ENABLED", "0")
        .env("GOOS", "linux")
        .env("GOARCH", &goarch)
        .current_dir(&config.project_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = run_with_timeout(command, config.timeout_secs, "go")?;

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    if !output.status.success() {
        return Err(SealError::CompilationError(format!(
            "go build failed: status={:?}, stderr={}, stdout={}",
            output.status.code(),
            stderr.trim(),
            stdout.trim()
        )));
    }

    if !output_path.exists() {
        return Err(SealError::CompilationError(format!(
            "go build completed but output not found at {}",
            output_path.display()
        )));
    }

    tracing::info!("go compilation successful: {}", output_path.display());
    Ok(output_path)
}

fn run_with_timeout(
    mut command: Command,
    timeout_secs: u64,
    command_name: &str,
) -> Result<std::process::Output, SealError> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| map_spawn_error(err, command_name))?;

    let timeout = Duration::from_secs(timeout_secs.max(1));
    let start = Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                let output = child.wait_with_output()?;
                return Ok(output);
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(SealError::CompilationTimeout(timeout_secs));
                }
                thread::sleep(Duration::from_millis(100));
            }
            Err(err) => return Err(SealError::Io(err)),
        }
    }
}

fn map_spawn_error(err: std::io::Error, command_name: &str) -> SealError {
    if err.kind() == std::io::ErrorKind::NotFound {
        SealError::CompilationError(format!("{command_name} not found"))
    } else {
        SealError::Io(err)
    }
}

fn project_name(project_dir: &Path) -> Result<String, SealError> {
    project_dir
        .file_name()
        .and_then(OsStr::to_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            SealError::CompilationError(format!(
                "cannot determine project name from directory: {}",
                project_dir.display()
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_backend_reports_name() {
        let backend = GoBackend;
        assert_eq!(backend.name(), "go");
    }

    #[test]
    fn go_backend_detects_go_mod() {
        let temp_dir = std::env::temp_dir().join(format!(
            "snapfzz-seal-go-detect-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock should be after unix epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&temp_dir).expect("temp dir should be created");
        std::fs::write(temp_dir.join("go.mod"), "module test\n").expect("go.mod should be created");

        assert!(GoBackend.can_compile(&temp_dir));

        std::fs::remove_dir_all(&temp_dir).expect("temp dir should be removed");
    }

    #[test]
    fn go_backend_rejects_non_go_project() {
        let temp_dir = std::env::temp_dir().join(format!(
            "snapfzz-seal-go-reject-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock should be after unix epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&temp_dir).expect("temp dir should be created");

        assert!(!GoBackend.can_compile(&temp_dir));

        std::fs::remove_dir_all(&temp_dir).expect("temp dir should be removed");
    }

    #[test]
    fn go_backend_compile_fails_for_invalid_project() {
        let temp_dir = std::env::temp_dir().join(format!(
            "snapfzz-seal-go-compile-fail-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock should be after unix epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&temp_dir).expect("temp dir should be created");
        let output_dir = temp_dir.join("output");
        std::fs::create_dir_all(&output_dir).expect("output dir should be created");

        std::fs::write(
            temp_dir.join("go.mod"),
            "module test\ninvalid syntax here\n",
        )
        .expect("invalid go.mod should be written");

        let config = CompileConfig {
            project_dir: temp_dir.clone(),
            output_dir: output_dir.clone(),
            target_triple: "x86_64-unknown-linux-musl".to_string(),
            timeout_secs: 30,
        };

        let result = GoBackend.compile(&config);
        assert!(result.is_err());

        std::fs::remove_dir_all(&temp_dir).expect("temp dir should be removed");
    }

    #[test]
    fn project_name_extracts_directory_name() {
        let path = PathBuf::from("/home/user/my-agent");
        assert_eq!(
            project_name(&path).expect("project name should parse"),
            "my-agent"
        );
    }

    #[test]
    fn project_name_errors_for_root_path() {
        let result = project_name(Path::new("/"));
        assert!(result.is_err());
    }
}
