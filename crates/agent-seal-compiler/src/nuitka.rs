use agent_seal_core::error::SealError;
use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[derive(Debug, Clone)]
pub struct NuitkaConfig {
    pub project_dir: PathBuf,
    pub output_dir: PathBuf,
    pub onefile: bool,
    pub standalone: bool,
    pub remove_output: bool,
    pub timeout_secs: u64,
}

impl Default for NuitkaConfig {
    fn default() -> Self {
        Self {
            project_dir: PathBuf::new(),
            output_dir: PathBuf::new(),
            onefile: true,
            standalone: true,
            remove_output: true,
            timeout_secs: 1_800,
        }
    }
}

pub fn compile_with_nuitka(config: &NuitkaConfig) -> Result<PathBuf, SealError> {
    compile_with_command("nuitka", config)
}

fn compile_with_command(command_name: &str, config: &NuitkaConfig) -> Result<PathBuf, SealError> {
    let project_name = project_name(&config.project_dir)?;

    let mut command = Command::new(command_name);
    if config.standalone {
        command.arg("--standalone");
    }
    if config.onefile {
        command.arg("--onefile");
    }
    if config.remove_output {
        command.arg("--remove-output");
    }

    command
        .arg("--output-dir")
        .arg(&config.output_dir)
        .arg(&config.project_dir);

    let output = run_with_timeout(command, config.timeout_secs, command_name)?;

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    if !output.status.success() || contains_error_indicator(&stderr) {
        return Err(SealError::CompilationError(format!(
            "nuitka failed: status={:?}, stderr={}, stdout={}",
            output.status.code(),
            stderr.trim(),
            stdout.trim()
        )));
    }

    Ok(expected_output_path(config, &project_name))
}

fn expected_output_path(config: &NuitkaConfig, project_name: &str) -> PathBuf {
    if config.onefile {
        config.output_dir.join(format!("{project_name}.bin"))
    } else {
        config
            .output_dir
            .join(format!("{project_name}.dist"))
            .join(project_name)
    }
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

fn project_name(path: &Path) -> Result<String, SealError> {
    path.file_name()
        .and_then(OsStr::to_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| SealError::InvalidInput(format!("invalid project path: {}", path.display())))
}

fn contains_error_indicator(stderr: &str) -> bool {
    ["Error:", "error:", "FAILED"]
        .iter()
        .any(|needle| stderr.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nuitka_missing_binary_returns_compilation_error() {
        let config = NuitkaConfig {
            project_dir: PathBuf::from("/tmp/example_project"),
            output_dir: PathBuf::from("/tmp/out"),
            onefile: true,
            standalone: true,
            remove_output: true,
            timeout_secs: 1,
        };

        let err = compile_with_command("definitely-missing-nuitka", &config)
            .expect_err("missing command should return an error");

        match err {
            SealError::CompilationError(message) => {
                assert!(message.contains("not found"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
