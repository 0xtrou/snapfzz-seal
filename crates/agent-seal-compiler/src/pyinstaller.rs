use agent_seal_core::error::SealError;
use std::{
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[derive(Debug, Clone)]
pub struct PyInstallerConfig {
    pub project_dir: PathBuf,
    pub output_dir: PathBuf,
    pub onefile: bool,
    pub timeout_secs: u64,
}

impl Default for PyInstallerConfig {
    fn default() -> Self {
        Self {
            project_dir: PathBuf::new(),
            output_dir: PathBuf::new(),
            onefile: true,
            timeout_secs: 1_800,
        }
    }
}

pub fn compile_with_pyinstaller(config: &PyInstallerConfig) -> Result<PathBuf, SealError> {
    compile_with_command("pyinstaller", config)
}

fn compile_with_command(
    command_name: &str,
    config: &PyInstallerConfig,
) -> Result<PathBuf, SealError> {
    let project_name = project_name(&config.project_dir)?;
    let source_file = config.project_dir.join("main.py");
    if !source_file.exists() {
        return Err(SealError::CompilationError(format!(
            "missing entrypoint: {}",
            source_file.display()
        )));
    }

    let temp_root = std::env::temp_dir().join(format!("agent-seal-pyinstaller-{project_name}"));
    let workpath = temp_root.join("work");
    let specpath = temp_root.join("spec");

    fs::create_dir_all(&config.output_dir)?;
    fs::create_dir_all(&workpath)?;
    fs::create_dir_all(&specpath)?;

    let mut command = Command::new(command_name);
    if config.onefile {
        command.arg("--onefile");
    }

    command
        .arg("--distpath")
        .arg(&config.output_dir)
        .arg("--workpath")
        .arg(&workpath)
        .arg("--specpath")
        .arg(&specpath)
        .arg("--name")
        .arg(&project_name)
        .arg(source_file);

    let output = run_with_timeout(command, config.timeout_secs, command_name)?;

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() || contains_error_indicator(&stderr) {
        return Err(SealError::CompilationError(format!(
            "pyinstaller failed: status={:?}, stderr={}, stdout={}",
            output.status.code(),
            stderr.trim(),
            stdout.trim()
        )));
    }

    Ok(config.output_dir.join(project_name))
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
    fn pyinstaller_missing_binary_returns_compilation_error() {
        let test_root = std::env::temp_dir().join("agent-seal-pyinstaller-test-missing");
        let project_dir = test_root.join("project");
        let output_dir = test_root.join("dist");
        fs::create_dir_all(&project_dir).expect("project dir should be creatable");
        fs::write(project_dir.join("main.py"), "print('hello')")
            .expect("main.py should be writable");

        let config = PyInstallerConfig {
            project_dir,
            output_dir,
            onefile: true,
            timeout_secs: 1,
        };

        let err = compile_with_command("definitely-missing-pyinstaller", &config)
            .expect_err("missing command should return an error");

        match err {
            SealError::CompilationError(message) => {
                assert!(message.contains("not found"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
