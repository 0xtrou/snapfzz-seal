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

#[derive(Debug, Clone, Copy, Default)]
pub struct NuitkaBackend;

impl CompileBackend for NuitkaBackend {
    fn name(&self) -> &str {
        "nuitka"
    }

    fn can_compile(&self, project_dir: &Path) -> bool {
        project_dir.join("main.py").exists() || project_dir.join("setup.py").exists()
    }

    fn compile(&self, config: &CompileConfig) -> Result<PathBuf, SealError> {
        let nuitka_cfg = NuitkaConfig {
            project_dir: config.project_dir.clone(),
            output_dir: config.output_dir.clone(),
            timeout_secs: config.timeout_secs,
            ..NuitkaConfig::default()
        };
        compile_with_nuitka(&nuitka_cfg)
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
        .arg(format!("--output-dir={}", config.output_dir.display()))
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
    fn nuitka_backend_name_and_detection() {
        let root = std::env::temp_dir().join(format!(
            "snapfzz-seal-nuitka-backend-detect-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock should be after unix epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).expect("root dir should be created");
        let backend = NuitkaBackend;
        assert_eq!(backend.name(), "nuitka");
        assert!(!backend.can_compile(&root));

        std::fs::write(root.join("main.py"), "print('hello')").expect("main.py should be writable");
        assert!(backend.can_compile(&root));
    }

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

    #[test]
    fn expected_output_path_uses_bin_for_onefile() {
        let config = NuitkaConfig {
            output_dir: PathBuf::from("/tmp/out"),
            onefile: true,
            ..NuitkaConfig::default()
        };

        let path = expected_output_path(&config, "agent");
        assert_eq!(path, PathBuf::from("/tmp/out/agent.bin"));
    }

    #[test]
    fn expected_output_path_uses_dist_layout_for_non_onefile() {
        let config = NuitkaConfig {
            output_dir: PathBuf::from("/tmp/out"),
            onefile: false,
            ..NuitkaConfig::default()
        };

        let path = expected_output_path(&config, "agent");
        assert_eq!(path, PathBuf::from("/tmp/out/agent.dist/agent"));
    }

    #[test]
    fn project_name_returns_filename_for_valid_path() {
        let name = project_name(Path::new("/tmp/example_project"))
            .expect("valid project path should return file name");
        assert_eq!(name, "example_project");
    }

    #[test]
    fn project_name_rejects_path_without_filename() {
        let err = project_name(Path::new("/"))
            .expect_err("root path should not contain a usable file name");
        match err {
            SealError::InvalidInput(message) => {
                assert!(message.contains("invalid project path"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn project_name_rejects_empty_path() {
        let err = project_name(Path::new(""))
            .expect_err("empty path should not contain a usable file name");
        match err {
            SealError::InvalidInput(message) => {
                assert!(message.contains("invalid project path"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn contains_error_indicator_detects_known_patterns() {
        assert!(contains_error_indicator("Error: fatal"));
        assert!(contains_error_indicator("error: lower case"));
        assert!(contains_error_indicator("build FAILED unexpectedly"));
        assert!(!contains_error_indicator("all good"));
    }

    #[test]
    fn run_with_timeout_succeeds_for_fast_command() {
        let mut command = Command::new("echo");
        command.arg("hello");

        let output = run_with_timeout(command, 5, "echo")
            .expect("fast echo command should complete within timeout");
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("hello"));
    }

    #[test]
    fn map_spawn_error_maps_not_found_to_compilation_error() {
        let err = map_spawn_error(
            std::io::Error::new(std::io::ErrorKind::NotFound, "missing"),
            "nuitka",
        );

        match err {
            SealError::CompilationError(message) => {
                assert!(message.contains("nuitka not found"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn map_spawn_error_keeps_other_io_errors() {
        let err = map_spawn_error(
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
            "nuitka",
        );

        match err {
            SealError::Io(io) => {
                assert_eq!(io.kind(), std::io::ErrorKind::PermissionDenied);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn default_config_sets_expected_defaults() {
        let config = NuitkaConfig::default();
        assert!(config.project_dir.as_os_str().is_empty());
        assert!(config.output_dir.as_os_str().is_empty());
        assert!(config.onefile);
        assert!(config.standalone);
        assert!(config.remove_output);
        assert_eq!(config.timeout_secs, 1_800);
    }

    #[test]
    fn compile_with_nuitka_surfaces_invalid_project_path() {
        let config = NuitkaConfig {
            project_dir: PathBuf::from("/"),
            output_dir: PathBuf::from("/tmp/out"),
            onefile: true,
            standalone: true,
            remove_output: true,
            timeout_secs: 1,
        };

        let err = compile_with_nuitka(&config)
            .expect_err("invalid project path should fail before command execution");
        match err {
            SealError::InvalidInput(message) => {
                assert!(message.contains("invalid project path"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn run_with_timeout_returns_timeout_for_slow_command() {
        let mut command = Command::new("python3");
        command.arg("-c").arg("import time; time.sleep(2)");

        let err = run_with_timeout(command, 0, "python3")
            .expect_err("slow command should time out even when timeout is zero");
        match err {
            SealError::CompilationTimeout(timeout) => {
                assert_eq!(timeout, 0);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn compile_with_command_treats_error_text_as_failure() {
        let test_root = std::env::temp_dir().join(format!(
            "snapfzz-seal-nuitka-error-indicator-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock should be after unix epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&test_root).expect("test root should be creatable");

        let fake_nuitka = test_root.join("fake-nuitka.sh");
        std::fs::write(
            &fake_nuitka,
            "#!/bin/sh\necho 'error: simulated nuitka failure' >&2\nexit 0\n",
        )
        .expect("fake nuitka should be writable");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&fake_nuitka)
                .expect("fake nuitka metadata should be readable")
                .permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&fake_nuitka, perms)
                .expect("fake nuitka should be executable");
        }

        let config = NuitkaConfig {
            project_dir: test_root.join("project"),
            output_dir: test_root.join("out"),
            onefile: true,
            standalone: true,
            remove_output: true,
            timeout_secs: 5,
        };
        std::fs::create_dir_all(&config.project_dir).expect("project dir should be creatable");

        let err = compile_with_command(
            fake_nuitka
                .to_str()
                .expect("fake nuitka path should be valid utf-8"),
            &config,
        )
        .expect_err("stderr error indicator should be treated as failure");

        match err {
            SealError::CompilationError(message) => {
                assert!(message.contains("nuitka failed"));
                assert!(message.contains("status=Some(0)"));
                assert!(message.contains("error: simulated nuitka failure"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn compile_with_command_reports_non_zero_exit_status() {
        let test_root = std::env::temp_dir().join(format!(
            "snapfzz-seal-nuitka-non-zero-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock should be after unix epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&test_root).expect("test root should be creatable");

        let fake_nuitka = test_root.join("fake-nuitka-exit.sh");
        std::fs::write(&fake_nuitka, "#!/bin/sh\necho 'boom' >&2\nexit 42\n")
            .expect("fake nuitka should be writable");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&fake_nuitka)
                .expect("fake nuitka metadata should be readable")
                .permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&fake_nuitka, perms)
                .expect("fake nuitka should be executable");
        }

        let config = NuitkaConfig {
            project_dir: test_root.join("project"),
            output_dir: test_root.join("out"),
            onefile: false,
            standalone: false,
            remove_output: false,
            timeout_secs: 5,
        };
        std::fs::create_dir_all(&config.project_dir).expect("project dir should be creatable");

        let err = compile_with_command(
            fake_nuitka
                .to_str()
                .expect("fake nuitka path should be valid utf-8"),
            &config,
        )
        .expect_err("non-zero status should be treated as failure");

        match err {
            SealError::CompilationError(message) => {
                assert!(message.contains("nuitka failed"));
                assert!(message.contains("status=Some(42)"));
                assert!(message.contains("boom"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
