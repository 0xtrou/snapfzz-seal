use crate::backend::{
    ChainBackend, CompileBackend, CompileConfig, GoBackend, NuitkaBackend, PyInstallerBackend,
};
use snapfzz_seal_core::error::SealError;
use std::{
    path::{Path, PathBuf},
    process::Command,
};

pub fn compile_agent(project_dir: &Path, output_dir: &Path) -> Result<PathBuf, SealError> {
    let backend = ChainBackend::new(vec![
        Box::new(NuitkaBackend),
        Box::new(PyInstallerBackend),
        Box::new(GoBackend),
    ]);
    compile_agent_with_backend(project_dir, output_dir, &backend)
}

pub fn compile_agent_with_backend(
    project_dir: &Path,
    output_dir: &Path,
    backend: &dyn CompileBackend,
) -> Result<PathBuf, SealError> {
    let config = CompileConfig {
        project_dir: project_dir.to_path_buf(),
        output_dir: output_dir.to_path_buf(),
        target_triple: "x86_64-unknown-linux-musl".to_string(),
        timeout_secs: 1_800,
    };
    let output = backend.compile(&config)?;

    // Nuitka onefile binaries MUST NOT be stripped - strip destroys attached payload data
    // See: https://github.com/Nuitka/Nuitka/issues/3231
    if backend.name() != "nuitka" {
        run_strip(&output)?;
    }

    verify_non_empty(&output)?;
    Ok(output)
}

fn run_strip(binary_path: &Path) -> Result<(), SealError> {
    let output = Command::new("strip").arg(binary_path).output();
    match output {
        Ok(result) => {
            if result.status.success() {
                Ok(())
            } else {
                let stderr = String::from_utf8_lossy(&result.stderr);
                let stderr_trimmed = stderr.trim();
                if stderr_trimmed.contains("Unable to recognise the format")
                    || stderr_trimmed.contains("file format not recognized")
                {
                    tracing::warn!(
                        "strip skipped for {}: format not recognized (may already be stripped)",
                        binary_path.display()
                    );
                    Ok(())
                } else {
                    Err(SealError::CompilationError(format!(
                        "strip failed for {}: {}",
                        binary_path.display(),
                        stderr_trimmed
                    )))
                }
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(SealError::Io(err)),
    }
}

fn verify_non_empty(binary_path: &Path) -> Result<(), SealError> {
    let metadata = std::fs::metadata(binary_path)?;
    if !metadata.is_file() {
        return Err(SealError::CompilationError(format!(
            "compiled output is not a file: {}",
            binary_path.display()
        )));
    }
    if metadata.len() == 0 {
        return Err(SealError::CompilationError(format!(
            "compiled output is empty: {}",
            binary_path.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::CompileConfig;

    struct TestBackend {
        name: &'static str,
        output: Option<PathBuf>,
        error: Option<&'static str>,
    }

    impl CompileBackend for TestBackend {
        fn name(&self) -> &str {
            self.name
        }

        fn can_compile(&self, _project_dir: &Path) -> bool {
            true
        }

        fn compile(&self, _config: &CompileConfig) -> Result<PathBuf, SealError> {
            if let Some(output) = &self.output {
                Ok(output.clone())
            } else {
                Err(SealError::CompilationError(
                    self.error
                        .expect("test backend error should exist")
                        .to_string(),
                ))
            }
        }
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock should be after unix epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir should be creatable");
        dir
    }

    #[test]
    fn compile_agent_with_backend_propagates_backend_errors() {
        let backend = TestBackend {
            name: "failing",
            output: None,
            error: Some("backend failed"),
        };

        let err =
            compile_agent_with_backend(Path::new("/tmp/project"), Path::new("/tmp/out"), &backend)
                .expect_err("backend error should be returned");

        match err {
            SealError::CompilationError(message) => {
                assert!(message.contains("backend failed"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn compile_agent_with_backend_accepts_non_empty_output() {
        let temp_dir = unique_temp_dir("snapfzz-seal-compile-backend-success");
        let output_path = temp_dir.join("compiled.bin");
        std::fs::copy("/bin/ls", &output_path).expect("binary should be copied");

        let backend = TestBackend {
            name: "success",
            output: Some(output_path.clone()),
            error: None,
        };

        let result = compile_agent_with_backend(&temp_dir, &temp_dir, &backend)
            .expect("backend output should pass strip and non-empty checks");
        assert_eq!(result, output_path);
    }

    #[test]
    fn compile_agent_auto_reports_invalid_project_path_for_default_chain() {
        let output_dir = unique_temp_dir("snapfzz-seal-compile-chain-invalid-project");
        let err = compile_agent(Path::new("/"), &output_dir)
            .expect_err("invalid project should fail across default chain");

        match err {
            SealError::CompilationError(message) => {
                assert!(message.contains("no backend could compile project"));
                assert!(message.contains("/"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn run_strip_succeeds_for_valid_binary() {
        let temp_dir = unique_temp_dir("snapfzz-seal-compile-strip-success");
        let binary_path = temp_dir.join("ls-copy");
        std::fs::copy("/bin/ls", &binary_path).expect("binary should be copied");

        let result = run_strip(&binary_path);
        assert!(result.is_ok(), "strip on copied binary should succeed");
    }

    #[test]
    fn run_strip_fails_for_missing_input_file() {
        let temp_dir = unique_temp_dir("snapfzz-seal-compile-strip-failure");
        let missing_binary = temp_dir.join("does-not-exist.bin");

        let err = run_strip(&missing_binary).expect_err("strip should fail for missing file");
        match err {
            SealError::CompilationError(message) => {
                assert!(message.contains("strip failed"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn run_strip_returns_ok_when_strip_command_missing() {
        if std::env::var_os("SNAPFZZ_SEAL_TEST_STRIP_MISSING_CHILD").is_some() {
            let result = run_strip(Path::new("/this/path/is/never/read"));
            assert!(
                result.is_ok(),
                "missing strip command should be treated as non-fatal"
            );
            return;
        }

        let current_exe = std::env::current_exe().expect("current test binary path should resolve");
        let output = std::process::Command::new(current_exe)
            .arg("--exact")
            .arg("compile::tests::run_strip_returns_ok_when_strip_command_missing")
            .env("SNAPFZZ_SEAL_TEST_STRIP_MISSING_CHILD", "1")
            .env("PATH", "")
            .output()
            .expect("child test process should execute");

        assert!(
            output.status.success(),
            "child process should pass when strip is missing: stdout={}, stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn verify_non_empty_rejects_empty_file() {
        let temp_dir = unique_temp_dir("snapfzz-seal-compile-verify-empty");
        let binary_path = temp_dir.join("empty.bin");
        std::fs::write(&binary_path, b"").expect("empty test file should be writable");

        let err = verify_non_empty(&binary_path).expect_err("empty file should be rejected");
        match err {
            SealError::CompilationError(message) => {
                assert!(message.contains("compiled output is empty"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn verify_non_empty_rejects_non_file_path() {
        let temp_dir = unique_temp_dir("snapfzz-seal-compile-verify-non-file");

        let err = verify_non_empty(&temp_dir).expect_err("directory should be rejected");
        match err {
            SealError::CompilationError(message) => {
                assert!(message.contains("compiled output is not a file"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn verify_non_empty_accepts_non_empty_file() {
        let temp_dir = unique_temp_dir("snapfzz-seal-compile-verify-valid");
        let binary_path = temp_dir.join("valid.bin");
        std::fs::write(&binary_path, b"abc").expect("non-empty test file should be writable");

        verify_non_empty(&binary_path).expect("non-empty file should be accepted");
    }

    #[test]
    fn run_strip_returns_io_error_when_strip_is_not_executable() {
        if std::env::var_os("SNAPFZZ_SEAL_TEST_STRIP_PERMISSION_DENIED_CHILD").is_some() {
            let err = run_strip(Path::new("/bin/ls"))
                .expect_err("non-executable strip command should return io error");
            match err {
                SealError::Io(io) => {
                    assert_eq!(io.kind(), std::io::ErrorKind::PermissionDenied);
                }
                other => panic!("unexpected error: {other:?}"),
            }
            return;
        }

        let path_dir = unique_temp_dir("snapfzz-seal-compile-strip-permission-denied");
        let fake_strip = path_dir.join("strip");
        std::fs::write(&fake_strip, "#!/bin/sh\nexit 0\n")
            .expect("fake strip placeholder should be writable");

        let current_exe = std::env::current_exe().expect("current test binary path should resolve");
        let output = std::process::Command::new(current_exe)
            .arg("--exact")
            .arg("compile::tests::run_strip_returns_io_error_when_strip_is_not_executable")
            .env("SNAPFZZ_SEAL_TEST_STRIP_PERMISSION_DENIED_CHILD", "1")
            .env("PATH", &path_dir)
            .output()
            .expect("child test process should execute");

        assert!(
            output.status.success(),
            "child process should pass when strip is permission denied: stdout={}, stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn verify_non_empty_returns_io_error_for_missing_path() {
        let temp_dir = unique_temp_dir("snapfzz-seal-compile-verify-missing");
        let missing_path = temp_dir.join("missing.bin");

        let err =
            verify_non_empty(&missing_path).expect_err("missing path should surface io error");
        match err {
            SealError::Io(io) => {
                assert_eq!(io.kind(), std::io::ErrorKind::NotFound);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
