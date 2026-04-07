use crate::{
    nuitka::{NuitkaConfig, compile_with_nuitka},
    pyinstaller::{PyInstallerConfig, compile_with_pyinstaller},
};
use agent_seal_core::error::SealError;
use std::{
    path::{Path, PathBuf},
    process::Command,
};
use tracing::warn;

#[derive(Debug, Clone, PartialEq)]
pub enum Backend {
    Nuitka,
    PyInstaller,
}

pub fn compile_agent(
    project_dir: &Path,
    output_dir: &Path,
    backend: Backend,
) -> Result<PathBuf, SealError> {
    compile_agent_with_backends(
        project_dir,
        output_dir,
        backend,
        |project_dir, output_dir| {
            let nuitka_cfg = NuitkaConfig {
                project_dir: project_dir.to_path_buf(),
                output_dir: output_dir.to_path_buf(),
                ..NuitkaConfig::default()
            };
            compile_with_nuitka(&nuitka_cfg)
        },
        |project_dir, output_dir| {
            let pyinstaller_cfg = PyInstallerConfig {
                project_dir: project_dir.to_path_buf(),
                output_dir: output_dir.to_path_buf(),
                onefile: true,
                timeout_secs: 1_800,
            };
            compile_with_pyinstaller(&pyinstaller_cfg)
        },
    )
}

fn compile_agent_with_backends<FN, FP>(
    project_dir: &Path,
    output_dir: &Path,
    backend: Backend,
    compile_nuitka: FN,
    compile_pyinstaller: FP,
) -> Result<PathBuf, SealError>
where
    FN: Fn(&Path, &Path) -> Result<PathBuf, SealError>,
    FP: Fn(&Path, &Path) -> Result<PathBuf, SealError>,
{
    let output = match backend {
        Backend::Nuitka => match compile_nuitka(project_dir, output_dir) {
            Ok(path) => path,
            Err(_nuitka_err) => {
                warn!("nuitka compilation failed, falling back to pyinstaller: {_nuitka_err}");
                compile_pyinstaller(project_dir, output_dir)?
            }
        },
        Backend::PyInstaller => compile_pyinstaller(project_dir, output_dir)?,
    };

    run_strip(&output)?;
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
                Err(SealError::CompilationError(format!(
                    "strip failed for {}: {}",
                    binary_path.display(),
                    stderr.trim()
                )))
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

    #[test]
    fn backend_variants_compare_as_expected() {
        assert_eq!(Backend::Nuitka, Backend::Nuitka);
        assert_eq!(Backend::PyInstaller, Backend::PyInstaller);
        assert_ne!(Backend::Nuitka, Backend::PyInstaller);
    }

    #[test]
    fn compile_agent_returns_error_when_no_backend_available() {
        let project_dir = PathBuf::from("/tmp/project");
        let output_dir = std::env::temp_dir().join("agent-seal-compile-no-backend-test");

        let err = compile_agent_with_backends(
            &project_dir,
            &output_dir,
            Backend::Nuitka,
            |_project_dir, _output_dir| {
                Err(SealError::CompilationError("nuitka not found".to_string()))
            },
            |_project_dir, _output_dir| {
                Err(SealError::CompilationError(
                    "pyinstaller not found".to_string(),
                ))
            },
        )
        .expect_err("both backend failures should bubble up as error");

        match err {
            SealError::CompilationError(message) => {
                assert!(message.contains("pyinstaller not found"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
