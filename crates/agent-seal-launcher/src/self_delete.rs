use agent_seal_core::error::SealError;

pub fn self_delete() -> Result<(), SealError> {
    let executable_path = std::fs::read_link("/proc/self/exe")?;

    if !executable_path.exists() {
        return Ok(());
    }

    match std::fs::remove_file(&executable_path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            tracing::warn!(
                "self-delete skipped due to permission denied (likely overlayfs): {}",
                executable_path.display()
            );
            Ok(())
        }
        Err(err) => Err(SealError::Io(err)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_delete_symbol_is_available() {
        let func: fn() -> Result<(), SealError> = self_delete;
        let _ = func;
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn self_delete_test_skipped_on_non_linux() {
        assert!(true);
    }
}
