use agent_seal_core::error::SealError;
use std::ffi::CStr;

#[allow(dead_code)]
pub fn self_delete() -> Result<(), SealError> {
    let argv0 = unsafe { libc::getprogname() };
    if argv0.is_null() {
        tracing::warn!("getprogname returned null, skipping self-delete");
        return Ok(());
    }

    let path = unsafe { CStr::from_ptr(argv0) };
    let path_str = path.to_string_lossy();
    let path = std::path::Path::new(&*path_str);

    if path.exists() {
        match std::fs::remove_file(path) {
            Ok(()) => tracing::info!("self-delete: removed {}", path_str),
            Err(err) => tracing::warn!("self-delete failed for {}: {}", path_str, err),
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn self_delete_symbol_is_available_on_macos() {
        let func: fn() -> Result<(), SealError> = self_delete;
        let _ = func;
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn self_delete_returns_result_on_macos() {
        let result = self_delete();
        assert!(result.is_ok());
    }
}
