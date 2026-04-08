#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "linux")]
mod linux;

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
use agent_seal_core::error::SealError;

#[cfg(target_os = "macos")]
#[allow(unused_imports)]
pub use macos::apply_protections;

#[cfg(target_os = "linux")]
#[allow(unused_imports)]
pub use linux::apply_protections;

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn apply_protections() -> Result<Vec<String>, SealError> {
    Ok(vec!["no-platform-protections".to_string()])
}
