#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "linux")]
mod linux;

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
use agent_seal_core::error::SealError;

#[cfg(target_os = "macos")]
#[allow(unused_imports)]
pub use macos::self_delete;

#[cfg(target_os = "linux")]
#[allow(unused_imports)]
pub use linux::self_delete;

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn self_delete() -> Result<(), SealError> {
    Ok(())
}
