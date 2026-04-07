use agent_seal_core::{
    error::SealError,
    types::{LAUNCHER_SECRET_MARKER, LAUNCHER_TAMPER_MARKER},
};

pub fn embed_master_secret(launcher_bytes: &[u8], secret: &[u8; 32]) -> Result<Vec<u8>, SealError> {
    replace_after_marker(launcher_bytes, LAUNCHER_SECRET_MARKER, secret)
}

pub fn embed_tamper_hash(launcher_bytes: &[u8], hash: &[u8; 32]) -> Result<Vec<u8>, SealError> {
    replace_after_marker(launcher_bytes, LAUNCHER_TAMPER_MARKER, hash)
}

fn replace_after_marker(
    launcher_bytes: &[u8],
    marker: &[u8],
    replacement: &[u8; 32],
) -> Result<Vec<u8>, SealError> {
    let Some(marker_offset) = find_marker(launcher_bytes, marker) else {
        return Err(embed_failed("marker not found"));
    };

    let payload_offset = marker_offset + marker.len();
    let end_offset = payload_offset + replacement.len();
    if launcher_bytes.len() < end_offset {
        return Err(embed_failed("launcher too small for embedded payload"));
    }

    let mut modified = launcher_bytes.to_vec();
    modified[payload_offset..end_offset].copy_from_slice(replacement);
    Ok(modified)
}

fn find_marker(haystack: &[u8], marker: &[u8]) -> Option<usize> {
    haystack
        .windows(marker.len())
        .position(|window| window == marker)
}

fn embed_failed(detail: &str) -> SealError {
    SealError::CompilationError(format!("EmbedFailed: {detail}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embed_master_secret_replaces_bytes_after_secret_marker() {
        let mut launcher = vec![0xAA; 64];
        launcher.extend_from_slice(LAUNCHER_SECRET_MARKER);
        launcher.extend_from_slice(&[0_u8; 32]);
        launcher.extend_from_slice(LAUNCHER_TAMPER_MARKER);
        launcher.extend_from_slice(&[0x11_u8; 32]);
        launcher.extend_from_slice(&[0xBB; 64]);

        let secret = [0xCC; 32];
        let modified = embed_master_secret(&launcher, &secret).expect("embed should succeed");

        let secret_start = 64 + LAUNCHER_SECRET_MARKER.len();
        assert_eq!(&modified[secret_start..secret_start + 32], &secret);

        let tamper_start = 64 + LAUNCHER_SECRET_MARKER.len() + 32 + LAUNCHER_TAMPER_MARKER.len();
        assert_eq!(&modified[tamper_start..tamper_start + 32], &[0x11_u8; 32]);
    }

    #[test]
    fn embed_tamper_hash_replaces_bytes_after_tamper_marker() {
        let mut launcher = vec![0x10; 8];
        launcher.extend_from_slice(LAUNCHER_SECRET_MARKER);
        launcher.extend_from_slice(&[0x22_u8; 32]);
        launcher.extend_from_slice(LAUNCHER_TAMPER_MARKER);
        launcher.extend_from_slice(&[0_u8; 32]);
        launcher.extend_from_slice(&[0x20; 8]);

        let hash = [0x44; 32];
        let modified = embed_tamper_hash(&launcher, &hash).expect("embed should succeed");

        let tamper_start = 8 + LAUNCHER_SECRET_MARKER.len() + 32 + LAUNCHER_TAMPER_MARKER.len();
        assert_eq!(&modified[tamper_start..tamper_start + 32], &hash);

        let secret_start = 8 + LAUNCHER_SECRET_MARKER.len();
        assert_eq!(&modified[secret_start..secret_start + 32], &[0x22_u8; 32]);
    }

    #[test]
    fn embed_returns_error_when_marker_missing() {
        let err =
            embed_master_secret(&[1_u8; 64], &[2_u8; 32]).expect_err("missing marker should fail");

        assert!(matches!(err, SealError::CompilationError(_)));
    }
}
