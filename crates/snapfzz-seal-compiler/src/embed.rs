use snapfzz_seal_core::{
    error::SealError,
    shamir::split_secret,
    types::{LAUNCHER_TAMPER_MARKER, SHAMIR_THRESHOLD, SHAMIR_TOTAL_SHARES, get_secret_marker},
};

pub fn embed_master_secret(launcher_bytes: &[u8], secret: &[u8; 32]) -> Result<Vec<u8>, SealError> {
    embed_master_secret_with_shamir(launcher_bytes, secret)
}

pub fn embed_master_secret_with_shamir(
    launcher_bytes: &[u8],
    secret: &[u8; 32],
) -> Result<Vec<u8>, SealError> {
    let shares = split_secret(secret, SHAMIR_THRESHOLD, SHAMIR_TOTAL_SHARES)
        .map_err(|e| embed_failed(&format!("shamir split failed: {e}")))?;

    let mut modified = launcher_bytes.to_vec();

    for (i, (_x, share)) in shares.iter().enumerate() {
        let marker = get_secret_marker(i);
        let marker_offset = find_marker(&modified, marker)
            .ok_or_else(|| embed_failed(&format!("marker {} not found", i + 1)))?;

        let share_offset = marker_offset + marker.len();
        let end_offset = share_offset + share.len();
        if modified.len() < end_offset {
            return Err(embed_failed(&format!(
                "launcher too small for share slot {}",
                i + 1
            )));
        }

        modified[share_offset..end_offset].copy_from_slice(share);
    }

    Ok(modified)
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
    use snapfzz_seal_core::{
        shamir::reconstruct_secret,
        types::{LAUNCHER_TAMPER_MARKER, SHAMIR_THRESHOLD, SHAMIR_TOTAL_SHARES, get_secret_marker},
    };

    fn launcher_with_share_slots(slot_len: usize) -> Vec<u8> {
        let mut launcher = vec![0xAA; 64];
        for i in 0..SHAMIR_TOTAL_SHARES {
            launcher.extend_from_slice(get_secret_marker(i));
            launcher.extend_from_slice(&vec![0_u8; slot_len]);
            launcher.extend_from_slice(&[0xA0 + i as u8; 7]);
        }
        launcher.extend_from_slice(LAUNCHER_TAMPER_MARKER);
        launcher.extend_from_slice(&[0x11_u8; 32]);
        launcher.extend_from_slice(&[0xBB; 64]);
        launcher
    }

    #[test]
    fn embed_master_secret_replaces_all_five_secret_share_slots() {
        let launcher = launcher_with_share_slots(32);
        let secret = [0x0C; 32];

        let modified = embed_master_secret(&launcher, &secret).expect("embed should succeed");

        let mut shares = Vec::new();
        for i in 0..SHAMIR_TOTAL_SHARES {
            let marker = get_secret_marker(i);
            let marker_offset = find_marker(&modified, marker).expect("marker should remain");
            let share_start = marker_offset + marker.len();
            let mut share = [0u8; 32];
            share.copy_from_slice(&modified[share_start..share_start + 32]);
            shares.push(((i + 1) as u8, share));
        }

        assert_eq!(shares.len(), 5);
        let recovered = reconstruct_secret(&shares[1..4], SHAMIR_THRESHOLD).unwrap();
        assert_eq!(recovered, secret);

        let tamper_marker_offset =
            find_marker(&modified, LAUNCHER_TAMPER_MARKER).expect("tamper marker exists");
        let tamper_start = tamper_marker_offset + LAUNCHER_TAMPER_MARKER.len();
        assert_eq!(&modified[tamper_start..tamper_start + 32], &[0x11_u8; 32]);
    }

    #[test]
    fn embed_tamper_hash_replaces_bytes_after_tamper_marker() {
        let launcher = launcher_with_share_slots(32);

        let hash = [0x44; 32];
        let modified = embed_tamper_hash(&launcher, &hash).expect("embed should succeed");

        let tamper_start =
            find_marker(&modified, LAUNCHER_TAMPER_MARKER).unwrap() + LAUNCHER_TAMPER_MARKER.len();
        assert_eq!(&modified[tamper_start..tamper_start + 32], &hash);
    }

    #[test]
    fn embed_returns_error_when_any_secret_marker_is_missing() {
        let err =
            embed_master_secret(&[1_u8; 64], &[2_u8; 32]).expect_err("missing marker should fail");

        match err {
            SealError::CompilationError(message) => {
                assert!(message.contains("EmbedFailed: marker 1 not found"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn embed_tamper_hash_returns_error_when_marker_missing() {
        let err = embed_tamper_hash(&[1_u8; 64], &[3_u8; 32])
            .expect_err("missing tamper marker should fail");

        match err {
            SealError::CompilationError(message) => {
                assert!(message.contains("EmbedFailed: marker not found"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn embed_master_secret_returns_error_when_any_share_slot_is_too_short() {
        let launcher = launcher_with_share_slots(8);

        let err = embed_master_secret(&launcher, &[0x55_u8; 32])
            .expect_err("insufficient bytes after marker should fail");

        match err {
            SealError::CompilationError(message) => {
                assert!(message.contains("EmbedFailed:"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
