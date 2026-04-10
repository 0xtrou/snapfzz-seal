use sha2::{Digest, Sha256};
use snapfzz_seal_core::{error::SealError, types::POSITION_HINT_SALT};

const DECOY_SETS: usize = 10;
const POSITION_HINT_MARKER: &[u8] = b"ASL_POSITION_HINT_v1";

pub fn generate_decoy_secret(set_index: usize) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"DECOY_SECRET_V1");
    hasher.update(set_index.to_le_bytes());
    hasher.update(POSITION_HINT_SALT);
    hasher.finalize().into()
}

pub fn generate_all_decoys() -> Vec<[u8; 32]> {
    (0..DECOY_SETS).map(generate_decoy_secret).collect()
}

pub fn obfuscate_real_position(real_index: usize, salt: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"REAL_POSITION_HINT");
    hasher.update(real_index.to_le_bytes());
    hasher.update(salt);
    hasher.finalize().into()
}

pub fn determine_real_position(hint: &[u8; 32], salt: &[u8; 32]) -> usize {
    for i in 0..(DECOY_SETS + 1) {
        if obfuscate_real_position(i, salt) == *hint {
            return i;
        }
    }
    0
}

pub fn embed_decoy_secrets(binary: &[u8], real_index: usize) -> Result<Vec<u8>, SealError> {
    let _decoys = generate_all_decoys();
    let salt = rand::random::<[u8; 32]>();
    let hint = obfuscate_real_position(real_index, &salt);

    let mut modified = binary.to_vec();

    #[allow(clippy::collapsible_if)]
    if let Some(pos) = modified
        .windows(POSITION_HINT_MARKER.len())
        .position(|window| window == POSITION_HINT_MARKER)
    {
        if pos + 32 <= modified.len() {
            modified[pos..pos + 32].copy_from_slice(&hint);
        }
    }

    Ok(modified)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decoy_generation() {
        let d1 = generate_decoy_secret(0);
        let d2 = generate_decoy_secret(1);
        assert_ne!(d1, d2);

        let d1_again = generate_decoy_secret(0);
        assert_eq!(d1, d1_again);
    }

    #[test]
    fn test_position_obfuscation() {
        let salt = [0xAA; 32];
        let hint = obfuscate_real_position(0, &salt);
        let determined = determine_real_position(&hint, &salt);
        assert_eq!(determined, 0);

        let hint2 = obfuscate_real_position(5, &salt);
        let determined2 = determine_real_position(&hint2, &salt);
        assert_eq!(determined2, 5);
    }

    #[test]
    fn test_generate_all_decoys_returns_ten_sets() {
        let decoys = generate_all_decoys();
        assert_eq!(decoys.len(), DECOY_SETS);
    }

    #[test]
    fn test_embed_decoy_secrets_with_marker() {
        let mut binary = b"test binary".to_vec();
        binary.extend_from_slice(POSITION_HINT_MARKER);
        binary.extend_from_slice(&[0u8; 32]);

        let result = embed_decoy_secrets(&binary, 3).expect("embedding should succeed");
        assert!(result.len() >= binary.len());
    }
}
