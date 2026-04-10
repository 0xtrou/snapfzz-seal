use crate::error::SealError;
use subtle::ConstantTimeEq;

use sha2::{Digest, Sha256};
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::Read;

/// Compute SHA-256 hash of arbitrary bytes.
/// Used for launcher portion tamper verification.
pub fn compute_hash_of_bytes(bytes: &[u8]) -> [u8; 32] {
    let hash = Sha256::digest(bytes);
    let mut out = [0_u8; 32];
    out.copy_from_slice(&hash);
    out
}

#[cfg(target_os = "linux")]
pub fn compute_binary_hash() -> Result<[u8; 32], SealError> {
    let mut file = File::open("/proc/self/exe")?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];

    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    let hash = hasher.finalize();
    let mut out = [0_u8; 32];
    out.copy_from_slice(&hash);
    Ok(out)
}

#[cfg(not(target_os = "linux"))]
pub fn compute_binary_hash() -> Result<[u8; 32], SealError> {
    Err(SealError::Io(std::io::Error::other(
        "tamper verification requires Linux: /proc/self/exe is unavailable on this platform",
    )))
}

pub fn verify_tamper(expected_hash: &[u8]) -> Result<(), SealError> {
    if expected_hash.len() != 32 {
        return Err(SealError::InvalidInput(
            "expected hash must be exactly 32 bytes".to_string(),
        ));
    }

    let current_hash = compute_binary_hash()?;
    if current_hash.ct_eq(expected_hash).into() {
        Ok(())
    } else {
        Err(SealError::TamperDetected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use sha2::{Digest, Sha256};

    #[test]
    fn compute_hash_of_bytes_matches_sha256_for_various_sizes() {
        for len in [0_usize, 1, 31, 32, 33, 256, 4096, 65_537] {
            let input: Vec<u8> = (0..len).map(|idx| ((idx * 17 + 3) % 251) as u8).collect();
            let computed = compute_hash_of_bytes(&input);

            let expected = Sha256::digest(&input);
            let mut expected_arr = [0_u8; 32];
            expected_arr.copy_from_slice(&expected);

            assert_eq!(computed, expected_arr, "hash mismatch for input len={len}");
        }
    }

    #[test]
    fn compute_hash_of_bytes_is_deterministic_and_input_sensitive() {
        let a = vec![0xAB; 1024];
        let mut b = a.clone();
        b[17] ^= 0x01;

        let hash_a_first = compute_hash_of_bytes(&a);
        let hash_a_second = compute_hash_of_bytes(&a);
        let hash_b = compute_hash_of_bytes(&b);

        assert_eq!(hash_a_first, hash_a_second);
        assert_ne!(hash_a_first, hash_b);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn binary_hash_is_32_bytes() {
        let hash = compute_binary_hash().expect("hash should be computed on linux");
        assert_eq!(hash.len(), 32);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn binary_hash_requires_linux() {
        let err = compute_binary_hash().expect_err("should fail on non-linux");
        match err {
            SealError::Io(io_err) => {
                assert!(io_err.to_string().contains("requires Linux"));
            }
            other => panic!("expected io error, got {other:?}"),
        }
    }

    #[test]
    fn verify_tamper_rejects_wrong_hash_length() {
        let err = verify_tamper(&[0_u8; 31]).expect_err("31-byte hash must be rejected");
        match err {
            SealError::InvalidInput(message) => {
                assert!(message.contains("exactly 32 bytes"));
            }
            other => panic!("expected invalid input, got {other:?}"),
        }
    }

    #[test]
    fn verify_tamper_rejects_too_long_hash_length() {
        let err = verify_tamper(&[0_u8; 33]).expect_err("33-byte hash must be rejected");
        assert!(matches!(err, SealError::InvalidInput(_)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn verify_tamper_detects_mismatch_on_linux() {
        let err = verify_tamper(&[0_u8; 32]).expect_err("wrong hash should be detected");
        assert!(matches!(err, SealError::TamperDetected));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn verify_tamper_detects_near_match_mismatch_on_linux() {
        let mut hash = compute_binary_hash().expect("hash should be computed on linux");
        hash[0] ^= 0x01;

        let err = verify_tamper(&hash).expect_err("bit-flipped hash should be rejected");
        assert!(matches!(err, SealError::TamperDetected));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn verify_tamper_accepts_current_binary_hash_on_linux() {
        let hash = compute_binary_hash().expect("hash should be computed on linux");
        verify_tamper(&hash).expect("current binary hash should verify");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn verify_tamper_propagates_io_error_on_non_linux() {
        let err = verify_tamper(&[7_u8; 32]).expect_err("non-linux should propagate io error");
        match err {
            SealError::Io(io_err) => {
                assert!(io_err.to_string().contains("requires Linux"));
            }
            other => panic!("expected io error, got {other:?}"),
        }
    }

    #[test]
    fn verify_tamper_rejects_empty_hash_length() {
        let err = verify_tamper(&[]).expect_err("empty hash must be rejected");
        assert!(matches!(err, SealError::InvalidInput(_)));
    }
}
