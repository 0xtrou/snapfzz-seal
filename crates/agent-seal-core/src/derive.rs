use crate::{
    constants::{KDF_INFO_ENV, KDF_INFO_SESSION},
    error::SealError,
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

pub fn derive_env_key(
    master_secret: &[u8; 32],
    stable_hash: &[u8; 32],
    user_fingerprint: &[u8; 32],
) -> Result<[u8; 32], SealError> {
    validate_32("master_secret", master_secret)?;
    validate_32("stable_hash", stable_hash)?;
    validate_32("user_fingerprint", user_fingerprint)?;

    let mut fingerprint_ikm = [0_u8; 64];
    fingerprint_ikm[..32].copy_from_slice(stable_hash);
    fingerprint_ikm[32..].copy_from_slice(user_fingerprint);

    let out = hkdf_expand_32(master_secret, &fingerprint_ikm, KDF_INFO_ENV)?;
    fingerprint_ikm.zeroize();
    Ok(out)
}

pub fn derive_session_key(
    env_key: &[u8; 32],
    ephemeral_hash: &[u8; 32],
) -> Result<[u8; 32], SealError> {
    validate_32("env_key", env_key)?;
    validate_32("ephemeral_hash", ephemeral_hash)?;
    hkdf_expand_32(env_key, ephemeral_hash, KDF_INFO_SESSION)
}

fn hkdf_expand_32(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; 32], SealError> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut output = [0_u8; 32];
    hkdf.expand(info, &mut output)
        .map_err(|_| SealError::InvalidInput("hkdf expansion failed".to_string()))?;
    Ok(output)
}

fn validate_32(label: &str, value: &[u8]) -> Result<(), SealError> {
    if value.len() != 32 {
        return Err(SealError::InvalidInput(format!(
            "{label} must be exactly 32 bytes"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hkdf::Hkdf;
    use sha2::{Digest, Sha256};

    #[test]
    fn same_inputs_produce_same_output() {
        let master_secret = [1_u8; 32];
        let stable_hash = [2_u8; 32];
        let user_fingerprint = [3_u8; 32];

        let a = derive_env_key(&master_secret, &stable_hash, &user_fingerprint)
            .expect("derivation should work");
        let b = derive_env_key(&master_secret, &stable_hash, &user_fingerprint)
            .expect("derivation should work");

        assert_eq!(a, b);
    }

    #[test]
    fn different_user_fingerprint_produces_different_env_key() {
        let master_secret = [1_u8; 32];
        let stable_hash = [2_u8; 32];

        let key_a = derive_env_key(&master_secret, &stable_hash, &[3_u8; 32])
            .expect("derivation should work");
        let key_b = derive_env_key(&master_secret, &stable_hash, &[4_u8; 32])
            .expect("derivation should work");

        assert_ne!(key_a, key_b);
    }

    #[test]
    fn rfc5869_test_case_1_matches_reference_output() {
        let ikm = [0x0b_u8; 22];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];

        let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut okm = [0_u8; 42];
        hkdf.expand(&info, &mut okm)
            .expect("rfc vector expansion should work");

        let expected_okm = hex::decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        )
        .expect("hex decode should work");
        assert_eq!(okm.as_slice(), expected_okm.as_slice());

        let prk_hasher = hmac_sha256(&salt, &ikm);
        let expected_prk =
            hex::decode("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
                .expect("hex decode should work");
        assert_eq!(prk_hasher.as_slice(), expected_prk.as_slice());
    }

    fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
        const BLOCK_SIZE: usize = 64;
        let mut key_block = [0_u8; BLOCK_SIZE];

        if key.len() > BLOCK_SIZE {
            let digest = Sha256::digest(key);
            key_block[..32].copy_from_slice(&digest);
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }

        let mut o_key_pad = [0x5c_u8; BLOCK_SIZE];
        let mut i_key_pad = [0x36_u8; BLOCK_SIZE];

        for idx in 0..BLOCK_SIZE {
            o_key_pad[idx] ^= key_block[idx];
            i_key_pad[idx] ^= key_block[idx];
        }

        let mut inner = Sha256::new();
        inner.update(i_key_pad);
        inner.update(data);
        let inner_hash = inner.finalize();

        let mut outer = Sha256::new();
        outer.update(o_key_pad);
        outer.update(inner_hash);
        let result = outer.finalize();

        let mut out = [0_u8; 32];
        out.copy_from_slice(&result);
        out
    }
}
