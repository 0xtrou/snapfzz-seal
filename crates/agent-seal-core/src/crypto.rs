use crate::{constants::CHUNK_SIZE, error::SealError};
use aead_stream::{DecryptorBE32, EncryptorBE32, Key, Nonce};
use aes_gcm::Aes256Gcm;
use rand::{RngCore, rngs::OsRng};
use std::io::Read;
use zeroize::Zeroize;

const STREAM_NONCE_SIZE: usize = 7;
const TAG_SIZE: usize = 16;
const ENCRYPTED_CHUNK_SIZE: usize = CHUNK_SIZE + TAG_SIZE;

pub fn encrypt_stream(mut plaintext: impl Read, key: &[u8; 32]) -> Result<Vec<u8>, SealError> {
    let mut key_copy = *key;
    let mut stream_nonce = [0_u8; STREAM_NONCE_SIZE];
    OsRng.fill_bytes(&mut stream_nonce);

    let key_array = Key::<Aes256Gcm>::from(key_copy);
    let nonce_array = Nonce::<Aes256Gcm, aead_stream::StreamBE32<Aes256Gcm>>::from(stream_nonce);
    let mut encryptor = EncryptorBE32::<Aes256Gcm>::new(&key_array, &nonce_array);

    let mut output = Vec::with_capacity(STREAM_NONCE_SIZE);
    output.extend_from_slice(&stream_nonce);

    let first_chunk = read_chunk(&mut plaintext, CHUNK_SIZE)?;
    match first_chunk {
        None => {
            let empty: &[u8] = &[];
            let encrypted = encryptor
                .encrypt_last(empty)
                .map_err(|err| SealError::EncryptionFailed(err.to_string()))?;
            output.extend_from_slice(&encrypted);
        }
        Some(mut current) => loop {
            match read_chunk(&mut plaintext, CHUNK_SIZE)? {
                Some(next) => {
                    let encrypted = encryptor
                        .encrypt_next(current.as_slice())
                        .map_err(|err| SealError::EncryptionFailed(err.to_string()))?;
                    output.extend_from_slice(&encrypted);
                    current.zeroize();
                    current = next;
                }
                None => {
                    let encrypted = encryptor
                        .encrypt_last(current.as_slice())
                        .map_err(|err| SealError::EncryptionFailed(err.to_string()))?;
                    output.extend_from_slice(&encrypted);
                    current.zeroize();
                    break;
                }
            }
        },
    }

    key_copy.zeroize();
    stream_nonce.zeroize();
    Ok(output)
}

pub fn decrypt_stream(mut ciphertext: impl Read, key: &[u8; 32]) -> Result<Vec<u8>, SealError> {
    let mut key_copy = *key;
    let mut stream_nonce = [0_u8; STREAM_NONCE_SIZE];
    ciphertext
        .read_exact(&mut stream_nonce)
        .map_err(|err| SealError::DecryptionFailed(format!("failed to read nonce: {err}")))?;

    let key_array = Key::<Aes256Gcm>::from(key_copy);
    let nonce_array = Nonce::<Aes256Gcm, aead_stream::StreamBE32<Aes256Gcm>>::from(stream_nonce);
    let mut decryptor = DecryptorBE32::<Aes256Gcm>::new(&key_array, &nonce_array);
    let mut output = Vec::new();

    let first_segment = read_chunk(&mut ciphertext, ENCRYPTED_CHUNK_SIZE)?;
    let mut current = first_segment.ok_or_else(|| {
        SealError::DecryptionFailed("ciphertext missing encrypted payload".to_string())
    })?;

    loop {
        match read_chunk(&mut ciphertext, ENCRYPTED_CHUNK_SIZE)? {
            Some(next) => {
                if current.len() != ENCRYPTED_CHUNK_SIZE {
                    current.zeroize();
                    return Err(SealError::DecryptionFailed(
                        "truncated ciphertext chunk before final segment".to_string(),
                    ));
                }

                let decrypted = decryptor
                    .decrypt_next(current.as_slice())
                    .map_err(|err| SealError::DecryptionFailed(err.to_string()))?;
                output.extend_from_slice(&decrypted);
                current.zeroize();
                current = next;
            }
            None => {
                let decrypted = decryptor
                    .decrypt_last(current.as_slice())
                    .map_err(|err| SealError::DecryptionFailed(err.to_string()))?;
                output.extend_from_slice(&decrypted);
                current.zeroize();
                break;
            }
        }
    }

    key_copy.zeroize();
    stream_nonce.zeroize();
    Ok(output)
}

fn read_chunk(reader: &mut impl Read, max_len: usize) -> Result<Option<Vec<u8>>, SealError> {
    let mut chunk = Vec::with_capacity(max_len);
    let mut buffer = [0_u8; 8192];

    while chunk.len() < max_len {
        let to_read = (max_len - chunk.len()).min(buffer.len());
        let read = reader.read(&mut buffer[..to_read])?;
        if read == 0 {
            break;
        }
        chunk.extend_from_slice(&buffer[..read]);
    }

    buffer.zeroize();
    if chunk.is_empty() {
        Ok(None)
    } else {
        Ok(Some(chunk))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn patterned_bytes(len: usize) -> Vec<u8> {
        (0..len).map(|idx| (idx % 251) as u8).collect()
    }

    #[test]
    fn round_trip_encrypts_and_decrypts_1kb() {
        let key = [7_u8; 32];
        let plaintext = patterned_bytes(1024);

        let encrypted =
            encrypt_stream(Cursor::new(&plaintext), &key).expect("encryption should work");
        let decrypted =
            decrypt_stream(Cursor::new(encrypted), &key).expect("decryption should work");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn round_trip_encrypts_and_decrypts_1mb() {
        let key = [9_u8; 32];
        let plaintext = patterned_bytes(1024 * 1024);

        let encrypted =
            encrypt_stream(Cursor::new(&plaintext), &key).expect("encryption should work");
        let decrypted =
            decrypt_stream(Cursor::new(encrypted), &key).expect("decryption should work");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn round_trip_encrypts_and_decrypts_10mb() {
        let key = [11_u8; 32];
        let plaintext = patterned_bytes(10 * 1024 * 1024);

        let encrypted =
            encrypt_stream(Cursor::new(&plaintext), &key).expect("encryption should work");
        let decrypted =
            decrypt_stream(Cursor::new(encrypted), &key).expect("decryption should work");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn round_trip_encrypts_and_decrypts_empty_payload() {
        let key = [5_u8; 32];
        let plaintext = Vec::<u8>::new();

        let encrypted =
            encrypt_stream(Cursor::new(&plaintext), &key).expect("encryption should work");
        let decrypted =
            decrypt_stream(Cursor::new(encrypted), &key).expect("decryption should work");

        assert!(decrypted.is_empty());
    }

    #[test]
    fn wrong_key_returns_decryption_failed() {
        let key = [1_u8; 32];
        let wrong_key = [2_u8; 32];
        let plaintext = patterned_bytes(2048);

        let encrypted =
            encrypt_stream(Cursor::new(&plaintext), &key).expect("encryption should work");
        let err =
            decrypt_stream(Cursor::new(encrypted), &wrong_key).expect_err("wrong key should fail");

        match err {
            SealError::DecryptionFailed(message) => {
                assert!(!message.is_empty());
            }
            other => panic!("expected decryption failure, got {other:?}"),
        }
    }

    #[test]
    fn truncated_ciphertext_returns_decryption_failed() {
        let key = [3_u8; 32];
        let plaintext = patterned_bytes(4096);

        let mut encrypted =
            encrypt_stream(Cursor::new(&plaintext), &key).expect("encryption should work");
        encrypted.truncate(encrypted.len().saturating_sub(8));

        let err = decrypt_stream(Cursor::new(encrypted), &key)
            .expect_err("truncated ciphertext should fail");
        assert!(matches!(err, SealError::DecryptionFailed(_)));
    }
}
