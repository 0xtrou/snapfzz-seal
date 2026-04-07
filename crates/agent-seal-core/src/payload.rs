use crate::{
    constants::{CHUNK_SIZE, ENC_ALG_AES256_GCM, FMT_STREAM, MAGIC_BYTES, VERSION_V1},
    crypto::{decrypt_stream, encrypt_stream},
    error::SealError,
    types::PayloadHeader,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io::{Cursor, Read};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

const HEADER_SIZE: usize = 4 + 2 + 2 + 2 + 4 + 32;
const NONCE_SIZE: usize = 7;

pub fn pack_payload(mut plaintext: impl Read, key: &[u8; 32]) -> Result<Vec<u8>, SealError> {
    let mut plaintext_bytes = Vec::new();
    plaintext.read_to_end(&mut plaintext_bytes)?;

    let encrypted_bytes = encrypt_stream(Cursor::new(&plaintext_bytes), key)?;

    if encrypted_bytes.len() < NONCE_SIZE {
        return Err(SealError::EncryptionFailed(
            "encrypted payload missing stream nonce".to_string(),
        ));
    }

    let chunk_count = if plaintext_bytes.is_empty() {
        0
    } else {
        plaintext_bytes.len().div_ceil(CHUNK_SIZE) as u32
    };

    let header_hmac = compute_header_hmac(
        &MAGIC_BYTES,
        VERSION_V1,
        ENC_ALG_AES256_GCM,
        FMT_STREAM,
        chunk_count,
        key,
    );

    let header = PayloadHeader {
        magic: MAGIC_BYTES,
        version: VERSION_V1,
        enc_alg: ENC_ALG_AES256_GCM,
        fmt_version: FMT_STREAM,
        chunk_count,
        header_hmac,
    };

    let mut out = Vec::with_capacity(HEADER_SIZE + encrypted_bytes.len());
    out.extend_from_slice(&serialize_header(&header));
    out.extend_from_slice(&encrypted_bytes);
    Ok(out)
}

pub fn unpack_payload(
    mut payload: impl Read,
    key: &[u8; 32],
) -> Result<(Vec<u8>, PayloadHeader), SealError> {
    let mut payload_bytes = Vec::new();
    payload.read_to_end(&mut payload_bytes)?;

    if payload_bytes.len() < HEADER_SIZE {
        return Err(SealError::InvalidPayload(
            "payload too small to contain header and encrypted body".to_string(),
        ));
    }

    let header = parse_header(&payload_bytes[..HEADER_SIZE])?;

    let expected_hmac = compute_header_hmac(
        &header.magic,
        header.version,
        header.enc_alg,
        header.fmt_version,
        header.chunk_count,
        key,
    );

    if !bool::from(header.header_hmac.ct_eq(&expected_hmac)) {
        return Err(SealError::DecryptionFailed(
            "payload header authentication failed".to_string(),
        ));
    }

    let encrypted_bytes = &payload_bytes[HEADER_SIZE..];
    if encrypted_bytes.len() < NONCE_SIZE {
        return Err(SealError::InvalidPayload(
            "encrypted payload missing stream nonce".to_string(),
        ));
    }

    let decrypted = decrypt_stream(Cursor::new(encrypted_bytes), key)?;

    Ok((decrypted, header))
}

pub fn validate_payload_header(data: &[u8]) -> Result<PayloadHeader, SealError> {
    if data.len() < HEADER_SIZE {
        return Err(SealError::InvalidPayload(
            "insufficient bytes for payload header".to_string(),
        ));
    }

    parse_header(&data[..HEADER_SIZE])
}

fn parse_header(bytes: &[u8]) -> Result<PayloadHeader, SealError> {
    if bytes.len() != HEADER_SIZE {
        return Err(SealError::InvalidPayload(
            "payload header length mismatch".to_string(),
        ));
    }

    let mut offset = 0_usize;

    let mut magic = [0_u8; 4];
    magic.copy_from_slice(&bytes[offset..offset + 4]);
    offset += 4;
    if magic != MAGIC_BYTES {
        return Err(SealError::InvalidPayload(
            "invalid payload magic bytes".to_string(),
        ));
    }

    let version = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
    offset += 2;
    if version != VERSION_V1 {
        return Err(SealError::UnsupportedPayloadVersion(version));
    }

    let enc_alg = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
    offset += 2;
    if enc_alg != ENC_ALG_AES256_GCM {
        return Err(SealError::InvalidPayload(format!(
            "unsupported encryption algorithm: {enc_alg}"
        )));
    }

    let fmt_version = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
    offset += 2;
    if fmt_version != FMT_STREAM {
        return Err(SealError::InvalidPayload(format!(
            "unsupported payload format version: {fmt_version}"
        )));
    }

    let chunk_count = u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ]);
    offset += 4;

    let mut header_hmac = [0_u8; 32];
    header_hmac.copy_from_slice(&bytes[offset..offset + 32]);

    Ok(PayloadHeader {
        magic,
        version,
        enc_alg,
        fmt_version,
        chunk_count,
        header_hmac,
    })
}

fn serialize_header(header: &PayloadHeader) -> [u8; HEADER_SIZE] {
    let mut out = [0_u8; HEADER_SIZE];
    out[0..4].copy_from_slice(&header.magic);
    out[4..6].copy_from_slice(&header.version.to_le_bytes());
    out[6..8].copy_from_slice(&header.enc_alg.to_le_bytes());
    out[8..10].copy_from_slice(&header.fmt_version.to_le_bytes());
    out[10..14].copy_from_slice(&header.chunk_count.to_le_bytes());
    out[14..46].copy_from_slice(&header.header_hmac);
    out
}

fn serialize_header_without_hmac(
    magic: &[u8; 4],
    version: u16,
    enc_alg: u16,
    fmt_version: u16,
    chunk_count: u32,
) -> [u8; HEADER_SIZE - 32] {
    let mut out = [0_u8; HEADER_SIZE - 32];
    out[0..4].copy_from_slice(magic);
    out[4..6].copy_from_slice(&version.to_le_bytes());
    out[6..8].copy_from_slice(&enc_alg.to_le_bytes());
    out[8..10].copy_from_slice(&fmt_version.to_le_bytes());
    out[10..14].copy_from_slice(&chunk_count.to_le_bytes());
    out
}

fn compute_header_hmac(
    magic: &[u8; 4],
    version: u16,
    enc_alg: u16,
    fmt_version: u16,
    chunk_count: u32,
    key: &[u8; 32],
) -> [u8; 32] {
    let header_without_hmac =
        serialize_header_without_hmac(magic, version, enc_alg, fmt_version, chunk_count);
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(&header_without_hmac);

    let mut out = [0_u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, Mac};
    use std::io::Cursor;

    type TestHmacSha256 = Hmac<Sha256>;

    fn patterned_bytes(len: usize) -> Vec<u8> {
        (0..len).map(|idx| (idx % 241) as u8).collect()
    }

    #[test]
    fn pack_then_unpack_round_trip() {
        let key = [13_u8; 32];
        let plaintext = patterned_bytes(220_000);

        let payload = pack_payload(Cursor::new(&plaintext), &key).expect("pack should succeed");
        let (decrypted, header) =
            unpack_payload(Cursor::new(payload), &key).expect("unpack should succeed");

        assert_eq!(decrypted, plaintext);
        assert_eq!(header.magic, MAGIC_BYTES);
        assert_eq!(header.version, VERSION_V1);
        assert_eq!(header.enc_alg, ENC_ALG_AES256_GCM);
        assert_eq!(header.fmt_version, FMT_STREAM);
    }

    #[test]
    fn pack_then_unpack_round_trip_10mb() {
        let key = [14_u8; 32];
        let plaintext = patterned_bytes(10 * 1024 * 1024);

        let payload = pack_payload(Cursor::new(&plaintext), &key).expect("pack should succeed");
        let (decrypted, _) =
            unpack_payload(Cursor::new(payload), &key).expect("unpack should succeed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_returns_decryption_failed() {
        let key = [21_u8; 32];
        let wrong = [22_u8; 32];
        let plaintext = patterned_bytes(8192);

        let payload = pack_payload(Cursor::new(&plaintext), &key).expect("pack should succeed");
        let err = unpack_payload(Cursor::new(payload), &wrong).expect_err("wrong key should fail");

        assert!(matches!(err, SealError::DecryptionFailed(_)));
    }

    #[test]
    fn invalid_magic_returns_invalid_payload() {
        let key = [31_u8; 32];
        let plaintext = patterned_bytes(512);

        let mut payload = pack_payload(Cursor::new(&plaintext), &key).expect("pack should succeed");
        payload[0..4].copy_from_slice(b"BADS");

        let err =
            unpack_payload(Cursor::new(payload), &key).expect_err("invalid magic should fail");
        assert!(matches!(err, SealError::InvalidPayload(_)));
    }

    #[test]
    fn wrong_version_returns_unsupported_payload_version() {
        let key = [41_u8; 32];
        let plaintext = patterned_bytes(512);

        let mut payload = pack_payload(Cursor::new(&plaintext), &key).expect("pack should succeed");
        payload[4..6].copy_from_slice(&0x9999_u16.to_le_bytes());

        let err =
            unpack_payload(Cursor::new(payload), &key).expect_err("wrong version should fail");
        assert!(matches!(err, SealError::UnsupportedPayloadVersion(0x9999)));
    }

    #[test]
    fn validate_payload_header_parses_and_validates() {
        let key = [51_u8; 32];
        let plaintext = patterned_bytes(4096);

        let payload = pack_payload(Cursor::new(&plaintext), &key).expect("pack should succeed");
        let header = validate_payload_header(&payload).expect("header should parse");

        assert_eq!(header.magic, MAGIC_BYTES);
        assert_eq!(header.version, VERSION_V1);
    }
}
