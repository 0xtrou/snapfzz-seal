use crate::{
    constants::{CHUNK_SIZE, ENC_ALG_AES256_GCM, FMT_STREAM, MAGIC_BYTES, VERSION_V1},
    crypto::{decrypt_stream, encrypt_stream},
    error::SealError,
    types::{AgentMode, BackendType, PayloadFooter, PayloadHeader},
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io::{Cursor, Read};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

const HEADER_SIZE: usize = 4 + 2 + 2 + 2 + 4 + 32;
const MODE_SIZE: usize = 1;
const HASH_SIZE: usize = 32;
const FOOTER_SIZE: usize = HASH_SIZE + HASH_SIZE + 1;
const LEGACY_FOOTER_SIZE: usize = HASH_SIZE + HASH_SIZE;
const NONCE_SIZE: usize = 7;

pub fn pack_payload(mut plaintext: impl Read, key: &[u8; 32]) -> Result<Vec<u8>, SealError> {
    pack_payload_with_mode(plaintext.by_ref(), key, AgentMode::Batch)
}

pub fn pack_payload_with_mode(
    mut plaintext: impl Read,
    key: &[u8; 32],
    mode: AgentMode,
) -> Result<Vec<u8>, SealError> {
    pack_payload_with_footer(plaintext.by_ref(), key, mode, None)
}

pub fn pack_payload_with_footer(
    mut plaintext: impl Read,
    key: &[u8; 32],
    mode: AgentMode,
    footer: Option<&PayloadFooter>,
) -> Result<Vec<u8>, SealError> {
    let mut plaintext_bytes = Vec::new();
    plaintext.read_to_end(&mut plaintext_bytes)?;

    let encrypted_bytes = encrypt_stream(Cursor::new(&plaintext_bytes), key)?;

    let chunk_count = if plaintext_bytes.is_empty() {
        0
    } else {
        plaintext_bytes.len().div_ceil(CHUNK_SIZE) as u32
    };

    let footer_bytes: Option<[u8; FOOTER_SIZE]> = footer.map(write_footer);

    let header_hmac = compute_header_hmac(
        &MAGIC_BYTES,
        VERSION_V1,
        ENC_ALG_AES256_GCM,
        FMT_STREAM,
        chunk_count,
        key,
        footer_bytes.as_ref().map(|b| b.as_slice()),
    );

    let header = PayloadHeader {
        magic: MAGIC_BYTES,
        version: VERSION_V1,
        enc_alg: ENC_ALG_AES256_GCM,
        fmt_version: FMT_STREAM,
        chunk_count,
        header_hmac,
        mode,
    };

    let mut out = Vec::with_capacity(HEADER_SIZE + MODE_SIZE + encrypted_bytes.len());
    out.extend_from_slice(&serialize_header(&header));
    out.push(mode.as_u8());
    out.extend_from_slice(&encrypted_bytes);
    Ok(out)
}

pub fn unpack_payload(
    mut payload: impl Read,
    key: &[u8; 32],
) -> Result<(Vec<u8>, PayloadHeader), SealError> {
    unpack_payload_with_footer(payload.by_ref(), key, None)
}

pub fn unpack_payload_with_footer(
    mut payload: impl Read,
    key: &[u8; 32],
    footer: Option<&PayloadFooter>,
) -> Result<(Vec<u8>, PayloadHeader), SealError> {
    let mut payload_bytes = Vec::new();
    payload.read_to_end(&mut payload_bytes)?;

    if payload_bytes.len() < HEADER_SIZE + MODE_SIZE {
        return Err(SealError::InvalidPayload(
            "payload too small to contain header, mode, and encrypted body".to_string(),
        ));
    }

    let mut header = parse_header(&payload_bytes[..HEADER_SIZE])?;

    let footer_bytes: Option<[u8; FOOTER_SIZE]> = footer.map(write_footer);

    let expected_hmac = compute_header_hmac(
        &header.magic,
        header.version,
        header.enc_alg,
        header.fmt_version,
        header.chunk_count,
        key,
        footer_bytes.as_ref().map(|b| b.as_slice()),
    );

    if !bool::from(header.header_hmac.ct_eq(&expected_hmac)) {
        return Err(SealError::DecryptionFailed(
            "payload header authentication failed".to_string(),
        ));
    }

    let mode_byte = payload_bytes[HEADER_SIZE];
    let mode = AgentMode::from_u8(mode_byte).ok_or_else(|| {
        SealError::InvalidPayload(format!("invalid payload mode byte: {mode_byte}"))
    })?;
    header.mode = mode;

    let encrypted_bytes = &payload_bytes[HEADER_SIZE + MODE_SIZE..];
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

pub fn write_footer(footer: &PayloadFooter) -> [u8; FOOTER_SIZE] {
    let mut out = [0_u8; FOOTER_SIZE];
    out[..HASH_SIZE].copy_from_slice(&footer.original_hash);
    out[HASH_SIZE..HASH_SIZE * 2].copy_from_slice(&footer.launcher_hash);
    out[HASH_SIZE * 2] = footer.backend_type.as_u8();
    out
}

pub fn read_footer(data: &[u8]) -> Result<PayloadFooter, SealError> {
    if data.len() != FOOTER_SIZE && data.len() != LEGACY_FOOTER_SIZE {
        return Err(SealError::InvalidPayload(format!(
            "payload footer must be exactly {FOOTER_SIZE} bytes or legacy {LEGACY_FOOTER_SIZE} bytes"
        )));
    }

    let mut original_hash = [0_u8; HASH_SIZE];
    original_hash.copy_from_slice(&data[..HASH_SIZE]);

    let mut launcher_hash = [0_u8; HASH_SIZE];
    launcher_hash.copy_from_slice(&data[HASH_SIZE..HASH_SIZE * 2]);

    let backend_type = if data.len() == FOOTER_SIZE {
        BackendType::from_u8(data[HASH_SIZE * 2]).ok_or_else(|| {
            SealError::InvalidPayload(format!(
                "invalid payload backend type byte: {}",
                data[HASH_SIZE * 2]
            ))
        })?
    } else {
        BackendType::Unknown
    };

    Ok(PayloadFooter {
        original_hash,
        launcher_hash,
        backend_type,
    })
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
        mode: AgentMode::Batch,
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
    footer_bytes: Option<&[u8]>,
) -> [u8; 32] {
    let header_without_hmac =
        serialize_header_without_hmac(magic, version, enc_alg, fmt_version, chunk_count);
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(&header_without_hmac);
    if let Some(footer) = footer_bytes {
        mac.update(footer);
    }

    let mut out = [0_u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read};

    struct ErrReader;

    impl Read for ErrReader {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("forced read failure"))
        }
    }

    fn patterned_bytes(len: usize) -> Vec<u8> {
        (0..len).map(|idx| (idx % 241) as u8).collect()
    }

    #[test]
    fn pack_then_unpack_round_trip() {
        let key = [13_u8; 32];
        let plaintext = patterned_bytes(220_000);

        let payload = pack_payload_with_mode(Cursor::new(&plaintext), &key, AgentMode::Batch)
            .expect("pack should succeed");
        let (decrypted, header) =
            unpack_payload(Cursor::new(payload), &key).expect("unpack should succeed");

        assert_eq!(decrypted, plaintext);
        assert_eq!(header.magic, MAGIC_BYTES);
        assert_eq!(header.version, VERSION_V1);
        assert_eq!(header.enc_alg, ENC_ALG_AES256_GCM);
        assert_eq!(header.fmt_version, FMT_STREAM);
        assert_eq!(header.mode, AgentMode::Batch);
    }

    #[test]
    fn pack_then_unpack_round_trip_10mb() {
        let key = [14_u8; 32];
        let plaintext = patterned_bytes(10 * 1024 * 1024);

        let payload = pack_payload_with_mode(Cursor::new(&plaintext), &key, AgentMode::Batch)
            .expect("pack should succeed");
        let (decrypted, _) =
            unpack_payload(Cursor::new(payload), &key).expect("unpack should succeed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_returns_decryption_failed() {
        let key = [21_u8; 32];
        let wrong = [22_u8; 32];
        let plaintext = patterned_bytes(8192);

        let payload = pack_payload_with_mode(Cursor::new(&plaintext), &key, AgentMode::Batch)
            .expect("pack should succeed");
        let err = unpack_payload(Cursor::new(payload), &wrong).expect_err("wrong key should fail");

        assert!(matches!(err, SealError::DecryptionFailed(_)));
    }

    #[test]
    fn invalid_magic_returns_invalid_payload() {
        let key = [31_u8; 32];
        let plaintext = patterned_bytes(512);

        let mut payload = pack_payload_with_mode(Cursor::new(&plaintext), &key, AgentMode::Batch)
            .expect("pack should succeed");
        payload[0..4].copy_from_slice(b"BADS");

        let err =
            unpack_payload(Cursor::new(payload), &key).expect_err("invalid magic should fail");
        assert!(matches!(err, SealError::InvalidPayload(_)));
    }

    #[test]
    fn wrong_version_returns_unsupported_payload_version() {
        let key = [41_u8; 32];
        let plaintext = patterned_bytes(512);

        let mut payload = pack_payload_with_mode(Cursor::new(&plaintext), &key, AgentMode::Batch)
            .expect("pack should succeed");
        payload[4..6].copy_from_slice(&0x9999_u16.to_le_bytes());

        let err =
            unpack_payload(Cursor::new(payload), &key).expect_err("wrong version should fail");
        assert!(matches!(err, SealError::UnsupportedPayloadVersion(0x9999)));
    }

    #[test]
    fn validate_payload_header_parses_and_validates() {
        let key = [51_u8; 32];
        let plaintext = patterned_bytes(4096);

        let payload = pack_payload_with_mode(Cursor::new(&plaintext), &key, AgentMode::Batch)
            .expect("pack should succeed");
        let header = validate_payload_header(&payload).expect("header should parse");

        assert_eq!(header.magic, MAGIC_BYTES);
        assert_eq!(header.version, VERSION_V1);
    }

    #[test]
    fn empty_plaintext_sets_zero_chunk_count() {
        let key = [52_u8; 32];
        let payload =
            pack_payload_with_mode(Cursor::new(Vec::<u8>::new()), &key, AgentMode::Batch).unwrap();
        let (_decrypted, header) = unpack_payload(Cursor::new(payload), &key).unwrap();
        assert_eq!(header.chunk_count, 0);
    }

    #[test]
    fn exact_chunk_plaintext_sets_chunk_count_one() {
        let key = [53_u8; 32];
        let plaintext = patterned_bytes(CHUNK_SIZE);
        let payload =
            pack_payload_with_mode(Cursor::new(&plaintext), &key, AgentMode::Batch).unwrap();
        let (_decrypted, header) = unpack_payload(Cursor::new(payload), &key).unwrap();
        assert_eq!(header.chunk_count, 1);
        assert_eq!(header.mode, AgentMode::Batch);
    }

    #[test]
    fn unpack_payload_rejects_payload_too_small_for_header() {
        let key = [55_u8; 32];
        let err = unpack_payload(Cursor::new(vec![0_u8; HEADER_SIZE]), &key)
            .expect_err("small payload must fail");
        assert!(matches!(err, SealError::InvalidPayload(_)));
    }

    #[test]
    fn unpack_payload_rejects_encrypted_body_missing_nonce() {
        let key = [56_u8; 32];
        let header = PayloadHeader {
            magic: MAGIC_BYTES,
            version: VERSION_V1,
            enc_alg: ENC_ALG_AES256_GCM,
            fmt_version: FMT_STREAM,
            chunk_count: 1,
            header_hmac: compute_header_hmac(
                &MAGIC_BYTES,
                VERSION_V1,
                ENC_ALG_AES256_GCM,
                FMT_STREAM,
                1,
                &key,
                None,
            ),
            mode: AgentMode::Batch,
        };

        let mut payload = serialize_header(&header).to_vec();
        payload.push(AgentMode::Batch.as_u8());
        let err = unpack_payload(Cursor::new(payload), &key).expect_err("missing nonce must fail");
        assert!(
            matches!(err, SealError::InvalidPayload(message) if message.contains("missing stream nonce"))
        );
    }

    #[test]
    fn pack_payload_sets_header_fields_for_non_empty_plaintext() {
        let key = [63_u8; 32];
        let plaintext = b"payload-bytes";

        let payload = pack_payload_with_mode(Cursor::new(plaintext), &key, AgentMode::Batch)
            .expect("pack should succeed");
        let header = parse_header(&payload[..HEADER_SIZE]).expect("header should parse");

        assert_eq!(header.magic, MAGIC_BYTES);
        assert_eq!(header.version, VERSION_V1);
        assert_eq!(header.enc_alg, ENC_ALG_AES256_GCM);
        assert_eq!(header.fmt_version, FMT_STREAM);
        assert_eq!(header.chunk_count, 1);
    }

    #[test]
    fn pack_payload_encrypts_plaintext_bytes_beyond_header() {
        let key = [64_u8; 32];
        let plaintext = b"secret-body";

        let payload = pack_payload_with_mode(Cursor::new(plaintext), &key, AgentMode::Batch)
            .expect("pack should succeed");

        assert!(payload.len() > HEADER_SIZE + MODE_SIZE + NONCE_SIZE);
        assert_eq!(payload[HEADER_SIZE], AgentMode::Batch.as_u8());
        assert_ne!(
            &payload[HEADER_SIZE + MODE_SIZE..HEADER_SIZE + MODE_SIZE + NONCE_SIZE],
            &[0_u8; NONCE_SIZE]
        );
        assert_ne!(&payload[HEADER_SIZE + MODE_SIZE + NONCE_SIZE..], plaintext);
    }

    #[test]
    fn unpack_payload_round_trips_single_chunk_body() {
        let key = [65_u8; 32];
        let plaintext = b"single-chunk-body".to_vec();
        let payload = pack_payload_with_mode(Cursor::new(&plaintext), &key, AgentMode::Batch)
            .expect("pack should succeed");

        let (decrypted, header) =
            unpack_payload(Cursor::new(payload), &key).expect("unpack should succeed");

        assert_eq!(decrypted, plaintext);
        assert_eq!(header.chunk_count, 1);
    }

    #[test]
    fn validate_payload_header_returns_same_header_as_parse_header() {
        let key = [66_u8; 32];
        let plaintext = b"validate-me";
        let payload = pack_payload_with_mode(Cursor::new(plaintext), &key, AgentMode::Batch)
            .expect("pack should succeed");

        let validated = validate_payload_header(&payload).expect("validation should succeed");
        let parsed = parse_header(&payload[..HEADER_SIZE]).expect("parse should succeed");

        assert_eq!(validated, parsed);
    }

    #[test]
    fn read_footer_parses_hash_halves_in_order() {
        let mut bytes = [0_u8; FOOTER_SIZE];
        bytes[..HASH_SIZE].copy_from_slice(&[0x12; 32]);
        bytes[HASH_SIZE..HASH_SIZE * 2].copy_from_slice(&[0x34; 32]);
        bytes[HASH_SIZE * 2] = BackendType::PyInstaller.as_u8();

        let footer = read_footer(&bytes).expect("footer should parse");

        assert_eq!(footer.original_hash, [0x12; 32]);
        assert_eq!(footer.launcher_hash, [0x34; 32]);
        assert_eq!(footer.backend_type, BackendType::PyInstaller);
    }

    #[test]
    fn unpack_payload_rejects_tampered_header_hmac() {
        let key = [57_u8; 32];
        let plaintext = patterned_bytes(1024);
        let mut payload =
            pack_payload_with_mode(Cursor::new(&plaintext), &key, AgentMode::Batch).unwrap();
        payload[HEADER_SIZE - 1] ^= 0x01;

        let err = unpack_payload(Cursor::new(payload), &key).expect_err("tampered hmac must fail");
        assert!(matches!(err, SealError::DecryptionFailed(_)));
    }

    #[test]
    fn validate_payload_header_rejects_short_data() {
        let short = [0_u8; HEADER_SIZE - 1];
        let err = validate_payload_header(&short).expect_err("must fail");
        assert!(matches!(err, SealError::InvalidPayload(_)));
    }

    #[test]
    fn parse_header_rejects_wrong_length() {
        let short = [0_u8; HEADER_SIZE - 1];
        let err = parse_header(&short).expect_err("must fail");
        assert!(matches!(err, SealError::InvalidPayload(_)));
    }

    #[test]
    fn parse_header_rejects_invalid_encryption_algorithm() {
        let key = [58_u8; 32];
        let plaintext = patterned_bytes(512);
        let mut payload =
            pack_payload_with_mode(Cursor::new(&plaintext), &key, AgentMode::Batch).unwrap();
        payload[6..8].copy_from_slice(&0x9999_u16.to_le_bytes());

        let err =
            unpack_payload(Cursor::new(payload), &key).expect_err("invalid enc alg must fail");
        assert!(matches!(err, SealError::InvalidPayload(_)));
    }

    #[test]
    fn parse_header_rejects_invalid_format_version() {
        let key = [59_u8; 32];
        let plaintext = patterned_bytes(512);
        let mut payload =
            pack_payload_with_mode(Cursor::new(&plaintext), &key, AgentMode::Batch).unwrap();
        payload[8..10].copy_from_slice(&0x7777_u16.to_le_bytes());

        let err = unpack_payload(Cursor::new(payload), &key)
            .expect_err("invalid format version must fail");
        assert!(matches!(err, SealError::InvalidPayload(_)));
    }

    #[test]
    fn serialize_header_round_trips_with_parse_header() {
        let header = PayloadHeader {
            magic: MAGIC_BYTES,
            version: VERSION_V1,
            enc_alg: ENC_ALG_AES256_GCM,
            fmt_version: FMT_STREAM,
            chunk_count: 9,
            header_hmac: [0xCD; 32],
            mode: AgentMode::Batch,
        };

        let serialized = serialize_header(&header);
        let parsed = parse_header(&serialized).unwrap();
        assert_eq!(parsed, header);
    }

    #[test]
    fn serialize_header_without_hmac_writes_expected_layout() {
        let bytes = serialize_header_without_hmac(&MAGIC_BYTES, 2, 3, 4, 5);

        assert_eq!(&bytes[0..4], &MAGIC_BYTES);
        assert_eq!(&bytes[4..6], &2_u16.to_le_bytes());
        assert_eq!(&bytes[6..8], &3_u16.to_le_bytes());
        assert_eq!(&bytes[8..10], &4_u16.to_le_bytes());
        assert_eq!(&bytes[10..14], &5_u32.to_le_bytes());
    }

    #[test]
    fn compute_header_hmac_changes_with_chunk_count() {
        let key = [60_u8; 32];
        let a = compute_header_hmac(
            &MAGIC_BYTES,
            VERSION_V1,
            ENC_ALG_AES256_GCM,
            FMT_STREAM,
            1,
            &key,
            None,
        );
        let b = compute_header_hmac(
            &MAGIC_BYTES,
            VERSION_V1,
            ENC_ALG_AES256_GCM,
            FMT_STREAM,
            2,
            &key,
            None,
        );

        assert_ne!(a, b);
    }

    #[test]
    fn write_footer_produces_exactly_65_bytes() {
        let footer = PayloadFooter {
            original_hash: [0x11; 32],
            launcher_hash: [0x22; 32],
            backend_type: BackendType::Nuitka,
        };

        let bytes = write_footer(&footer);

        assert_eq!(bytes.len(), FOOTER_SIZE);
        assert_eq!(&bytes[..HASH_SIZE], &[0x11; 32]);
        assert_eq!(&bytes[HASH_SIZE..HASH_SIZE * 2], &[0x22; 32]);
        assert_eq!(bytes[HASH_SIZE * 2], BackendType::Nuitka.as_u8());
    }

    #[test]
    fn footer_round_trip() {
        let footer = PayloadFooter {
            original_hash: [0x33; 32],
            launcher_hash: [0x44; 32],
            backend_type: BackendType::Go,
        };

        let bytes = write_footer(&footer);
        let parsed = read_footer(&bytes).expect("footer should parse");

        assert_eq!(parsed, footer);
    }

    #[test]
    fn read_footer_rejects_shorter_than_legacy_footer_size() {
        let err = read_footer(&[0xAA; LEGACY_FOOTER_SIZE - 1]).expect_err("short footer must fail");
        assert!(matches!(err, SealError::InvalidPayload(_)));
    }

    #[test]
    fn read_footer_rejects_longer_than_current_footer_size() {
        let err = read_footer(&[0xBB; FOOTER_SIZE + 1]).expect_err("long footer must fail");
        assert!(matches!(err, SealError::InvalidPayload(_)));
    }

    #[test]
    fn read_footer_accepts_legacy_64_byte_footer_as_unknown_backend() {
        let mut bytes = [0_u8; LEGACY_FOOTER_SIZE];
        bytes[..HASH_SIZE].copy_from_slice(&[0xAA; HASH_SIZE]);
        bytes[HASH_SIZE..HASH_SIZE * 2].copy_from_slice(&[0xBB; HASH_SIZE]);

        let footer = read_footer(&bytes).expect("legacy footer should parse");
        assert_eq!(footer.original_hash, [0xAA; HASH_SIZE]);
        assert_eq!(footer.launcher_hash, [0xBB; HASH_SIZE]);
        assert_eq!(footer.backend_type, BackendType::Unknown);
    }

    #[test]
    fn read_footer_rejects_invalid_backend_type_byte() {
        let mut bytes = [0_u8; FOOTER_SIZE];
        bytes[HASH_SIZE * 2] = u8::MAX;

        let err = read_footer(&bytes).expect_err("invalid backend type must fail");
        assert!(
            matches!(err, SealError::InvalidPayload(message) if message.contains("invalid payload backend type byte"))
        );
    }

    #[test]
    fn pack_payload_propagates_plaintext_read_error() {
        let key = [61_u8; 32];
        let err = pack_payload_with_mode(ErrReader, &key, AgentMode::Batch)
            .expect_err("reader failure must propagate");
        assert!(matches!(err, SealError::Io(_)));
    }

    #[test]
    fn unpack_payload_propagates_payload_read_error() {
        let key = [62_u8; 32];
        let err = unpack_payload(ErrReader, &key).expect_err("reader failure must propagate");
        assert!(matches!(err, SealError::Io(_)));
    }

    #[test]
    fn pack_unpack_round_trip_interactive_mode() {
        let key = [67_u8; 32];
        let plaintext = b"interactive-mode-body";

        let payload = pack_payload_with_mode(Cursor::new(plaintext), &key, AgentMode::Interactive)
            .expect("pack");
        let (decrypted, header) = unpack_payload(Cursor::new(payload), &key).expect("unpack");

        assert_eq!(decrypted, plaintext);
        assert_eq!(header.mode, AgentMode::Interactive);
    }

    #[test]
    fn unpack_rejects_invalid_mode_byte() {
        let key = [68_u8; 32];
        let plaintext = b"invalid-mode";
        let mut payload =
            pack_payload_with_mode(Cursor::new(plaintext), &key, AgentMode::Batch).unwrap();
        payload[HEADER_SIZE] = 9;

        let err = unpack_payload(Cursor::new(payload), &key).expect_err("invalid mode must fail");
        assert!(
            matches!(err, SealError::InvalidPayload(message) if message.contains("invalid payload mode byte"))
        );
    }

    #[test]
    fn pack_unpack_with_footer_round_trip() {
        let key = [70_u8; 32];
        let plaintext = b"footer-round-trip-body";
        let footer = PayloadFooter {
            original_hash: [0xAA; 32],
            launcher_hash: [0xBB; 32],
            backend_type: BackendType::Go,
        };

        let payload = pack_payload_with_footer(
            Cursor::new(plaintext),
            &key,
            AgentMode::Batch,
            Some(&footer),
        )
        .expect("pack with footer should succeed");
        let (decrypted, header) =
            unpack_payload_with_footer(Cursor::new(payload), &key, Some(&footer))
                .expect("unpack with footer should succeed");

        assert_eq!(decrypted, plaintext.as_slice());
        assert_eq!(header.mode, AgentMode::Batch);
    }

    #[test]
    fn tampered_backend_type_causes_hmac_failure() {
        let key = [71_u8; 32];
        let plaintext = b"backend-type-tamper-test";
        let footer = PayloadFooter {
            original_hash: [0x11; 32],
            launcher_hash: [0x22; 32],
            backend_type: BackendType::Go,
        };

        let payload = pack_payload_with_footer(
            Cursor::new(plaintext),
            &key,
            AgentMode::Batch,
            Some(&footer),
        )
        .expect("pack should succeed");

        // Attacker flips backend_type from Go (0x01) to PyInstaller (0x02)
        let tampered_footer = PayloadFooter {
            original_hash: [0x11; 32],
            launcher_hash: [0x22; 32],
            backend_type: BackendType::PyInstaller,
        };

        let err = unpack_payload_with_footer(Cursor::new(payload), &key, Some(&tampered_footer))
            .expect_err("tampered backend_type must cause HMAC failure");
        assert!(matches!(err, SealError::DecryptionFailed(_)));
    }

    #[test]
    fn footer_authenticated_payload_rejects_no_footer_unpack() {
        let key = [72_u8; 32];
        let plaintext = b"footer-required";
        let footer = PayloadFooter {
            original_hash: [0x33; 32],
            launcher_hash: [0x44; 32],
            backend_type: BackendType::Nuitka,
        };

        let payload = pack_payload_with_footer(
            Cursor::new(plaintext),
            &key,
            AgentMode::Batch,
            Some(&footer),
        )
        .expect("pack should succeed");

        // Unpack without footer should fail: HMAC was computed with footer bytes
        let err = unpack_payload(Cursor::new(payload), &key)
            .expect_err("unpack without footer must fail when packed with footer");
        assert!(matches!(err, SealError::DecryptionFailed(_)));
    }

    #[test]
    fn no_footer_pack_rejects_footer_unpack() {
        let key = [73_u8; 32];
        let plaintext = b"no-footer-pack";

        let payload = pack_payload_with_mode(Cursor::new(plaintext), &key, AgentMode::Batch)
            .expect("pack without footer should succeed");

        let footer = PayloadFooter {
            original_hash: [0x55; 32],
            launcher_hash: [0x66; 32],
            backend_type: BackendType::Go,
        };

        // Unpack with a footer when pack used none should fail: HMAC mismatch
        let err = unpack_payload_with_footer(Cursor::new(payload), &key, Some(&footer))
            .expect_err("unpack with spurious footer must fail");
        assert!(matches!(err, SealError::DecryptionFailed(_)));
    }

    #[test]
    fn tampered_original_hash_causes_hmac_failure() {
        let key = [74_u8; 32];
        let plaintext = b"original-hash-tamper-test";
        let footer = PayloadFooter {
            original_hash: [0x77; 32],
            launcher_hash: [0x88; 32],
            backend_type: BackendType::Go,
        };

        let payload = pack_payload_with_footer(
            Cursor::new(plaintext),
            &key,
            AgentMode::Batch,
            Some(&footer),
        )
        .expect("pack should succeed");

        let tampered_footer = PayloadFooter {
            original_hash: [0x78; 32], // flip one byte
            launcher_hash: [0x88; 32],
            backend_type: BackendType::Go,
        };

        let err = unpack_payload_with_footer(Cursor::new(payload), &key, Some(&tampered_footer))
            .expect_err("tampered original_hash must cause HMAC failure");
        assert!(matches!(err, SealError::DecryptionFailed(_)));
    }
}
