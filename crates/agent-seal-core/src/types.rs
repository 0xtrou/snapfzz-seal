use serde::{Deserialize, Serialize};

/// 4-byte magic: "ASL\x01"
pub const MAGIC_BYTES: [u8; 4] = [0x41, 0x53, 0x4C, 0x01];
pub const VERSION_V1: u16 = 0x0001;
pub const ENC_ALG_AES256_GCM: u16 = 0x0001;
pub const FMT_STREAM: u16 = 0x0001;
pub const CHUNK_SIZE: usize = 65536; // 64KB
pub const KDF_INFO_ENV: &[u8] = b"agent-seal/env/v1";
pub const KDF_INFO_SESSION: &[u8] = b"agent-seal/session/v1";
pub const LAUNCHER_SECRET_MARKER: &[u8; 32] =
    b"ASL_SECRET_MRK_v1\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E";
pub const LAUNCHER_TAMPER_MARKER: &[u8; 32] =
    b"ASL_TAMPER_MRK_v1\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E";
pub const LAUNCHER_PAYLOAD_SENTINEL: &[u8; 32] =
    b"ASL_PAYLOAD_SPLIT_v1\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAA\xAB";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PayloadHeader {
    pub magic: [u8; 4],
    pub version: u16,
    pub enc_alg: u16,
    pub fmt_version: u16,
    pub chunk_count: u32,
    pub header_hmac: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChunkRecord {
    pub len: u32,
    pub data: Vec<u8>, // ciphertext + 16-byte tag
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PayloadFooter {
    pub original_hash: [u8; 32],
    pub launcher_hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}
