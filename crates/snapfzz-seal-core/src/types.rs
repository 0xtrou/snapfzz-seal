use serde::{Deserialize, Serialize};

/// 4-byte magic: "ASL\x01"
pub const MAGIC_BYTES: [u8; 4] = [0x41, 0x53, 0x4C, 0x01];
pub const VERSION_V1: u16 = 0x0001;
pub const ENC_ALG_AES256_GCM: u16 = 0x0001;
pub const FMT_STREAM: u16 = 0x0001;
pub const CHUNK_SIZE: usize = 65536; // 64KB
pub const KDF_INFO_ENV: &[u8] = b"snapfzz-seal/env/v1";
pub const KDF_INFO_SESSION: &[u8] = b"snapfzz-seal/session/v1";

include!(concat!(env!("OUT_DIR"), "/generated_markers.rs"));

pub fn get_secret_marker(index: usize) -> &'static [u8; 32] {
    match index {
        0 => &SECRET_MARKER_0,
        1 => &SECRET_MARKER_1,
        2 => &SECRET_MARKER_2,
        3 => &SECRET_MARKER_3,
        4 => &SECRET_MARKER_4,
        _ => panic!("Invalid marker index"),
    }
}

pub fn get_decoy_marker(set: usize, index: usize) -> &'static [u8; 32] {
    &DECOY_MARKERS[set * 5 + index]
}

pub const SHAMIR_TOTAL_SHARES: usize = 5;
pub const SHAMIR_THRESHOLD: usize = 3;

pub const LAUNCHER_SECRET_MARKER: &[u8; 32] = &SECRET_MARKER_0;
pub const LAUNCHER_TAMPER_MARKER: &[u8; 32] = &TAMPER_MARKER;
pub const LAUNCHER_PAYLOAD_SENTINEL: &[u8; 32] = &PAYLOAD_SENTINEL;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PayloadHeader {
    pub magic: [u8; 4],
    pub version: u16,
    pub enc_alg: u16,
    pub fmt_version: u16,
    pub chunk_count: u32,
    pub header_hmac: [u8; 32],
    pub mode: AgentMode,
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum AgentMode {
    #[default]
    Batch,
    Interactive,
}

impl AgentMode {
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Batch => 0,
            Self::Interactive => 1,
        }
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Batch),
            1 => Some(Self::Interactive),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}
