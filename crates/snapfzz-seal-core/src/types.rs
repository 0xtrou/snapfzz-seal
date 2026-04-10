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
    pub backend_type: BackendType,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
pub enum BackendType {
    Unknown = 0,
    Go = 1,
    PyInstaller = 2,
    Nuitka = 3,
}

impl Default for BackendType {
    fn default() -> Self {
        BackendType::Unknown
    }
}

impl BackendType {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Unknown),
            1 => Some(Self::Go),
            2 => Some(Self::PyInstaller),
            3 => Some(Self::Nuitka),
            _ => None,
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::{read_footer, write_footer};

    #[test]
    fn secret_markers_are_unique_and_32_bytes() {
        let markers = [
            get_secret_marker(0),
            get_secret_marker(1),
            get_secret_marker(2),
            get_secret_marker(3),
            get_secret_marker(4),
        ];

        for marker in markers {
            assert_eq!(marker.len(), 32);
            assert!(marker.iter().any(|byte| *byte != 0));
        }

        for left in 0..markers.len() {
            for right in left + 1..markers.len() {
                assert_ne!(
                    markers[left], markers[right],
                    "secret markers should be distinct"
                );
            }
        }
    }

    #[test]
    #[should_panic(expected = "Invalid marker index")]
    fn secret_marker_panics_for_out_of_range_index() {
        let _ = get_secret_marker(SHAMIR_TOTAL_SHARES);
    }

    #[test]
    fn decoy_markers_cover_all_sets_and_are_distinct_from_secret_markers() {
        let secret_markers = [
            get_secret_marker(0),
            get_secret_marker(1),
            get_secret_marker(2),
            get_secret_marker(3),
            get_secret_marker(4),
        ];

        let first = get_decoy_marker(0, 0);
        let last = get_decoy_marker(9, 4);

        assert_eq!(first.len(), 32);
        assert_eq!(last.len(), 32);
        assert_ne!(first, last);
        assert!(secret_markers.iter().all(|marker| *marker != first));
        assert!(secret_markers.iter().all(|marker| *marker != last));
    }

    #[test]
    fn launcher_markers_alias_expected_secret_and_generated_markers() {
        assert_eq!(LAUNCHER_SECRET_MARKER, get_secret_marker(0));
        assert_eq!(LAUNCHER_TAMPER_MARKER, &TAMPER_MARKER);
        assert_eq!(LAUNCHER_PAYLOAD_SENTINEL, &PAYLOAD_SENTINEL);
    }

    #[test]
    fn payload_footer_round_trips_through_binary_serialization() {
        let footer = PayloadFooter {
            original_hash: [0x11; 32],
            launcher_hash: [0x22; 32],
            backend_type: BackendType::Go,
        };

        let serialized = write_footer(&footer);
        let parsed = read_footer(&serialized).expect("footer should deserialize");

        assert_eq!(parsed, footer);
    }

    #[test]
    fn payload_footer_preserves_hash_order_in_binary_serialization() {
        let footer = PayloadFooter {
            original_hash: [0xAA; 32],
            launcher_hash: [0xBB; 32],
            backend_type: BackendType::PyInstaller,
        };

        let serialized = write_footer(&footer);

        assert_eq!(&serialized[..32], &[0xAA; 32]);
        assert_eq!(&serialized[32..64], &[0xBB; 32]);
        assert_eq!(serialized[64], BackendType::PyInstaller.as_u8());
    }

    #[test]
    fn backend_type_default_and_type_conversions_cover_valid_and_invalid_values() {
        assert_eq!(BackendType::default(), BackendType::Unknown);
        assert_eq!(BackendType::Unknown.as_u8(), 0);
        assert_eq!(BackendType::Go.as_u8(), 1);
        assert_eq!(BackendType::PyInstaller.as_u8(), 2);
        assert_eq!(BackendType::Nuitka.as_u8(), 3);
        assert_eq!(BackendType::from_u8(0), Some(BackendType::Unknown));
        assert_eq!(BackendType::from_u8(1), Some(BackendType::Go));
        assert_eq!(BackendType::from_u8(2), Some(BackendType::PyInstaller));
        assert_eq!(BackendType::from_u8(3), Some(BackendType::Nuitka));
        assert_eq!(BackendType::from_u8(4), None);
        assert_eq!(BackendType::from_u8(u8::MAX), None);
    }

    #[test]
    fn agent_mode_default_and_type_conversions_cover_valid_and_invalid_values() {
        assert_eq!(AgentMode::default(), AgentMode::Batch);
        assert_eq!(AgentMode::Batch.as_u8(), 0);
        assert_eq!(AgentMode::Interactive.as_u8(), 1);
        assert_eq!(AgentMode::from_u8(0), Some(AgentMode::Batch));
        assert_eq!(AgentMode::from_u8(1), Some(AgentMode::Interactive));
        assert_eq!(AgentMode::from_u8(2), None);
        assert_eq!(AgentMode::from_u8(u8::MAX), None);
    }

    #[test]
    fn constants_match_expected_wire_values() {
        assert_eq!(MAGIC_BYTES, *b"ASL\x01");
        assert_eq!(VERSION_V1, 0x0001);
        assert_eq!(ENC_ALG_AES256_GCM, 0x0001);
        assert_eq!(FMT_STREAM, 0x0001);
        assert_eq!(CHUNK_SIZE, 65_536);
        assert_eq!(KDF_INFO_ENV, b"snapfzz-seal/env/v1");
        assert_eq!(KDF_INFO_SESSION, b"snapfzz-seal/session/v1");
        assert_eq!(SHAMIR_TOTAL_SHARES, 5);
        assert_eq!(SHAMIR_THRESHOLD, 3);
    }
}
