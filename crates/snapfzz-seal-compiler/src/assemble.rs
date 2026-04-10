use crate::decoys::embed_decoy_secrets;
use crate::embed::{embed_master_secret, embed_tamper_hash};
use crate::whitebox_embed::{embed_whitebox_tables, generate_whitebox_tables};
use sha2::{Digest, Sha256};
use snapfzz_seal_core::{
    derive::derive_env_key,
    error::SealError,
    integrity::{
        compute_binary_integrity_hash, derive_key_with_integrity_from_binary,
        find_integrity_regions,
    },
    payload::{pack_payload_with_mode, write_footer},
    types::{AgentMode, BackendType, LAUNCHER_PAYLOAD_SENTINEL, PayloadFooter},
};
use std::{io::Cursor, path::PathBuf};

pub struct AssembleConfig {
    pub agent_elf_path: PathBuf,
    pub launcher_path: PathBuf,
    pub master_secret: [u8; 32],
    pub stable_fingerprint_hash: [u8; 32],
    pub user_fingerprint: [u8; 32],
    pub mode: AgentMode,
    pub backend_name: String,
}

fn backend_type_from_name(name: &str) -> BackendType {
    match name {
        "go" => BackendType::Go,
        "pyinstaller" => BackendType::PyInstaller,
        "nuitka" => BackendType::Nuitka,
        _ => BackendType::Unknown,
    }
}

pub fn assemble(config: &AssembleConfig) -> Result<Vec<u8>, SealError> {
    let agent_elf_bytes = std::fs::read(&config.agent_elf_path)?;
    let env_key = derive_env_key(
        &config.master_secret,
        &config.stable_fingerprint_hash,
        &config.user_fingerprint,
    )?;

    let launcher_bytes = std::fs::read(&config.launcher_path)?;

    let launcher_with_secret = embed_master_secret(&launcher_bytes, &config.master_secret)?;

    let launcher_with_decoys = embed_decoy_secrets(&launcher_with_secret, 0)?;

    let mut tamper_hash = [0_u8; 32];
    tamper_hash.copy_from_slice(&Sha256::digest(&launcher_with_decoys));
    let launcher_with_tamper = embed_tamper_hash(&launcher_with_decoys, &tamper_hash)?;

    let whitebox_tables = generate_whitebox_tables(&config.master_secret);
    let launcher_with_whitebox = embed_whitebox_tables(&launcher_with_tamper, &whitebox_tables)?;

    let regions = find_integrity_regions(&launcher_with_whitebox)?;
    let launcher_integrity_hash = compute_binary_integrity_hash(&launcher_with_whitebox, &regions)?;

    let integrity_key = derive_key_with_integrity_from_binary(&env_key, &launcher_with_whitebox)?;

    let encrypted_payload =
        pack_payload_with_mode(Cursor::new(&agent_elf_bytes), &integrity_key, config.mode)?;

    let mut original_hash = [0_u8; 32];
    original_hash.copy_from_slice(&Sha256::digest(&agent_elf_bytes));

    let regions = find_integrity_regions(&launcher_with_whitebox)?;
    let launcher_hash = compute_binary_integrity_hash(&launcher_with_whitebox, &regions)?;

    let backend_type = backend_type_from_name(&config.backend_name);

    let footer = PayloadFooter {
        original_hash,
        launcher_hash,
        backend_type,
    };
    let footer_bytes = write_footer(&footer);

    let mut assembled = Vec::with_capacity(
        launcher_with_whitebox.len()
            + LAUNCHER_PAYLOAD_SENTINEL.len()
            + encrypted_payload.len()
            + footer_bytes.len(),
    );
    assembled.extend_from_slice(&launcher_with_whitebox);
    assembled.extend_from_slice(LAUNCHER_PAYLOAD_SENTINEL);
    assembled.extend_from_slice(&encrypted_payload);
    assembled.extend_from_slice(&footer_bytes);
    Ok(assembled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use snapfzz_seal_core::{
        derive::derive_env_key,
        integrity::{
            compute_binary_integrity_hash, derive_key_with_integrity_from_binary,
            find_integrity_regions,
        },
        payload::{pack_payload_with_mode, read_footer, unpack_payload, write_footer},
        types::{
            AgentMode, LAUNCHER_PAYLOAD_SENTINEL, LAUNCHER_TAMPER_MARKER, PayloadFooter,
            SHAMIR_TOTAL_SHARES, get_secret_marker,
        },
    };
    use std::io::Cursor;

    fn test_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("snapfzz-seal-assemble-{name}"))
    }

    fn launcher_with_markers(fill: u8) -> Vec<u8> {
        let mut launcher = vec![fill; 256];
        for i in 0..SHAMIR_TOTAL_SHARES {
            launcher.extend_from_slice(get_secret_marker(i));
            launcher.extend_from_slice(&[0_u8; 32]);
            launcher.extend_from_slice(&[fill; 12]);
        }
        launcher.extend_from_slice(LAUNCHER_TAMPER_MARKER);
        launcher.extend_from_slice(&[0_u8; 32]);
        launcher.extend_from_slice(&[fill; 128]);
        launcher
    }

    #[test]
    fn assembled_binary_is_launcher_plus_encrypted_payload_and_footer() {
        let root = test_root("size");
        std::fs::create_dir_all(&root).expect("test root should be creatable");

        let agent_path = root.join("agent.bin");
        let launcher_path = root.join("launcher.bin");

        let agent_bytes = vec![0xAA; 1024];
        let launcher_bytes = launcher_with_markers(0xBB);

        std::fs::write(&agent_path, &agent_bytes).expect("agent bytes should be writable");
        std::fs::write(&launcher_path, &launcher_bytes).expect("launcher bytes should be writable");

        let config = AssembleConfig {
            agent_elf_path: agent_path,
            launcher_path,
            master_secret: [1_u8; 32],
            stable_fingerprint_hash: [2_u8; 32],
            user_fingerprint: [3_u8; 32],
            mode: AgentMode::Batch,
            backend_name: "go".to_string(),
        };

        let assembled = assemble(&config).expect("assembly should succeed");

        let env_key = derive_env_key(
            &config.master_secret,
            &config.stable_fingerprint_hash,
            &config.user_fingerprint,
        )
        .expect("key derivation should succeed");
        let launcher_with_secret =
            embed_master_secret(&launcher_bytes, &config.master_secret).expect("secret embed");
        let mut tamper_hash = [0_u8; 32];
        tamper_hash.copy_from_slice(&Sha256::digest(&launcher_with_secret));
        let launcher_with_tamper =
            embed_tamper_hash(&launcher_with_secret, &tamper_hash).expect("tamper embed");
        let integrity_key = derive_key_with_integrity_from_binary(&env_key, &launcher_with_tamper)
            .expect("integrity key");
        let expected_payload = pack_payload_with_mode(
            Cursor::new(agent_bytes.clone()),
            &integrity_key,
            AgentMode::Batch,
        )
        .expect("payload packing should succeed");

        assert!(assembled.len() > launcher_bytes.len());

        let footer_size = write_footer(&PayloadFooter {
            original_hash: [0_u8; 32],
            launcher_hash: [0_u8; 32],
            backend_type: BackendType::Unknown,
        })
        .len();
        let launcher_len = assembled.len()
            - expected_payload.len()
            - LAUNCHER_PAYLOAD_SENTINEL.len()
            - footer_size;
        let sentinel_start = launcher_len;
        let payload_start = sentinel_start + LAUNCHER_PAYLOAD_SENTINEL.len();
        let footer_start = payload_start + expected_payload.len();

        assert_eq!(
            &assembled[sentinel_start..payload_start],
            LAUNCHER_PAYLOAD_SENTINEL
        );

        let payload_section = &assembled[payload_start..footer_start];
        assert_eq!(payload_section.len(), expected_payload.len());
        assert!(payload_section.len() > 20);
        assert_eq!(&payload_section[..4], b"ASL\x01");

        let footer_section = &assembled[footer_start..];
        assert_eq!(footer_section.len(), footer_size);
    }

    #[test]
    fn payload_section_round_trip_after_assembly() {
        let root = test_root("roundtrip");
        std::fs::create_dir_all(&root).expect("test root should be creatable");

        let agent_path = root.join("agent.bin");
        let launcher_path = root.join("launcher.bin");

        let agent_bytes = b"#!/usr/bin/env python3\nprint('hello')\n".to_vec();
        let launcher_bytes = launcher_with_markers(0x11);

        std::fs::write(&agent_path, &agent_bytes).expect("agent bytes should be writable");
        std::fs::write(&launcher_path, &launcher_bytes).expect("launcher bytes should be writable");

        let master_secret = [9_u8; 32];
        let stable_fingerprint_hash = [8_u8; 32];
        let user_fingerprint = [7_u8; 32];

        let config = AssembleConfig {
            agent_elf_path: agent_path,
            launcher_path,
            master_secret,
            stable_fingerprint_hash,
            user_fingerprint,
            mode: AgentMode::Batch,
            backend_name: "pyinstaller".to_string(),
        };

        let assembled = assemble(&config).expect("assembly should succeed");

        // Find the payload sentinel to extract the launcher portion
        let sentinel_pos = assembled
            .windows(LAUNCHER_PAYLOAD_SENTINEL.len())
            .position(|w| w == LAUNCHER_PAYLOAD_SENTINEL)
            .expect("sentinel should be found");

        let env_key = derive_env_key(&master_secret, &stable_fingerprint_hash, &user_fingerprint)
            .expect("key derivation should succeed");

        // Derive integrity key from the actual launcher portion in the assembled binary
        let launcher_portion = &assembled[..sentinel_pos];
        let integrity_key = derive_key_with_integrity_from_binary(&env_key, launcher_portion)
            .expect("integrity key");
        let payload_len = pack_payload_with_mode(
            Cursor::new(agent_bytes.clone()),
            &integrity_key,
            AgentMode::Batch,
        )
        .expect("payload packing should succeed")
        .len();
        let footer_len = write_footer(&PayloadFooter {
            original_hash: [0_u8; 32],
            launcher_hash: [0_u8; 32],
            backend_type: BackendType::Unknown,
        })
        .len();
        let payload_start = assembled.len() - payload_len - footer_len;
        assert_eq!(
            &assembled[payload_start - LAUNCHER_PAYLOAD_SENTINEL.len()..payload_start],
            LAUNCHER_PAYLOAD_SENTINEL
        );
        let payload_section = &assembled[payload_start..payload_start + payload_len];

        let (decrypted, _header) = unpack_payload(Cursor::new(payload_section), &integrity_key)
            .expect("payload should unpack");

        assert_eq!(decrypted, agent_bytes);
    }

    #[test]
    fn assembled_binary_footer_round_trips() {
        let root = test_root("footer");
        std::fs::create_dir_all(&root).expect("test root should be creatable");

        let agent_path = root.join("agent.bin");
        let launcher_path = root.join("launcher.bin");

        let agent_bytes = b"agent-body".to_vec();
        let launcher_bytes = launcher_with_markers(0x22);

        std::fs::write(&agent_path, &agent_bytes).expect("agent bytes should be writable");
        std::fs::write(&launcher_path, &launcher_bytes).expect("launcher bytes should be writable");

        let config = AssembleConfig {
            agent_elf_path: agent_path,
            launcher_path,
            master_secret: [4_u8; 32],
            stable_fingerprint_hash: [5_u8; 32],
            user_fingerprint: [6_u8; 32],
            mode: AgentMode::Batch,
            backend_name: "nuitka".to_string(),
        };

        let assembled = assemble(&config).expect("assembly should succeed");
        let footer_size = write_footer(&PayloadFooter {
            original_hash: [0_u8; 32],
            launcher_hash: [0_u8; 32],
            backend_type: BackendType::Unknown,
        })
        .len();
        let footer_bytes = &assembled[assembled.len() - footer_size..];
        let footer = read_footer(footer_bytes).expect("footer should parse");

        let mut expected_original_hash = [0_u8; 32];
        expected_original_hash.copy_from_slice(&Sha256::digest(&agent_bytes));
        assert_eq!(footer.original_hash, expected_original_hash);

        let serialized = write_footer(&footer);
        assert_eq!(serialized.as_slice(), footer_bytes);

        let expected_footer = PayloadFooter {
            original_hash: footer.original_hash,
            launcher_hash: footer.launcher_hash,
            backend_type: BackendType::Nuitka,
        };
        assert_eq!(footer, expected_footer);
    }

    #[test]
    fn assemble_returns_error_when_launcher_missing_secret_marker() {
        let root = test_root("missing-secret-marker");
        std::fs::create_dir_all(&root).expect("test root should be creatable");

        let agent_path = root.join("agent.bin");
        let launcher_path = root.join("launcher.bin");
        std::fs::write(&agent_path, [0xAA; 32]).expect("agent bytes should be writable");
        std::fs::write(&launcher_path, [0xBB; 128]).expect("launcher bytes should be writable");

        let err = assemble(&AssembleConfig {
            agent_elf_path: agent_path,
            launcher_path,
            master_secret: [1_u8; 32],
            stable_fingerprint_hash: [2_u8; 32],
            user_fingerprint: [3_u8; 32],
            mode: AgentMode::Batch,
            backend_name: "go".to_string(),
        })
        .expect_err("launcher without markers should fail embedding");

        assert!(
            matches!(err, SealError::CompilationError(message) if message.contains("EmbedFailed: marker 1 not found"))
        );
    }

    #[test]
    fn assemble_sets_footer_launcher_hash_from_embedded_launcher() {
        let root = test_root("launcher-hash");
        std::fs::create_dir_all(&root).expect("test root should be creatable");

        let agent_path = root.join("agent.bin");
        let launcher_path = root.join("launcher.bin");
        let agent_bytes = b"agent-footer-hash".to_vec();
        let launcher_bytes = launcher_with_markers(0x6A);

        std::fs::write(&agent_path, &agent_bytes).expect("agent bytes should be writable");
        std::fs::write(&launcher_path, &launcher_bytes).expect("launcher bytes should be writable");

        let config = AssembleConfig {
            agent_elf_path: agent_path,
            launcher_path,
            master_secret: [7_u8; 32],
            stable_fingerprint_hash: [8_u8; 32],
            user_fingerprint: [9_u8; 32],
            mode: AgentMode::Batch,
            backend_name: "go".to_string(),
        };

        let assembled = assemble(&config).expect("assembly should succeed");
        let footer_size = 65; // FOOTER_SIZE = HASH_SIZE + HASH_SIZE + 1 (backend_type byte)
        let footer =
            read_footer(&assembled[assembled.len() - footer_size..]).expect("footer should parse");

        let env_key = derive_env_key(
            &config.master_secret,
            &config.stable_fingerprint_hash,
            &config.user_fingerprint,
        )
        .expect("key derivation should succeed");
        let launcher_with_secret =
            embed_master_secret(&launcher_bytes, &config.master_secret).expect("secret embed");
        let mut tamper_hash = [0_u8; 32];
        tamper_hash.copy_from_slice(&Sha256::digest(&launcher_with_secret));
        let launcher_with_tamper =
            embed_tamper_hash(&launcher_with_secret, &tamper_hash).expect("tamper embed");
        let integrity_key = derive_key_with_integrity_from_binary(&env_key, &launcher_with_tamper)
            .expect("integrity key");
        let encrypted_payload =
            pack_payload_with_mode(Cursor::new(&agent_bytes), &integrity_key, AgentMode::Batch)
                .expect("payload packing should succeed");
        let launcher_len = assembled.len()
            - LAUNCHER_PAYLOAD_SENTINEL.len()
            - encrypted_payload.len()
            - footer_size;
        let launcher_with_tamper = &assembled[..launcher_len];

        let regions = find_integrity_regions(launcher_with_tamper).expect("regions");
        let expected_launcher_hash =
            compute_binary_integrity_hash(launcher_with_tamper, &regions).expect("hash");
        assert_eq!(footer.launcher_hash, expected_launcher_hash);
    }

    #[test]
    fn assemble_returns_io_error_for_missing_agent_file() {
        let root = test_root("missing-agent");
        std::fs::create_dir_all(&root).expect("test root should be creatable");

        let err = assemble(&AssembleConfig {
            agent_elf_path: root.join("does-not-exist-agent.bin"),
            launcher_path: root.join("launcher.bin"),
            master_secret: [1_u8; 32],
            stable_fingerprint_hash: [2_u8; 32],
            user_fingerprint: [3_u8; 32],
            mode: AgentMode::Batch,
            backend_name: "go".to_string(),
        })
        .expect_err("missing agent file should surface io error");

        assert!(matches!(err, SealError::Io(io) if io.kind() == std::io::ErrorKind::NotFound));
    }

    #[test]
    fn assemble_returns_io_error_for_missing_launcher_file() {
        let root = test_root("missing-launcher");
        std::fs::create_dir_all(&root).expect("test root should be creatable");

        let agent_path = root.join("agent.bin");
        std::fs::write(&agent_path, [0xAB; 16]).expect("agent bytes should be writable");

        let err = assemble(&AssembleConfig {
            agent_elf_path: agent_path,
            launcher_path: root.join("does-not-exist-launcher.bin"),
            master_secret: [1_u8; 32],
            stable_fingerprint_hash: [2_u8; 32],
            user_fingerprint: [3_u8; 32],
            mode: AgentMode::Batch,
            backend_name: "go".to_string(),
        })
        .expect_err("missing launcher file should surface io error");

        assert!(matches!(err, SealError::Io(io) if io.kind() == std::io::ErrorKind::NotFound));
    }
}
