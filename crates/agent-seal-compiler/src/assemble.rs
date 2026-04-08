use crate::embed::{embed_master_secret, embed_tamper_hash};
use agent_seal_core::{
    derive::derive_env_key,
    error::SealError,
    payload::{pack_payload, write_footer},
    types::{LAUNCHER_PAYLOAD_SENTINEL, PayloadFooter},
};
use sha2::{Digest, Sha256};
use std::{io::Cursor, path::PathBuf};

pub struct AssembleConfig {
    pub agent_elf_path: PathBuf,
    pub launcher_path: PathBuf,
    pub master_secret: [u8; 32],
    pub stable_fingerprint_hash: [u8; 32],
    pub user_fingerprint: [u8; 32],
}

pub fn assemble(config: &AssembleConfig) -> Result<Vec<u8>, SealError> {
    let agent_elf_bytes = std::fs::read(&config.agent_elf_path)?;
    let key = derive_env_key(
        &config.master_secret,
        &config.stable_fingerprint_hash,
        &config.user_fingerprint,
    )?;

    let encrypted_payload = pack_payload(Cursor::new(&agent_elf_bytes), &key)?;
    let launcher_bytes = std::fs::read(&config.launcher_path)?;

    let launcher_with_secret = embed_master_secret(&launcher_bytes, &config.master_secret)?;

    let mut tamper_hash = [0_u8; 32];
    tamper_hash.copy_from_slice(&Sha256::digest(&launcher_with_secret));
    let launcher_with_tamper = embed_tamper_hash(&launcher_with_secret, &tamper_hash)?;

    let mut original_hash = [0_u8; 32];
    original_hash.copy_from_slice(&Sha256::digest(&agent_elf_bytes));

    let mut launcher_hash = [0_u8; 32];
    launcher_hash.copy_from_slice(&Sha256::digest(&launcher_with_tamper));

    let footer = PayloadFooter {
        original_hash,
        launcher_hash,
    };
    let footer_bytes = write_footer(&footer);

    let mut assembled = Vec::with_capacity(
        launcher_with_tamper.len()
            + LAUNCHER_PAYLOAD_SENTINEL.len()
            + encrypted_payload.len()
            + footer_bytes.len(),
    );
    assembled.extend_from_slice(&launcher_with_tamper);
    assembled.extend_from_slice(LAUNCHER_PAYLOAD_SENTINEL);
    assembled.extend_from_slice(&encrypted_payload);
    assembled.extend_from_slice(&footer_bytes);
    Ok(assembled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_seal_core::{
        derive::derive_env_key,
        payload::{pack_payload, read_footer, unpack_payload, write_footer},
        types::{
            LAUNCHER_PAYLOAD_SENTINEL, LAUNCHER_SECRET_MARKER, LAUNCHER_TAMPER_MARKER,
            PayloadFooter,
        },
    };
    use std::io::Cursor;

    fn test_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("agent-seal-assemble-{name}"))
    }

    fn launcher_with_markers(fill: u8) -> Vec<u8> {
        let mut launcher = vec![fill; 256];
        launcher.extend_from_slice(LAUNCHER_SECRET_MARKER);
        launcher.extend_from_slice(&[0_u8; 32]);
        launcher.extend_from_slice(&[fill; 64]);
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
        };

        let assembled = assemble(&config).expect("assembly should succeed");

        let key = derive_env_key(
            &config.master_secret,
            &config.stable_fingerprint_hash,
            &config.user_fingerprint,
        )
        .expect("key derivation should succeed");
        let expected_payload = pack_payload(Cursor::new(agent_bytes.clone()), &key)
            .expect("payload packing should succeed");

        assert!(assembled.len() > launcher_bytes.len());

        let footer_size = 64;
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
        };

        let assembled = assemble(&config).expect("assembly should succeed");

        let key = derive_env_key(&master_secret, &stable_fingerprint_hash, &user_fingerprint)
            .expect("key derivation should succeed");
        let payload_len = pack_payload(Cursor::new(agent_bytes.clone()), &key)
            .expect("payload packing should succeed")
            .len();
        let footer_len = 64;
        let payload_start = assembled.len() - payload_len - footer_len;
        assert_eq!(
            &assembled[payload_start - LAUNCHER_PAYLOAD_SENTINEL.len()..payload_start],
            LAUNCHER_PAYLOAD_SENTINEL
        );
        let payload_section = &assembled[payload_start..payload_start + payload_len];

        let (decrypted, _header) =
            unpack_payload(Cursor::new(payload_section), &key).expect("payload should unpack");

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
        };

        let assembled = assemble(&config).expect("assembly should succeed");
        let footer_bytes = &assembled[assembled.len() - 64..];
        let footer = read_footer(footer_bytes).expect("footer should parse");

        let mut expected_original_hash = [0_u8; 32];
        expected_original_hash.copy_from_slice(&Sha256::digest(&agent_bytes));
        assert_eq!(footer.original_hash, expected_original_hash);

        let serialized = write_footer(&footer);
        assert_eq!(serialized.as_slice(), footer_bytes);

        let expected_footer = PayloadFooter {
            original_hash: footer.original_hash,
            launcher_hash: footer.launcher_hash,
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
        })
        .expect_err("launcher without markers should fail embedding");

        assert!(
            matches!(err, SealError::CompilationError(message) if message.contains("EmbedFailed: marker not found"))
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
        };

        let assembled = assemble(&config).expect("assembly should succeed");
        let footer = read_footer(&assembled[assembled.len() - 64..]).expect("footer should parse");

        let key = derive_env_key(
            &config.master_secret,
            &config.stable_fingerprint_hash,
            &config.user_fingerprint,
        )
        .expect("key derivation should succeed");
        let encrypted_payload =
            pack_payload(Cursor::new(&agent_bytes), &key).expect("payload packing should succeed");
        let launcher_len =
            assembled.len() - LAUNCHER_PAYLOAD_SENTINEL.len() - encrypted_payload.len() - 64;
        let launcher_with_tamper = &assembled[..launcher_len];

        let mut expected_launcher_hash = [0_u8; 32];
        expected_launcher_hash.copy_from_slice(&Sha256::digest(launcher_with_tamper));
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
        })
        .expect_err("missing launcher file should surface io error");

        assert!(matches!(err, SealError::Io(io) if io.kind() == std::io::ErrorKind::NotFound));
    }
}
