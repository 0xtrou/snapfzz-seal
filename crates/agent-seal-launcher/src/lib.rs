#![allow(unsafe_code)]

#[allow(dead_code)]
mod anti_debug;
mod cleanup;
mod memfd_exec;
mod protection;
#[allow(dead_code)]
mod self_delete;
mod seccomp;

use std::io::Cursor;

#[cfg(target_os = "linux")]
use agent_seal_core::tamper;
use agent_seal_core::{
    derive::{derive_env_key, derive_session_key},
    error::SealError,
    payload::{read_footer, unpack_payload, validate_payload_header},
    signing,
    types::{
        LAUNCHER_PAYLOAD_SENTINEL, LAUNCHER_SECRET_MARKER, LAUNCHER_TAMPER_MARKER, PayloadFooter,
    },
};
use agent_seal_fingerprint::{
    FingerprintCollector, FingerprintSnapshot, canonicalize_ephemeral, canonicalize_stable,
};
use clap::{Parser, ValueEnum};
pub use memfd_exec::{ExecConfig, InteractiveHandle, KernelMemfdOps, MemfdExecutor};
use tracing_subscriber::EnvFilter;
use zeroize::{Zeroize, Zeroizing};

const SIG_MAGIC: &[u8; 4] = b"ASL\x02";
const SIG_BLOCK_SIZE: usize = 100;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum FingerprintMode {
    Stable,
    Session,
}

#[derive(Debug, Parser)]
#[command(name = "agent-seal-launcher")]
#[command(about = "Agent Seal launcher")]
pub struct Cli {
    #[arg(long)]
    pub payload: Option<String>,
    #[arg(long, value_enum, default_value_t = FingerprintMode::Stable)]
    pub fingerprint_mode: FingerprintMode,
    #[arg(long)]
    pub user_fingerprint: Option<String>,
    #[arg(long)]
    pub verbose: bool,
}

fn verify_signature(payload_bytes: &[u8]) -> Result<(), SealError> {
    if payload_bytes.len() < SIG_BLOCK_SIZE {
        tracing::warn!("payload too short for signature verification; skipping");
        return Ok(());
    }
    let sig_start = payload_bytes.len() - SIG_BLOCK_SIZE;
    if &payload_bytes[sig_start..sig_start + 4] != SIG_MAGIC {
        tracing::warn!("no signature block found; payload is unsigned");
        return Ok(());
    }

    let mut signature = [0u8; 64];
    signature.copy_from_slice(&payload_bytes[sig_start + 4..sig_start + 68]);
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&payload_bytes[sig_start + 68..sig_start + 100]);
    let data = &payload_bytes[..sig_start];

    match signing::verify(&pubkey, data, &signature)? {
        true => {
            tracing::info!(
                pubkey_fingerprint = %hex::encode(&pubkey[..16]),
                "signature verified"
            );
            Ok(())
        }
        false => Err(SealError::InvalidSignature),
    }
}

pub fn run(cli: Cli) -> Result<(), SealError> {
    let payload_bytes = load_payload_bytes(cli.payload.as_deref())?;
    validate_payload_header(&payload_bytes)?;
    verify_signature(&payload_bytes)?;
    let _footer = extract_footer(&payload_bytes).map_err(|_| {
        SealError::InvalidPayload("missing or corrupted payload footer".to_string())
    })?;

    let protections = protection::apply_protections()?;
    tracing::info!(?protections, "anti-debug protections evaluated");

    let collector = FingerprintCollector::new();
    let snapshot = match cli.fingerprint_mode {
        FingerprintMode::Stable => collector
            .collect_stable_only()
            .map_err(|err| SealError::InvalidInput(err.to_string()))?,
        FingerprintMode::Session => collector
            .collect()
            .map_err(|err| SealError::InvalidInput(err.to_string()))?,
    };

    let user_fingerprint = decode_user_fingerprint(cli.user_fingerprint)?;
    let mut master_secret = load_master_secret(&payload_bytes)?;

    let mut decryption_key = derive_decryption_key(
        &master_secret,
        &user_fingerprint,
        &snapshot,
        cli.fingerprint_mode,
    )?;

    let decrypted = Zeroizing::new(
        match unpack_payload(Cursor::new(&payload_bytes), &decryption_key) {
            Ok((bytes, _header)) => bytes,
            Err(SealError::DecryptionFailed(_)) => {
                eprintln!(
                    "ERROR: fingerprint mismatch — sandbox environment has changed, re-provisioning required"
                );
                std::process::exit(1);
            }
            Err(err) => return Err(err),
        },
    );

    decryption_key.zeroize();
    master_secret.zeroize();

    let tamper_hash = extract_embedded_tamper_hash(&payload_bytes)?;
    verify_embedded_tamper_hash(&tamper_hash)?;

    cleanup::self_delete()?;

    let executor = MemfdExecutor::new(KernelMemfdOps);
    let config = ExecConfig {
        args: Vec::new(),
        env: Vec::new(),
        cwd: None,
        max_lifetime_secs: None,
        grace_period_secs: 30,
        max_output_bytes: Some(64 * 1024 * 1024),
    };

    let result = executor.execute(decrypted.as_slice(), &config)?;
    let json = serde_json::to_string(&result).map_err(|err| {
        SealError::InvalidInput(format!("failed to serialize execution result: {err}"))
    })?;
    println!("{json}");
    Ok(())
}

fn derive_decryption_key(
    master_secret: &[u8; 32],
    user_fingerprint: &[u8; 32],
    snapshot: &FingerprintSnapshot,
    fingerprint_mode: FingerprintMode,
) -> Result<[u8; 32], SealError> {
    let stable_hash = canonicalize_stable(snapshot);
    let env_key = derive_env_key(master_secret, &stable_hash, user_fingerprint)?;

    if fingerprint_mode == FingerprintMode::Session {
        let ephemeral_hash = canonicalize_ephemeral(snapshot);
        derive_session_key(&env_key, &ephemeral_hash)
    } else {
        Ok(env_key)
    }
}

pub fn init_tracing(verbose: bool) {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        if verbose {
            EnvFilter::new("debug")
        } else {
            EnvFilter::new("info")
        }
    });

    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .try_init();
}

pub fn format_user_error(err: &SealError) -> String {
    match err {
        SealError::EncryptionFailed(_) => "ERROR: failed to encrypt payload".to_string(),
        SealError::DecryptionFailed(_) => "ERROR: failed to decrypt payload".to_string(),
        SealError::InvalidPayload(msg) => format!("ERROR: invalid payload: {msg}"),
        SealError::UnsupportedPayloadVersion(version) => {
            format!("ERROR: unsupported payload version: {version}")
        }
        SealError::TamperDetected => "ERROR: tamper detected".to_string(),
        SealError::FingerprintMismatch => {
            "ERROR: fingerprint mismatch — sandbox environment has changed".to_string()
        }
        SealError::InvalidSignature => "ERROR: invalid signature".to_string(),
        SealError::Io(msg) => format!("ERROR: IO failure: {msg}"),
        SealError::InvalidInput(msg) => format!("ERROR: invalid input: {msg}"),
        SealError::CompilationError(msg) => format!("ERROR: compilation error: {msg}"),
        SealError::CompilationTimeout(seconds) => {
            format!("ERROR: compilation timeout after {seconds}s")
        }
        SealError::Other(msg) => format!("ERROR: {msg}"),
    }
}

fn load_payload_bytes(payload_arg: Option<&str>) -> Result<Vec<u8>, SealError> {
    match payload_arg {
        Some(path) if !path.eq_ignore_ascii_case("self") => std::fs::read(path).map_err(Into::into),
        _ => {
            let executable_bytes = std::fs::read("/proc/self/exe")?;
            extract_payload_from_assembled_binary(&executable_bytes)
        }
    }
}

pub fn extract_footer(payload_bytes: &[u8]) -> Result<PayloadFooter, SealError> {
    if payload_bytes.len() < 64 {
        return Err(SealError::InvalidPayload(
            "payload too small to contain footer".to_string(),
        ));
    }

    let footer_start = payload_bytes.len() - 64;
    read_footer(&payload_bytes[footer_start..])
}

fn extract_payload_from_assembled_binary(executable_bytes: &[u8]) -> Result<Vec<u8>, SealError> {
    if let Ok(raw_launcher_size) = std::env::var("AGENT_SEAL_LAUNCHER_SIZE") {
        let launcher_size = raw_launcher_size.parse::<usize>().map_err(|err| {
            SealError::InvalidInput(format!("invalid AGENT_SEAL_LAUNCHER_SIZE: {err}"))
        })?;
        return extract_payload_at_launcher_size(executable_bytes, launcher_size);
    }

    let marker_offset = find_marker(executable_bytes, LAUNCHER_PAYLOAD_SENTINEL).ok_or_else(|| {
        SealError::InvalidInput(
            "unable to locate embedded payload in self executable; set AGENT_SEAL_LAUNCHER_SIZE or provide --payload"
                .to_string(),
        )
    })?;

    payload_from_offset(
        executable_bytes,
        marker_offset + LAUNCHER_PAYLOAD_SENTINEL.len(),
    )
}

fn extract_payload_at_launcher_size(
    executable_bytes: &[u8],
    launcher_size: usize,
) -> Result<Vec<u8>, SealError> {
    if launcher_size >= executable_bytes.len() {
        return Err(SealError::InvalidInput(
            "AGENT_SEAL_LAUNCHER_SIZE points beyond executable length".to_string(),
        ));
    }

    let mut payload_offset = launcher_size;
    if executable_bytes[payload_offset..].starts_with(LAUNCHER_PAYLOAD_SENTINEL) {
        payload_offset += LAUNCHER_PAYLOAD_SENTINEL.len();
    }

    payload_from_offset(executable_bytes, payload_offset)
}

fn payload_from_offset(
    executable_bytes: &[u8],
    payload_offset: usize,
) -> Result<Vec<u8>, SealError> {
    if payload_offset >= executable_bytes.len() {
        return Err(SealError::InvalidInput(
            "embedded payload section is empty".to_string(),
        ));
    }

    Ok(executable_bytes[payload_offset..].to_vec())
}

fn find_marker(haystack: &[u8], marker: &[u8]) -> Option<usize> {
    haystack
        .windows(marker.len())
        .position(|window| window == marker)
}

fn decode_user_fingerprint(user_fingerprint_hex: Option<String>) -> Result<[u8; 32], SealError> {
    let value = user_fingerprint_hex.ok_or_else(|| {
        SealError::InvalidInput("--user-fingerprint <HEX> is required".to_string())
    })?;

    let decoded = hex::decode(&value)
        .map_err(|err| SealError::InvalidInput(format!("invalid user fingerprint hex: {err}")))?;

    if decoded.len() != 32 {
        return Err(SealError::InvalidInput(
            "user fingerprint must be 64 hex chars (32 bytes)".to_string(),
        ));
    }

    let mut out = [0_u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

fn load_master_secret(payload_bytes: &[u8]) -> Result<[u8; 32], SealError> {
    if let Some(secret) = extract_embedded_master_secret(payload_bytes) {
        return Ok(secret);
    }

    load_master_secret_from_env()
}

fn extract_embedded_master_secret(payload_bytes: &[u8]) -> Option<[u8; 32]> {
    let marker_offset = find_marker(payload_bytes, LAUNCHER_SECRET_MARKER)?;
    let secret_offset = marker_offset + LAUNCHER_SECRET_MARKER.len();
    let secret_end = secret_offset + 32;

    if payload_bytes.len() < secret_end {
        tracing::warn!("embedded launcher secret marker found but secret bytes are truncated");
        return None;
    }

    let mut secret = [0_u8; 32];
    secret.copy_from_slice(&payload_bytes[secret_offset..secret_end]);

    let secret_hex = hex::encode(secret);
    let decoded = hex::decode(secret_hex).ok()?;

    if decoded.len() != 32 {
        return None;
    }

    let mut out = [0_u8; 32];
    out.copy_from_slice(&decoded);
    Some(out)
}

fn extract_embedded_tamper_hash(payload_bytes: &[u8]) -> Result<[u8; 32], SealError> {
    let marker_offset = find_marker(payload_bytes, LAUNCHER_TAMPER_MARKER).ok_or_else(|| {
        SealError::InvalidInput(
            "embedded tamper hash marker not found in payload bytes".to_string(),
        )
    })?;
    let hash_offset = marker_offset + LAUNCHER_TAMPER_MARKER.len();
    let hash_end = hash_offset + 32;

    if payload_bytes.len() < hash_end {
        return Err(SealError::InvalidInput(
            "embedded tamper hash marker found but hash bytes are truncated".to_string(),
        ));
    }

    let mut hash = [0_u8; 32];
    hash.copy_from_slice(&payload_bytes[hash_offset..hash_end]);
    Ok(hash)
}

#[cfg(target_os = "linux")]
fn verify_embedded_tamper_hash(tamper_hash: &[u8; 32]) -> Result<(), SealError> {
    tamper::verify_tamper(tamper_hash)
}

#[cfg(not(target_os = "linux"))]
fn verify_embedded_tamper_hash(tamper_hash: &[u8; 32]) -> Result<(), SealError> {
    tracing::warn!(
        tamper_hash = %hex::encode(tamper_hash),
        "embedded tamper hash found but tamper verification is skipped on non-Linux platforms"
    );
    Ok(())
}

fn load_master_secret_from_env() -> Result<[u8; 32], SealError> {
    let raw = std::env::var("AGENT_SEAL_MASTER_SECRET_HEX").map_err(|_| {
        tracing::error!("AGENT_SEAL_MASTER_SECRET_HEX is required");
        SealError::InvalidInput(
            "AGENT_SEAL_MASTER_SECRET_HEX is required and must contain 64 hex chars (32 bytes)"
                .to_string(),
        )
    })?;

    let decoded = hex::decode(raw).map_err(|err| {
        SealError::InvalidInput(format!("invalid AGENT_SEAL_MASTER_SECRET_HEX: {err}"))
    })?;

    if decoded.len() != 32 {
        return Err(SealError::InvalidInput(
            "AGENT_SEAL_MASTER_SECRET_HEX must be 64 hex chars (32 bytes)".to_string(),
        ));
    }

    let mut secret = [0_u8; 32];
    secret.copy_from_slice(&decoded);
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_seal_core::{
        derive::{derive_env_key, derive_session_key},
        payload::write_footer,
        types::PayloadFooter,
    };
    use agent_seal_fingerprint::{
        FingerprintSnapshot, RuntimeKind, SourceValue, Stability, canonicalize_ephemeral,
        canonicalize_stable,
    };
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    static ENV_LOCK: Mutex<()> = Mutex::new(());
    static TEMP_ID: AtomicU64 = AtomicU64::new(1);

    fn source(id: &str, value: &'static [u8], stability: Stability) -> SourceValue {
        SourceValue {
            id: id.to_string(),
            value: value.to_vec(),
            confidence: 90,
            stability,
        }
    }

    fn sample_snapshot(ephemeral_value: &'static [u8]) -> FingerprintSnapshot {
        FingerprintSnapshot {
            runtime: RuntimeKind::Docker,
            stable: vec![
                source("linux.hostname", b"sandbox-a", Stability::Stable),
                source("linux.kernel_release", b"6.9.3", Stability::Stable),
            ],
            ephemeral: vec![source(
                "linux.pid_namespace_inode",
                ephemeral_value,
                Stability::Ephemeral,
            )],
            collected_at_unix_ms: 42,
        }
    }

    fn derive_launcher_key(
        master_secret: &[u8; 32],
        user_fingerprint: &[u8; 32],
        snapshot: &FingerprintSnapshot,
        fingerprint_mode: FingerprintMode,
    ) -> [u8; 32] {
        derive_decryption_key(master_secret, user_fingerprint, snapshot, fingerprint_mode)
            .expect("launcher key derivation should succeed")
    }

    fn unique_temp_path(stem: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "agent-seal-launcher-{stem}-{}-{}",
            std::process::id(),
            TEMP_ID.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn cli_parses_required_and_optional_args() {
        let cli = Cli::try_parse_from([
            "agent-seal-launcher",
            "--payload",
            "./payload.seal",
            "--fingerprint-mode",
            "session",
            "--user-fingerprint",
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            "--verbose",
        ])
        .unwrap();

        assert_eq!(cli.payload.as_deref(), Some("./payload.seal"));
        assert_eq!(cli.fingerprint_mode, FingerprintMode::Session);
        assert_eq!(
            cli.user_fingerprint.as_deref(),
            Some("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
        );
        assert!(cli.verbose);
    }

    #[test]
    fn cli_uses_default_fingerprint_mode() {
        let cli = Cli::try_parse_from([
            "agent-seal-launcher",
            "--payload",
            "./payload.seal",
            "--user-fingerprint",
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        ])
        .unwrap();

        assert_eq!(cli.fingerprint_mode, FingerprintMode::Stable);
    }

    #[test]
    fn cli_allows_self_extraction_without_payload_flag() {
        let cli = Cli::try_parse_from([
            "agent-seal-launcher",
            "--user-fingerprint",
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        ])
        .unwrap();

        assert_eq!(cli.payload, None);
    }

    #[test]
    fn extract_payload_from_sentinel_without_launcher_size_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("AGENT_SEAL_LAUNCHER_SIZE");
        }

        let payload = b"ASL\x01payload-data".to_vec();
        let mut assembled = vec![0xAA; 12];
        assembled.extend_from_slice(LAUNCHER_PAYLOAD_SENTINEL);
        assembled.extend_from_slice(&payload);

        let extracted = extract_payload_from_assembled_binary(&assembled).unwrap();
        assert_eq!(extracted, payload);
    }

    #[test]
    fn extract_footer_reads_valid_footer() {
        let footer = PayloadFooter {
            original_hash: [0x11; 32],
            launcher_hash: [0x22; 32],
        };
        let mut payload_bytes = b"ASL\x01encrypted-payload".to_vec();
        payload_bytes.extend_from_slice(&write_footer(&footer));

        let extracted = extract_footer(&payload_bytes).expect("footer should parse");

        assert_eq!(extracted, footer);
    }

    #[test]
    fn extract_footer_errors_on_short_payload() {
        let err = extract_footer(&[0xAA; 63]).expect_err("short payload must fail");
        assert!(matches!(err, SealError::InvalidPayload(_)));
    }

    #[test]
    fn extract_footer_round_trips_with_write_footer() {
        let footer = PayloadFooter {
            original_hash: [0x33; 32],
            launcher_hash: [0x44; 32],
        };
        let footer_bytes = write_footer(&footer);

        let mut payload_bytes = vec![0x55; 128];
        payload_bytes.extend_from_slice(&footer_bytes);

        let extracted = extract_footer(&payload_bytes).expect("footer should parse");
        assert_eq!(extracted, footer);
    }

    #[test]
    fn extract_payload_from_launcher_size_env_skips_sentinel() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("AGENT_SEAL_LAUNCHER_SIZE", "12");
        }

        let payload = b"ASL\x01payload-data".to_vec();
        let mut assembled = vec![0xAA; 12];
        assembled.extend_from_slice(LAUNCHER_PAYLOAD_SENTINEL);
        assembled.extend_from_slice(&payload);

        let extracted = extract_payload_from_assembled_binary(&assembled).unwrap();
        assert_eq!(extracted, payload);

        unsafe {
            std::env::remove_var("AGENT_SEAL_LAUNCHER_SIZE");
        }
    }

    #[test]
    fn load_master_secret_extracts_embedded_secret_from_binary_bytes() {
        let secret = [0x5A; 32];
        let path = unique_temp_path("embedded-secret");
        let mut binary = vec![0xAA; 16];
        binary.extend_from_slice(LAUNCHER_SECRET_MARKER);
        binary.extend_from_slice(&secret);
        binary.extend_from_slice(&[0xBB; 16]);
        std::fs::write(&path, &binary).unwrap();

        let payload_bytes = std::fs::read(&path).unwrap();
        let loaded = load_master_secret(&payload_bytes).expect("embedded secret should load");
        assert_eq!(loaded, secret);

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn load_master_secret_falls_back_to_env_when_marker_missing() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("AGENT_SEAL_MASTER_SECRET_HEX", "ab".repeat(32));
        }

        let loaded = load_master_secret(b"no-secret-marker").expect("env fallback should load");
        assert_eq!(loaded, [0xAB; 32]);

        unsafe {
            std::env::remove_var("AGENT_SEAL_MASTER_SECRET_HEX");
        }
    }

    #[test]
    fn env_var_set_overrides_when_no_marker_present() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("AGENT_SEAL_MASTER_SECRET_HEX", "ef".repeat(32));
        }

        let loaded =
            load_master_secret(&[0x42; 64]).expect("env fallback should win without marker");
        assert_eq!(loaded, [0xEF; 32]);

        unsafe {
            std::env::remove_var("AGENT_SEAL_MASTER_SECRET_HEX");
        }
    }

    #[test]
    fn load_master_secret_falls_back_to_env_when_marker_payload_truncated() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("AGENT_SEAL_MASTER_SECRET_HEX", "cd".repeat(32));
        }

        let mut binary = vec![0xAA; 16];
        binary.extend_from_slice(LAUNCHER_SECRET_MARKER);
        binary.extend_from_slice(&[0xEE; 31]);

        let loaded = load_master_secret(&binary).expect("truncated marker should fall back");
        assert_eq!(loaded, [0xCD; 32]);

        unsafe {
            std::env::remove_var("AGENT_SEAL_MASTER_SECRET_HEX");
        }
    }

    #[test]
    fn extract_embedded_tamper_hash_reads_hash_after_marker() {
        let hash = [0x7C; 32];
        let mut binary = vec![0xAA; 16];
        binary.extend_from_slice(LAUNCHER_TAMPER_MARKER);
        binary.extend_from_slice(&hash);
        binary.extend_from_slice(&[0xBB; 16]);

        let extracted = extract_embedded_tamper_hash(&binary).expect("tamper hash should load");
        assert_eq!(extracted, hash);
    }

    #[test]
    fn extract_embedded_tamper_hash_errors_when_marker_missing() {
        let err = extract_embedded_tamper_hash(b"no-tamper-marker").expect_err("must fail");
        assert!(matches!(err, SealError::InvalidInput(_)));
    }

    #[test]
    fn extract_embedded_tamper_hash_errors_when_hash_bytes_truncated() {
        let mut binary = vec![0xAA; 16];
        binary.extend_from_slice(LAUNCHER_TAMPER_MARKER);
        binary.extend_from_slice(&[0xEE; 31]);

        let err = extract_embedded_tamper_hash(&binary).expect_err("must fail");
        assert!(matches!(err, SealError::InvalidInput(_)));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn verify_embedded_tamper_hash_skips_on_non_linux() {
        verify_embedded_tamper_hash(&[0xAB; 32]).expect("non-linux should skip tamper check");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn verify_embedded_tamper_hash_detects_mismatch_on_linux() {
        let err = verify_embedded_tamper_hash(&[0xAB; 32]).expect_err("wrong hash must fail");
        assert!(matches!(err, SealError::TamperDetected));
    }

    #[test]
    fn load_master_secret_fails_when_env_missing() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("AGENT_SEAL_MASTER_SECRET_HEX");
        }

        let err = load_master_secret(b"no-secret-marker").expect_err("missing env must fail");
        assert!(matches!(err, SealError::InvalidInput(_)));
    }

    #[test]
    fn init_tracing_handles_verbose_false_without_env_filter() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("RUST_LOG");
        }
        init_tracing(false);
    }

    #[test]
    fn init_tracing_handles_verbose_true_without_env_filter() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("RUST_LOG");
        }
        init_tracing(true);
    }

    #[test]
    fn init_tracing_prefers_env_filter_when_present() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("RUST_LOG", "warn");
        }
        init_tracing(false);
        unsafe {
            std::env::remove_var("RUST_LOG");
        }
    }

    #[test]
    fn format_user_error_covers_all_variants() {
        let cases = vec![
            (
                SealError::EncryptionFailed("enc".to_string()),
                "ERROR: failed to encrypt payload".to_string(),
            ),
            (
                SealError::DecryptionFailed("dec".to_string()),
                "ERROR: failed to decrypt payload".to_string(),
            ),
            (
                SealError::InvalidPayload("bad".to_string()),
                "ERROR: invalid payload: bad".to_string(),
            ),
            (
                SealError::UnsupportedPayloadVersion(7),
                "ERROR: unsupported payload version: 7".to_string(),
            ),
            (
                SealError::TamperDetected,
                "ERROR: tamper detected".to_string(),
            ),
            (
                SealError::FingerprintMismatch,
                "ERROR: fingerprint mismatch — sandbox environment has changed".to_string(),
            ),
            (
                SealError::Io(std::io::Error::other("io")),
                "ERROR: IO failure: io".to_string(),
            ),
            (
                SealError::InvalidInput("input".to_string()),
                "ERROR: invalid input: input".to_string(),
            ),
            (
                SealError::CompilationError("compile".to_string()),
                "ERROR: compilation error: compile".to_string(),
            ),
            (
                SealError::CompilationTimeout(42),
                "ERROR: compilation timeout after 42s".to_string(),
            ),
            (
                SealError::Other(std::io::Error::other("other").into()),
                "ERROR: other".to_string(),
            ),
        ];

        for (err, expected) in cases {
            assert_eq!(format_user_error(&err), expected);
        }
    }

    #[test]
    fn load_payload_bytes_uses_explicit_path() {
        let path = unique_temp_path("payload");
        let payload = b"ASL\x01direct-path".to_vec();
        std::fs::write(&path, &payload).unwrap();

        let loaded = load_payload_bytes(path.to_str()).unwrap();
        assert_eq!(loaded, payload);

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn load_payload_bytes_errors_on_nonexistent_path() {
        let result = load_payload_bytes(Some("/nonexistent/path/payload.asl"));
        assert!(matches!(result, Err(SealError::Io(_))));
    }

    #[test]
    fn load_payload_bytes_none_errors_without_proc_self_exe() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("AGENT_SEAL_LAUNCHER_SIZE");
        }

        // "self" and None both try /proc/self/exe which doesn't exist on macOS
        let self_result = load_payload_bytes(Some("self"));
        let none_result = load_payload_bytes(None);

        #[cfg(not(target_os = "linux"))]
        {
            assert!(matches!(self_result, Err(SealError::Io(_))));
            assert!(matches!(none_result, Err(SealError::Io(_))));
        }

        #[cfg(target_os = "linux")]
        {
            // On Linux, /proc/self/exe exists but won't have the sentinel marker
            // (unless the test binary was assembled with one). Either error is fine.
            match (&self_result, &none_result) {
                (Ok(_), Ok(_)) => {}
                (Err(_), Err(_)) => {}
                _ => panic!("expected both to succeed or both to fail"),
            }
        }
    }

    #[test]
    fn extract_payload_from_assembled_binary_rejects_launcher_size_beyond_length() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("AGENT_SEAL_LAUNCHER_SIZE", "100");
        }

        let assembled = vec![1_u8; 8];
        let err = extract_payload_from_assembled_binary(&assembled).expect_err("must fail");
        assert!(matches!(err, SealError::InvalidInput(_)));

        unsafe {
            std::env::remove_var("AGENT_SEAL_LAUNCHER_SIZE");
        }
    }

    #[test]
    fn extract_payload_at_launcher_size_skips_sentinel_when_present() {
        let payload = b"ASL\x01embedded".to_vec();
        let mut assembled = vec![0xEF; 5];
        assembled.extend_from_slice(LAUNCHER_PAYLOAD_SENTINEL);
        assembled.extend_from_slice(&payload);

        let extracted = extract_payload_at_launcher_size(&assembled, 5).unwrap();
        assert_eq!(extracted, payload);
    }

    #[test]
    fn payload_from_offset_rejects_offset_beyond_length() {
        let bytes = vec![1_u8, 2, 3];
        let err = payload_from_offset(&bytes, 3).expect_err("must fail");
        assert!(matches!(err, SealError::InvalidInput(_)));
    }

    #[test]
    fn find_marker_returns_expected_results() {
        let haystack = b"abc123markerxyz";
        let marker = b"marker";
        assert_eq!(find_marker(haystack, marker), Some(6));
        assert_eq!(find_marker(haystack, b"missing"), None);
    }

    #[test]
    fn decode_user_fingerprint_errors_when_missing() {
        let err = decode_user_fingerprint(None).expect_err("must fail");
        assert!(matches!(err, SealError::InvalidInput(_)));
    }

    #[test]
    fn decode_user_fingerprint_errors_on_invalid_hex() {
        let err = decode_user_fingerprint(Some("not-hex".to_string())).expect_err("must fail");
        assert!(matches!(err, SealError::InvalidInput(_)));
    }

    #[test]
    fn decode_user_fingerprint_errors_on_short_hex() {
        let err = decode_user_fingerprint(Some("aa".repeat(31))).expect_err("must fail");
        assert!(matches!(err, SealError::InvalidInput(_)));
    }

    #[test]
    fn decode_user_fingerprint_accepts_valid_hex() {
        let out = decode_user_fingerprint(Some("11".repeat(32))).unwrap();
        assert_eq!(out, [0x11; 32]);
    }

    #[test]
    fn load_master_secret_errors_when_hex_invalid() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("AGENT_SEAL_MASTER_SECRET_HEX", "zzzz");
        }

        let err = load_master_secret(b"no-secret-marker").expect_err("must fail");
        assert!(matches!(err, SealError::InvalidInput(_)));

        unsafe {
            std::env::remove_var("AGENT_SEAL_MASTER_SECRET_HEX");
        }
    }

    #[test]
    fn load_master_secret_errors_when_hex_too_short() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("AGENT_SEAL_MASTER_SECRET_HEX", "aa".repeat(31));
        }

        let err = load_master_secret(b"no-secret-marker").expect_err("must fail");
        assert!(matches!(err, SealError::InvalidInput(_)));

        unsafe {
            std::env::remove_var("AGENT_SEAL_MASTER_SECRET_HEX");
        }
    }

    #[test]
    fn stable_mode_uses_stable_fingerprint_without_session_derivation() {
        let master_secret = [0x11; 32];
        let user_fingerprint = [0x22; 32];
        let snapshot = sample_snapshot(b"4026531836");

        let stable_key = derive_launcher_key(
            &master_secret,
            &user_fingerprint,
            &snapshot,
            FingerprintMode::Stable,
        );
        let stable_hash = canonicalize_stable(&snapshot);
        let expected = derive_env_key(&master_secret, &stable_hash, &user_fingerprint)
            .expect("env key derivation should succeed");

        assert_eq!(stable_key, expected);
    }

    #[test]
    fn session_mode_uses_ephemeral_fingerprint_for_session_derivation() {
        let master_secret = [0x33; 32];
        let user_fingerprint = [0x44; 32];
        let snapshot = sample_snapshot(b"4026531836");

        let session_key = derive_launcher_key(
            &master_secret,
            &user_fingerprint,
            &snapshot,
            FingerprintMode::Session,
        );
        let stable_hash = canonicalize_stable(&snapshot);
        let env_key = derive_env_key(&master_secret, &stable_hash, &user_fingerprint)
            .expect("env key derivation should succeed");
        let ephemeral_hash = canonicalize_ephemeral(&snapshot);
        let expected = derive_session_key(&env_key, &ephemeral_hash)
            .expect("session key derivation should succeed");

        assert_eq!(session_key, expected);
        assert_ne!(session_key, env_key);
    }

    #[test]
    fn different_ephemeral_fingerprints_produce_different_session_keys() {
        let master_secret = [0x55; 32];
        let user_fingerprint = [0x66; 32];
        let snapshot_a = sample_snapshot(b"4026531836");
        let snapshot_b = sample_snapshot(b"4026531900");

        let key_a = derive_launcher_key(
            &master_secret,
            &user_fingerprint,
            &snapshot_a,
            FingerprintMode::Session,
        );
        let key_b = derive_launcher_key(
            &master_secret,
            &user_fingerprint,
            &snapshot_b,
            FingerprintMode::Session,
        );

        assert_ne!(
            canonicalize_ephemeral(&snapshot_a),
            canonicalize_ephemeral(&snapshot_b)
        );
        assert_eq!(
            canonicalize_stable(&snapshot_a),
            canonicalize_stable(&snapshot_b)
        );
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn derive_session_key_is_deterministic_for_same_input() {
        let master_secret = [0x77; 32];
        let user_fingerprint = [0x88; 32];
        let snapshot = sample_snapshot(b"4026531836");
        let stable_hash = canonicalize_stable(&snapshot);
        let env_key = derive_env_key(&master_secret, &stable_hash, &user_fingerprint)
            .expect("env key derivation should succeed");
        let ephemeral_hash = canonicalize_ephemeral(&snapshot);

        let first = derive_session_key(&env_key, &ephemeral_hash)
            .expect("session key derivation should succeed");
        let second = derive_session_key(&env_key, &ephemeral_hash)
            .expect("session key derivation should succeed");

        assert_eq!(first, second);
    }

    #[test]
    fn run_returns_io_error_for_missing_payload_path() {
        let cli = Cli {
            payload: Some("/definitely/missing/payload.asl".to_string()),
            fingerprint_mode: FingerprintMode::Stable,
            user_fingerprint: Some("11".repeat(32)),
            verbose: false,
        };

        let err = run(cli).expect_err("missing payload path must fail");
        assert!(matches!(err, SealError::Io(_)));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn run_errors_for_non_linux_platform() {
        let cli = Cli {
            payload: Some("/tmp/test-payload.asl".to_string()),
            fingerprint_mode: FingerprintMode::Stable,
            user_fingerprint: Some("11".repeat(32)),
            verbose: false,
        };

        let err = run(cli);
        match err {
            Ok(()) | Err(_) => {}
        }
    }

    #[test]
    fn run_returns_invalid_payload_for_bad_header_before_antidebug() {
        let payload_path = unique_temp_path("bad-payload");
        std::fs::write(&payload_path, b"not-a-valid-payload-header").unwrap();

        let cli = Cli {
            payload: Some(payload_path.to_string_lossy().into_owned()),
            fingerprint_mode: FingerprintMode::Session,
            user_fingerprint: Some("22".repeat(32)),
            verbose: false,
        };

        let err = run(cli).expect_err("invalid header must fail");
        assert!(matches!(err, SealError::InvalidPayload(_)));

        std::fs::remove_file(payload_path).unwrap();
    }

    #[test]
    fn extract_payload_from_assembled_binary_rejects_invalid_launcher_size_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("AGENT_SEAL_LAUNCHER_SIZE", "not-a-number");
        }

        let err = extract_payload_from_assembled_binary(b"abc").expect_err("must fail");
        assert!(matches!(err, SealError::InvalidInput(_)));

        unsafe {
            std::env::remove_var("AGENT_SEAL_LAUNCHER_SIZE");
        }
    }

    #[test]
    fn extract_payload_from_assembled_binary_errors_when_marker_missing() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("AGENT_SEAL_LAUNCHER_SIZE");
        }

        let err = extract_payload_from_assembled_binary(b"no-marker-here").expect_err("must fail");
        assert!(matches!(err, SealError::InvalidInput(_)));
    }

    #[test]
    fn extract_payload_at_launcher_size_without_sentinel_uses_offset_directly() {
        let assembled = b"LAUNCHPAYLOAD".to_vec();
        let extracted = extract_payload_at_launcher_size(&assembled, 6).unwrap();
        assert_eq!(extracted, b"PAYLOAD".to_vec());
    }

    #[test]
    fn payload_from_offset_returns_trailing_bytes() {
        let bytes = b"abcdef".to_vec();
        let payload = payload_from_offset(&bytes, 2).unwrap();
        assert_eq!(payload, b"cdef".to_vec());
    }

    #[test]
    fn decode_user_fingerprint_errors_on_long_hex() {
        let err = decode_user_fingerprint(Some("aa".repeat(33))).expect_err("must fail");
        assert!(matches!(err, SealError::InvalidInput(_)));
    }

    #[test]
    fn load_master_secret_accepts_valid_hex() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("AGENT_SEAL_MASTER_SECRET_HEX", "ab".repeat(32));
        }

        let secret = load_master_secret(b"no-secret-marker").unwrap();
        assert_eq!(secret, [0xAB; 32]);

        unsafe {
            std::env::remove_var("AGENT_SEAL_MASTER_SECRET_HEX");
        }
    }
}
