use crate::{
    error::SealError,
    types::{
        LAUNCHER_PAYLOAD_SENTINEL, LAUNCHER_TAMPER_MARKER, SHAMIR_TOTAL_SHARES, get_secret_marker,
    },
};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityRegions {
    pub code_start: usize,
    pub code_end: usize,
    pub data_start: usize,
    pub data_end: usize,
    pub excluded: Vec<(usize, usize)>,
}

pub fn compute_binary_integrity_hash(
    binary: &[u8],
    regions: &IntegrityRegions,
) -> Result<[u8; 32], SealError> {
    validate_region(binary, regions.code_start, regions.code_end, "code")?;
    validate_region(binary, regions.data_start, regions.data_end, "data")?;

    let mut hasher = Sha256::new();
    let mut hashed_any = false;

    if regions.code_end > regions.code_start {
        hash_region_with_exclusions(
            &mut hasher,
            binary,
            regions.code_start,
            regions.code_end,
            &regions.excluded,
        );
        hashed_any = true;
    }

    if regions.data_end > regions.data_start {
        hash_region_with_exclusions(
            &mut hasher,
            binary,
            regions.data_start,
            regions.data_end,
            &regions.excluded,
        );
        hashed_any = true;
    }

    if !hashed_any {
        return Err(SealError::InvalidInput(
            "integrity hashing requires at least one non-empty region".to_string(),
        ));
    }

    let digest = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);
    Ok(hash)
}

pub fn find_integrity_regions(binary: &[u8]) -> Result<IntegrityRegions, SealError> {
    let excluded = find_secret_regions(binary);

    #[cfg(target_os = "linux")]
    if is_supported_elf(binary) {
        return parse_elf_regions(binary, excluded);
    }

    Ok(IntegrityRegions {
        code_start: 0,
        code_end: binary.len(),
        data_start: 0,
        data_end: 0,
        excluded,
    })
}

pub fn find_secret_regions(binary: &[u8]) -> Vec<(usize, usize)> {
    let mut regions = Vec::new();

    for idx in 0..SHAMIR_TOTAL_SHARES {
        collect_marker_regions(binary, get_secret_marker(idx), &mut regions);
    }
    collect_marker_regions(binary, LAUNCHER_TAMPER_MARKER, &mut regions);

    if let Some(payload_offset) = find_marker(binary, LAUNCHER_PAYLOAD_SENTINEL) {
        regions.push((payload_offset, binary.len()));
    }

    merge_regions(regions, binary.len())
}

pub fn derive_key_with_integrity_from_binary(
    embedded_secret: &[u8; 32],
    binary: &[u8],
) -> Result<[u8; 32], SealError> {
    #[cfg(target_os = "linux")]
    {
        let regions = find_integrity_regions(binary)?;
        let integrity_hash = compute_binary_integrity_hash(binary, &regions)?;
        Ok(bind_secret_to_hash(embedded_secret, &integrity_hash))
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = binary;
        Ok(bind_secret_to_hash(embedded_secret, embedded_secret))
    }
}

pub fn derive_key_with_integrity(
    embedded_secret: &[u8; 32],
    binary_path: Option<&str>,
) -> Result<[u8; 32], SealError> {
    #[cfg(target_os = "linux")]
    {
        let path = binary_path.unwrap_or("/proc/self/exe");
        let binary = std::fs::read(path)?;
        derive_key_with_integrity_from_binary(embedded_secret, &binary)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = binary_path;
        Ok(bind_secret_to_hash(embedded_secret, embedded_secret))
    }
}

pub fn verify_binary_integrity(
    expected_hash: &[u8; 32],
    binary_path: Option<&str>,
) -> Result<(), SealError> {
    #[cfg(target_os = "linux")]
    {
        let path = binary_path.unwrap_or("/proc/self/exe");
        let binary = std::fs::read(path)?;
        let regions = find_integrity_regions(&binary)?;
        let actual_hash = compute_binary_integrity_hash(&binary, &regions)?;

        if actual_hash == *expected_hash {
            Ok(())
        } else {
            Err(SealError::TamperDetected)
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = expected_hash;
        let _ = binary_path;
        Ok(())
    }
}

fn bind_secret_to_hash(secret: &[u8; 32], integrity_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(secret);
    hasher.update(integrity_hash);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn validate_region(binary: &[u8], start: usize, end: usize, label: &str) -> Result<(), SealError> {
    if start > end || end > binary.len() {
        return Err(SealError::InvalidInput(format!(
            "invalid {label} region {start}..{end} for binary of {} bytes",
            binary.len()
        )));
    }

    Ok(())
}

fn hash_region_with_exclusions(
    hasher: &mut Sha256,
    binary: &[u8],
    start: usize,
    end: usize,
    excluded: &[(usize, usize)],
) {
    let mut cursor = start;

    for (exclude_start, exclude_end) in excluded.iter().copied() {
        let clipped_start = exclude_start.max(start);
        let clipped_end = exclude_end.min(end);

        if clipped_start >= clipped_end {
            continue;
        }

        if cursor < clipped_start {
            hasher.update(&binary[cursor..clipped_start]);
        }

        cursor = cursor.max(clipped_end);
    }

    if cursor < end {
        hasher.update(&binary[cursor..end]);
    }
}

fn collect_marker_regions(binary: &[u8], marker: &[u8; 32], regions: &mut Vec<(usize, usize)>) {
    let mut search_from = 0usize;

    while search_from + marker.len() <= binary.len() {
        let Some(relative_offset) = binary[search_from..]
            .windows(marker.len())
            .position(|window| window == marker)
        else {
            break;
        };

        let marker_offset = search_from + relative_offset;
        let slot_end = (marker_offset + marker.len() + 32).min(binary.len());
        regions.push((marker_offset, slot_end));
        search_from = marker_offset + marker.len();
    }
}

fn merge_regions(mut regions: Vec<(usize, usize)>, binary_len: usize) -> Vec<(usize, usize)> {
    regions.retain(|(start, end)| start < end && *start < binary_len);
    regions.sort_unstable_by_key(|(start, _)| *start);

    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(regions.len());
    for (start, end) in regions {
        let end = end.min(binary_len);
        if let Some((_, previous_end)) = merged.last_mut()
            && start <= *previous_end
        {
            *previous_end = (*previous_end).max(end);
        } else {
            merged.push((start, end));
        }
    }

    merged
}

fn find_marker(binary: &[u8], marker: &[u8]) -> Option<usize> {
    binary
        .windows(marker.len())
        .position(|window| window == marker)
}

#[cfg(target_os = "linux")]
fn is_supported_elf(binary: &[u8]) -> bool {
    binary.len() >= 64
        && &binary[0..4] == b"\x7fELF"
        && binary[4] == 2
        && binary[5] == 1
        && u16::from_le_bytes([binary[18], binary[19]]) == 0x3e
}

#[cfg(target_os = "linux")]
fn parse_elf_regions(
    binary: &[u8],
    excluded: Vec<(usize, usize)>,
) -> Result<IntegrityRegions, SealError> {
    let phoff = read_u64(binary, 32)? as usize;
    let phentsize = read_u16(binary, 54)? as usize;
    let phnum = read_u16(binary, 56)? as usize;

    if phentsize < 56 {
        return Err(SealError::InvalidInput(
            "ELF program header entry size is too small".to_string(),
        ));
    }

    let mut code_range: Option<(usize, usize)> = None;
    let mut data_range: Option<(usize, usize)> = None;

    for index in 0..phnum {
        let header_offset = phoff
            .checked_add(index.saturating_mul(phentsize))
            .ok_or_else(|| SealError::InvalidInput("ELF program header overflow".to_string()))?;
        let header = read_slice(binary, header_offset, phentsize)?;

        let segment_type = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        if segment_type != 1 {
            continue;
        }

        let flags = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
        let file_offset = u64::from_le_bytes([
            header[8], header[9], header[10], header[11], header[12], header[13], header[14],
            header[15],
        ]) as usize;
        let file_size = u64::from_le_bytes([
            header[32], header[33], header[34], header[35], header[36], header[37], header[38],
            header[39],
        ]) as usize;

        if file_size == 0 {
            continue;
        }

        let segment_end = file_offset.checked_add(file_size).ok_or_else(|| {
            SealError::InvalidInput(
                "ELF segment overflow while parsing integrity regions".to_string(),
            )
        })?;
        if segment_end > binary.len() {
            return Err(SealError::InvalidInput(
                "ELF segment extends beyond binary size".to_string(),
            ));
        }

        if flags & 0x1 != 0 {
            extend_range(&mut code_range, file_offset, segment_end);
        } else {
            extend_range(&mut data_range, file_offset, segment_end);
        }
    }

    let code = code_range.ok_or_else(|| {
        SealError::InvalidInput(
            "ELF integrity parsing found no executable PT_LOAD segment".to_string(),
        )
    })?;

    let data = data_range.unwrap_or((0, 0));

    Ok(IntegrityRegions {
        code_start: code.0,
        code_end: code.1,
        data_start: data.0,
        data_end: data.1,
        excluded,
    })
}

#[cfg(target_os = "linux")]
fn read_u16(binary: &[u8], offset: usize) -> Result<u16, SealError> {
    let bytes = read_slice(binary, offset, 2)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

#[cfg(target_os = "linux")]
fn read_u64(binary: &[u8], offset: usize) -> Result<u64, SealError> {
    let bytes = read_slice(binary, offset, 8)?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

#[cfg(target_os = "linux")]
fn read_slice(binary: &[u8], offset: usize, len: usize) -> Result<&[u8], SealError> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| SealError::InvalidInput("ELF read overflow".to_string()))?;
    binary
        .get(offset..end)
        .ok_or_else(|| SealError::InvalidInput("ELF header extends beyond binary size".to_string()))
}

#[cfg(target_os = "linux")]
fn extend_range(range: &mut Option<(usize, usize)>, start: usize, end: usize) {
    match range {
        Some((existing_start, existing_end)) => {
            *existing_start = (*existing_start).min(start);
            *existing_end = (*existing_end).max(end);
        }
        None => *range = Some((start, end)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_binary_with_markers() -> Vec<u8> {
        let mut binary = vec![0xA5; 640];

        for idx in 0..SHAMIR_TOTAL_SHARES {
            let marker = get_secret_marker(idx);
            let start = 40 + idx * 64;
            binary[start..start + 32].copy_from_slice(marker);
            binary[start + 32..start + 64].fill(idx as u8 + 1);
        }

        let tamper_start = 420;
        binary[tamper_start..tamper_start + 32].copy_from_slice(LAUNCHER_TAMPER_MARKER);
        binary[tamper_start + 32..tamper_start + 64].fill(0xBB);

        let sentinel_start = 560;
        binary[sentinel_start..sentinel_start + 32].copy_from_slice(LAUNCHER_PAYLOAD_SENTINEL);

        binary
    }

    #[test]
    fn secret_regions_include_all_secret_slots_and_payload_tail() {
        let binary = sample_binary_with_markers();
        let excluded = find_secret_regions(&binary);

        for idx in 0..SHAMIR_TOTAL_SHARES {
            let start = 40 + idx * 64;
            assert!(
                excluded
                    .iter()
                    .any(|(s, e)| *s <= start && *e >= start + 64)
            );
        }

        assert!(excluded.iter().any(|(s, e)| *s <= 420 && *e >= 484));
        assert!(
            excluded
                .iter()
                .any(|(s, e)| *s <= 560 && *e == binary.len())
        );
    }

    #[test]
    fn integrity_hash_changes_only_for_non_excluded_mutations() {
        let mut binary = sample_binary_with_markers();
        let regions = find_integrity_regions(&binary).expect("regions");
        let baseline = compute_binary_integrity_hash(&binary, &regions).expect("hash");

        binary[50] ^= 0xFF;
        let excluded_mutation_hash =
            compute_binary_integrity_hash(&binary, &regions).expect("hash");
        assert_eq!(baseline, excluded_mutation_hash);

        binary[8] ^= 0xFF;
        let included_mutation_hash =
            compute_binary_integrity_hash(&binary, &regions).expect("hash");
        assert_ne!(baseline, included_mutation_hash);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn integrity_bound_key_changes_when_binary_changes() {
        let secret = [0x19; 32];
        let binary = sample_binary_with_markers();
        let mut modified = binary.clone();
        modified[7] ^= 0xFF;

        let key_a = derive_key_with_integrity_from_binary(&secret, &binary).expect("key");
        let key_b = derive_key_with_integrity_from_binary(&secret, &modified).expect("key");

        assert_ne!(key_a, key_b);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_elf_regions_detect_executable_segment() {
        let binary = std::fs::read("/proc/self/exe").expect("self executable");
        let regions = find_integrity_regions(&binary).expect("regions");

        assert!(regions.code_end > regions.code_start);
        assert!(regions.code_end <= binary.len());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn verify_binary_integrity_accepts_match_and_rejects_mismatch() {
        let path = std::env::temp_dir().join("snapfzz-seal-core-integrity.bin");
        let mut binary = sample_binary_with_markers();
        binary[560..592].fill(0xCC);

        std::fs::write(&path, &binary).expect("write test binary");

        let regions = find_integrity_regions(&binary).expect("regions");
        let expected = compute_binary_integrity_hash(&binary, &regions).expect("hash");

        verify_binary_integrity(&expected, Some(path.to_str().unwrap())).expect("must verify");

        let err = verify_binary_integrity(&[0xDD; 32], Some(path.to_str().unwrap()))
            .expect_err("mismatch must fail");
        assert!(matches!(err, SealError::TamperDetected));

        let _ = std::fs::remove_file(path);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_integrity_fallbacks_are_deterministic() {
        let secret = [0x22; 32];
        let binary = vec![0x11; 128];

        let key_a = derive_key_with_integrity_from_binary(&secret, &binary).expect("key");
        let key_b = derive_key_with_integrity_from_binary(&secret, &binary).expect("key");
        assert_eq!(key_a, key_b);

        verify_binary_integrity(&[0x44; 32], None).expect("non-linux should skip verify");
    }
}
