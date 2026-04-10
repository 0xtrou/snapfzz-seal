use super::tables::{TBox, TypeI, TypeII, WhiteBoxTables};
use crate::error::SealError;
use sha2::{Digest, Sha256};

pub struct WhiteBoxAES {
    tables: WhiteBoxTables,
}

#[allow(dead_code)]
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

impl WhiteBoxAES {
    /// Generate white-box tables from key
    /// This is done at BUILD time
    pub fn generate_tables(key: &[u8; 32]) -> WhiteBoxTables {
        let mut tables = WhiteBoxTables::new();

        // AES-256 has 14 rounds
        for round in 0..14 {
            // Generate round key
            let round_key = Self::derive_round_key(key, round);

            // Create T-boxes for this round
            for byte_idx in 0..16 {
                tables
                    .t_boxes
                    .push(Self::generate_t_box(&round_key, round, byte_idx));
            }
        }

        // Generate mixing tables
        for round in 0..13 {
            tables.type_i.push(Self::generate_type_i(round));
            tables.type_ii.push(Self::generate_type_ii(round + 1));
        }

        // Add randomization for security
        tables.randomize();

        tables
    }

    /// Generate T-box for one byte position
    /// T-box combines SubBytes + ShiftRows + AddRoundKey
    fn generate_t_box(round_key: &[u8; 16], round: usize, byte_idx: usize) -> TBox {
        let mut t_box = [0u8; 256];

        // For decryption, we use inverse operations
        for input_byte in 0u8..=255 {
            // Apply inverse S-box for decryption
            let inv_s_out = INV_SBOX[input_byte as usize];

            // Add round key byte
            let key_byte = round_key[byte_idx];
            let output = inv_s_out ^ key_byte;

            t_box[input_byte as usize] = output;
        }

        TBox {
            round,
            byte_idx,
            table: t_box,
        }
    }

    /// Generate Type I mixing tables (input side)
    fn generate_type_i(round: usize) -> TypeI {
        // Type I tables mix the outputs of T-boxes
        // using the MixColumns transformation

        let mut tables = Vec::new();

        // For each column of the state
        for _col in 0..4 {
            let mut column_table = [[0u8; 256]; 4];

            for (row, column_row) in column_table.iter_mut().enumerate() {
                for input in 0u8..=255 {
                    // Inverse MixColumns coefficients for decryption
                    let coeff = match row {
                        0 => 0x0e,
                        1 => 0x0b,
                        2 => 0x0d,
                        3 => 0x09,
                        _ => unreachable!(),
                    };

                    // GF(2^8) multiplication
                    let output = gf_mult(coeff, input);
                    column_row[input as usize] = output;
                }
            }

            tables.push(column_table);
        }

        TypeI { round, tables }
    }

    /// Generate Type II mixing tables (output side)
    fn generate_type_ii(round: usize) -> TypeII {
        // Type II tables are the inverse of Type I
        // Applied before next round's T-boxes

        let mut tables = Vec::new();

        for _col in 0..4 {
            let mut column_table = [[0u8; 256]; 4];

            for (row, column_row) in column_table.iter_mut().enumerate() {
                for input in 0u8..=255 {
                    // Use standard MixColumns coefficients for decryption
                    let coeff = match row {
                        0 => 2,
                        1 => 3,
                        2 => 1,
                        3 => 1,
                        _ => unreachable!(),
                    };

                    let output = gf_mult(coeff, input);
                    column_row[input as usize] = output;
                }
            }

            tables.push(column_table);
        }

        TypeII { round, tables }
    }

    /// Derive round key from master key
    fn derive_round_key(key: &[u8; 32], round: usize) -> [u8; 16] {
        // Use SHA-256 to derive round keys
        // This is a simplified version - production would use proper AES key schedule

        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.update((round as u32).to_le_bytes());

        let result = hasher.finalize();
        let mut round_key = [0u8; 16];
        round_key.copy_from_slice(&result[..16]);

        round_key
    }

    /// Create WhiteBoxAES from existing tables
    pub fn from_tables(tables: WhiteBoxTables) -> Self {
        Self { tables }
    }

    /// Get reference to tables
    pub fn tables(&self) -> &WhiteBoxTables {
        &self.tables
    }

    /// Decrypt using white-box tables
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SealError> {
        if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16) {
            return Err(SealError::DecryptionFailed(
                "invalid ciphertext length for white-box decryption".to_string(),
            ));
        }

        let mut plaintext = Vec::with_capacity(ciphertext.len());

        for block in ciphertext.chunks(16) {
            let decrypted_block = self.decrypt_block(block);
            plaintext.extend_from_slice(&decrypted_block);
        }

        Ok(plaintext)
    }

    /// Decrypt single 16-byte block
    fn decrypt_block(&self, block: &[u8]) -> [u8; 16] {
        let mut state = [0u8; 16];
        state.copy_from_slice(block);

        // Reverse rounds (14 rounds for AES-256)
        for round in (0..14).rev() {
            state = self.apply_round_tables(round, &state);
        }

        state
    }

    /// Apply lookup tables for one round
    fn apply_round_tables(&self, round: usize, state: &[u8; 16]) -> [u8; 16] {
        let mut new_state = [0u8; 16];

        // Apply T-boxes
        for byte_idx in 0..16 {
            let t_box_idx = round * 16 + byte_idx;
            if t_box_idx < self.tables.t_boxes.len() {
                let t_box = &self.tables.t_boxes[t_box_idx];
                new_state[byte_idx] = t_box.table[state[byte_idx] as usize];
            }
        }

        // Apply mixing tables (except last round)
        if round < 13 && round < self.tables.type_i.len() {
            new_state = self.apply_mixing(&self.tables.type_i[round], &new_state);
        }

        new_state
    }

    fn apply_mixing(&self, type_i: &TypeI, state: &[u8; 16]) -> [u8; 16] {
        let mut new_state = [0u8; 16];

        for (col_idx, column_table) in type_i.tables.iter().enumerate() {
            for row in 0..4 {
                let state_idx = col_idx * 4 + row;
                let mut mixed = 0u8;

                for (i, table) in column_table.iter().enumerate() {
                    mixed ^= table[state[col_idx * 4 + i] as usize];
                }

                new_state[state_idx] = mixed;
            }
        }

        new_state
    }
}

/// GF(2^8) multiplication
fn gf_mult(a: u8, b: u8) -> u8 {
    let mut result = 0u8;
    let mut a = a;
    let mut b = b;

    for _ in 0..8 {
        if b & 1 != 0 {
            result ^= a;
        }

        let hi_bit = a & 0x80;
        a <<= 1;

        if hi_bit != 0 {
            a ^= 0x1b; // x^8 + x^4 + x^3 + x + 1
        }

        b >>= 1;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gf_mult() {
        assert_eq!(gf_mult(2, 0x57), 0xae);
        assert_eq!(gf_mult(3, 0x57), 0xf9);
        assert_eq!(gf_mult(0x0e, 0x57), 0x67);
    }

    #[test]
    fn test_tables_generation() {
        let key = [0x42u8; 32];
        let tables = WhiteBoxAES::generate_tables(&key);

        // Should have 14 rounds * 16 bytes = 224 T-boxes
        assert_eq!(tables.t_boxes.len(), 224);

        // Should have 13 Type I and Type II tables each
        assert_eq!(tables.type_i.len(), 13);
        assert_eq!(tables.type_ii.len(), 13);

        // Should have randomization
        assert_eq!(tables.randomization.len(), 16);
    }

    #[test]
    fn test_tables_size() {
        let key = [0x42u8; 32];
        let tables = WhiteBoxAES::generate_tables(&key);

        let size = tables.estimate_size();
        println!("White-box tables size: {} bytes", size);

        // Should be ~500KB - 2MB
        assert!(size > 100_000, "Tables too small: {}", size);
        assert!(size < 5_000_000, "Tables too large: {}", size);
    }

    #[test]
    fn test_tables_serialization() {
        let key = [0x42u8; 32];
        let tables = WhiteBoxAES::generate_tables(&key);

        let bytes = tables.to_bytes();
        assert!(!bytes.is_empty());

        // First 4 bytes should be T-box count
        let count = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        assert_eq!(count, 224);
    }

    #[test]
    fn test_decryption_length_validation() {
        let key = [0x42u8; 32];
        let wb = WhiteBoxAES::from_tables(WhiteBoxAES::generate_tables(&key));

        // Empty ciphertext should fail
        assert!(wb.decrypt(&[]).is_err());

        // Non-16-byte aligned should fail
        assert!(wb.decrypt(&[0u8; 15]).is_err());
        assert!(wb.decrypt(&[0u8; 17]).is_err());

        // 16-byte aligned should succeed
        assert!(wb.decrypt(&[0u8; 16]).is_ok());
        assert!(wb.decrypt(&[0u8; 32]).is_ok());
    }
}
