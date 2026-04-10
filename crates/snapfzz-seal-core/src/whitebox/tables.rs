use zeroize::Zeroize;

#[derive(Clone)]
pub struct TBox {
    pub round: usize,
    pub byte_idx: usize,
    pub table: [u8; 256],
}

#[derive(Clone)]
pub struct TypeI {
    pub round: usize,
    pub tables: Vec<[[u8; 256]; 4]>,
}

#[derive(Clone)]
pub struct TypeII {
    pub round: usize,
    pub tables: Vec<[[u8; 256]; 4]>,
}

#[derive(Clone)]
pub struct WhiteBoxTables {
    pub t_boxes: Vec<TBox>,
    pub type_i: Vec<TypeI>,
    pub type_ii: Vec<TypeII>,
    pub randomization: Vec<[u8; 16]>,
}

impl WhiteBoxTables {
    pub fn new() -> Self {
        Self {
            t_boxes: Vec::new(),
            type_i: Vec::new(),
            type_ii: Vec::new(),
            randomization: Vec::new(),
        }
    }

    pub fn randomize(&mut self) {
        for _ in 0..16 {
            let bijection: [u8; 16] = rand::random();
            self.randomization.push(bijection);
        }

        for (i, t_box) in self.t_boxes.iter_mut().enumerate() {
            let rand_idx = i % self.randomization.len();
            let rand_val = &self.randomization[rand_idx];

            for (j, entry) in t_box.table.iter_mut().enumerate() {
                *entry ^= rand_val[j % 16];
            }
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(&(self.t_boxes.len() as u32).to_le_bytes());

        for t_box in &self.t_boxes {
            bytes.push(t_box.round as u8);
            bytes.push(t_box.byte_idx as u8);
            bytes.extend_from_slice(&t_box.table);
        }

        bytes.extend_from_slice(&(self.type_i.len() as u32).to_le_bytes());

        for type_i in &self.type_i {
            bytes.push(type_i.round as u8);
            for column_table in &type_i.tables {
                for row_table in column_table {
                    bytes.extend_from_slice(row_table);
                }
            }
        }

        bytes.extend_from_slice(&(self.type_ii.len() as u32).to_le_bytes());

        bytes
    }

    pub fn estimate_size(&self) -> usize {
        let t_box_size = self.t_boxes.len() * (2 + 256);
        let type_i_size = self.type_i.len() * (1 + 4 * 4 * 256);
        let type_ii_size = self.type_ii.len() * (1 + 4 * 4 * 256);

        t_box_size + type_i_size + type_ii_size + 1000
    }

    pub fn zeroize(&mut self) {
        for t_box in &mut self.t_boxes {
            t_box.table.zeroize();
        }
        self.randomization.zeroize();
    }
}

impl Default for WhiteBoxTables {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tbox(round: usize, byte_idx: usize, fill: u8) -> TBox {
        TBox {
            round,
            byte_idx,
            table: [fill; 256],
        }
    }

    fn sample_type_tables(round: usize) -> (TypeI, TypeII) {
        let mut column = [[0_u8; 256]; 4];
        for (row_idx, row) in column.iter_mut().enumerate() {
            for (idx, byte) in row.iter_mut().enumerate() {
                *byte = (idx as u8) ^ (row_idx as u8);
            }
        }

        (
            TypeI {
                round,
                tables: vec![column; 4],
            },
            TypeII {
                round,
                tables: vec![column; 4],
            },
        )
    }

    #[test]
    fn randomize_adds_bijections_and_changes_tbox_entries() {
        let mut tables = WhiteBoxTables::new();
        tables.t_boxes.push(sample_tbox(0, 0, 0x5A));
        let before = tables.t_boxes[0].table;

        tables.randomize();

        assert_eq!(tables.randomization.len(), 16);
        assert!(
            tables.t_boxes[0]
                .table
                .iter()
                .enumerate()
                .all(|(idx, value)| *value == (before[idx] ^ tables.randomization[0][idx % 16]))
        );
        assert_ne!(tables.t_boxes[0].table, before);
    }

    #[test]
    fn randomize_accumulates_randomization_on_repeated_calls() {
        let mut tables = WhiteBoxTables::new();
        tables.t_boxes.push(sample_tbox(1, 2, 0xC3));
        tables.randomize();
        let after_first = tables.t_boxes[0].table;

        tables.randomize();

        assert_eq!(tables.randomization.len(), 32);
        assert_ne!(tables.t_boxes[0].table, after_first);
    }

    #[test]
    fn randomize_is_noop_for_empty_tboxes_but_still_sets_randomization() {
        let mut tables = WhiteBoxTables::new();
        tables.randomize();

        assert_eq!(tables.t_boxes.len(), 0);
        assert_eq!(tables.randomization.len(), 16);
    }

    #[test]
    fn zeroize_clears_tbox_data_and_randomization_but_not_structure() {
        let mut tables = WhiteBoxTables::new();
        tables.t_boxes.push(sample_tbox(0, 0, 0xFF));
        tables.randomization.push([0xAB; 16]);

        tables.zeroize();

        assert_eq!(tables.t_boxes.len(), 1);
        assert!(tables.t_boxes[0].table.iter().all(|byte| *byte == 0));
        assert!(tables.randomization.is_empty());
    }

    #[test]
    fn to_bytes_serializes_counts_and_sections_in_expected_order() {
        let mut tables = WhiteBoxTables::new();
        tables.t_boxes.push(sample_tbox(3, 7, 0xAA));
        let (type_i, type_ii) = sample_type_tables(5);
        tables.type_i.push(type_i);
        tables.type_ii.push(type_ii);

        let bytes = tables.to_bytes();

        let tbox_count = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        assert_eq!(tbox_count, 1);
        assert_eq!(bytes[4], 3);
        assert_eq!(bytes[5], 7);
        assert_eq!(&bytes[6..262], &[0xAA; 256]);

        let type_i_offset = 4 + (2 + 256);
        let type_i_count =
            u32::from_le_bytes(bytes[type_i_offset..type_i_offset + 4].try_into().unwrap());
        assert_eq!(type_i_count, 1);
        assert_eq!(bytes[type_i_offset + 4], 5);

        let type_ii_offset = type_i_offset + 4 + 1 + (4 * 4 * 256);
        let type_ii_count = u32::from_le_bytes(
            bytes[type_ii_offset..type_ii_offset + 4]
                .try_into()
                .unwrap(),
        );
        assert_eq!(type_ii_count, 1);
    }

    #[test]
    fn to_bytes_handles_large_round_indices_via_u8_truncation() {
        let mut tables = WhiteBoxTables::new();
        tables.t_boxes.push(sample_tbox(300, 513, 0x11));

        let bytes = tables.to_bytes();

        assert_eq!(bytes[4], 300_u16 as u8);
        assert_eq!(bytes[5], 513_u16 as u8);
    }

    #[test]
    fn to_bytes_for_empty_tables_contains_only_zero_counts() {
        let tables = WhiteBoxTables::new();
        let bytes = tables.to_bytes();

        assert_eq!(bytes.len(), 12);
        assert_eq!(u32::from_le_bytes(bytes[0..4].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 0);
    }

    #[test]
    fn estimate_size_matches_formula_for_populated_tables() {
        let mut tables = WhiteBoxTables::new();
        tables.t_boxes.extend([
            sample_tbox(0, 0, 0x01),
            sample_tbox(0, 1, 0x02),
            sample_tbox(1, 2, 0x03),
        ]);
        let (type_i_a, type_ii_a) = sample_type_tables(0);
        let (type_i_b, type_ii_b) = sample_type_tables(1);
        tables.type_i.extend([type_i_a, type_i_b]);
        tables.type_ii.extend([type_ii_a, type_ii_b]);

        let expected = 3 * (2 + 256) + 2 * (1 + 4 * 4 * 256) + 2 * (1 + 4 * 4 * 256) + 1000;
        assert_eq!(tables.estimate_size(), expected);
    }

    #[test]
    fn estimate_size_for_empty_tables_is_base_overhead() {
        let tables = WhiteBoxTables::new();
        assert_eq!(tables.estimate_size(), 1000);
    }
}
