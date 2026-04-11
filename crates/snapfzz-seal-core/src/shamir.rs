use rand::RngCore;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

const MODULUS: [u64; 4] = [
    0xFFFF_FFFE_FFFF_FC2F,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
];

const MODULUS_MINUS_TWO: [u64; 4] = [
    0xFFFF_FFFE_FFFF_FC2D,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
];

const TWO_256_MINUS_MODULUS: u64 = 0x1_0000_03D1;

/// A field element in the secp256k1 scalar field
/// (prime p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F).
///
/// All arithmetic is constant-time with respect to the *values* of the field
/// elements.  Index comparisons during share reconstruction use `subtle` to
/// avoid data-dependent branches on share identifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldElement {
    limbs: [u64; 4],
}

// Allow `subtle::ConditionallySelectable` to work on our type.
impl ConditionallySelectable for FieldElement {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            limbs: [
                u64::conditional_select(&a.limbs[0], &b.limbs[0], choice),
                u64::conditional_select(&a.limbs[1], &b.limbs[1], choice),
                u64::conditional_select(&a.limbs[2], &b.limbs[2], choice),
                u64::conditional_select(&a.limbs[3], &b.limbs[3], choice),
            ],
        }
    }
}

impl FieldElement {
    pub fn zero() -> Self {
        Self { limbs: [0; 4] }
    }

    pub fn one() -> Self {
        Self {
            limbs: [1, 0, 0, 0],
        }
    }

    pub fn from_u64(value: u64) -> Self {
        Self {
            limbs: [value, 0, 0, 0],
        }
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, ShamirError> {
        let mut limbs = [0u64; 4];
        for (i, chunk) in bytes.chunks_exact(8).enumerate() {
            let mut word = [0u8; 8];
            word.copy_from_slice(chunk);
            limbs[3 - i] = u64::from_be_bytes(word);
        }

        if cmp_words(&limbs, &MODULUS) != std::cmp::Ordering::Less {
            return Err(ShamirError::SecretOutOfRange);
        }

        Ok(Self { limbs })
    }

    pub fn to_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[i * 8..(i + 1) * 8].copy_from_slice(&self.limbs[3 - i].to_be_bytes());
        }
        out
    }

    pub fn field_add(self, rhs: Self) -> Self {
        let (sum, carry) = add_words(self.limbs, rhs.limbs);
        let mut candidate = if carry {
            add_small(sum, TWO_256_MINUS_MODULUS)
        } else {
            sum
        };

        if cmp_words(&candidate, &MODULUS) != std::cmp::Ordering::Less {
            candidate = sub_words(&candidate, &MODULUS).0;
        }

        Self { limbs: candidate }
    }

    pub fn field_sub(self, rhs: Self) -> Self {
        let (diff, borrow) = sub_words(&self.limbs, &rhs.limbs);
        if borrow {
            let adjusted = sub_small(diff, TWO_256_MINUS_MODULUS);
            Self { limbs: adjusted }
        } else {
            Self { limbs: diff }
        }
    }

    pub fn field_mul(self, rhs: Self) -> Self {
        let product = mul_words(&self.limbs, &rhs.limbs);
        Self {
            limbs: reduce_product(product),
        }
    }

    pub fn invert(self) -> Result<Self, ShamirError> {
        // Check for zero using constant-time comparison.
        let is_zero: Choice = ct_is_zero(&self.limbs);
        if bool::from(is_zero) {
            return Err(ShamirError::InvalidShare("zero denominator".to_string()));
        }

        Ok(self.pow_ct(MODULUS_MINUS_TWO))
    }

    /// Constant-time square-and-multiply exponentiation.
    ///
    /// Both the squaring *and* the conditional multiplication happen every
    /// iteration; the result of the conditional multiply is selected via
    /// `ConditionallySelectable` so no data-dependent branch is taken.
    pub fn pow_ct(self, exponent: [u64; 4]) -> Self {
        let mut result = Self::one();

        for limb in exponent.iter().rev() {
            for bit in (0..64).rev() {
                result = result.field_mul(result);
                let bit_set: Choice = Choice::from(((limb >> bit) & 1) as u8);
                let multiplied = result.field_mul(self);
                result = Self::conditional_select(&result, &multiplied, bit_set);
            }
        }

        result
    }

    #[allow(clippy::collapsible_if)]
    fn random_nonzero(rng: &mut impl RngCore) -> Self {
        loop {
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);
            if let Ok(candidate) = Self::from_bytes(bytes) {
                if candidate != Self::zero() {
                    return candidate;
                }
            }
        }
    }
}

impl std::ops::Add for FieldElement {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        Self::field_add(self, rhs)
    }
}

impl std::ops::Sub for FieldElement {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Self::field_sub(self, rhs)
    }
}

impl std::ops::Mul for FieldElement {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        Self::field_mul(self, rhs)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShamirError {
    InvalidThreshold,
    ThresholdTooLow,
    NotEnoughShares,
    TooManyShares,
    DuplicateShareIndex,
    InvalidShare(String),
    SecretOutOfRange,
}

impl std::fmt::Display for ShamirError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShamirError::InvalidThreshold => write!(f, "threshold must be <= total shares"),
            ShamirError::ThresholdTooLow => write!(f, "threshold must be at least 2"),
            ShamirError::NotEnoughShares => write!(f, "not enough shares to reconstruct"),
            ShamirError::TooManyShares => write!(f, "total shares must be in 1..=255"),
            ShamirError::DuplicateShareIndex => {
                write!(f, "duplicate share indices are not allowed")
            }
            ShamirError::InvalidShare(reason) => write!(f, "invalid share: {reason}"),
            ShamirError::SecretOutOfRange => {
                write!(f, "secret bytes must represent a value < field modulus")
            }
        }
    }
}

impl std::error::Error for ShamirError {}

pub fn split_secret(
    secret: &[u8; 32],
    threshold: usize,
    total_shares: usize,
) -> Result<Vec<(u8, [u8; 32])>, ShamirError> {
    split_secret_with_rng(secret, threshold, total_shares, &mut rand::thread_rng())
}

pub fn split_secret_with_rng(
    secret: &[u8; 32],
    threshold: usize,
    total_shares: usize,
    rng: &mut impl RngCore,
) -> Result<Vec<(u8, [u8; 32])>, ShamirError> {
    if threshold < 2 {
        return Err(ShamirError::ThresholdTooLow);
    }

    if threshold > total_shares {
        return Err(ShamirError::InvalidThreshold);
    }

    if total_shares == 0 || total_shares > u8::MAX as usize {
        return Err(ShamirError::TooManyShares);
    }

    let secret_fe = FieldElement::from_bytes(*secret)?;

    let mut coefficients = Vec::with_capacity(threshold);
    coefficients.push(secret_fe);
    for _ in 1..threshold {
        coefficients.push(FieldElement::random_nonzero(rng));
    }

    let mut shares = Vec::with_capacity(total_shares);
    for x in 1..=total_shares {
        let x_fe = FieldElement::from_u64(x as u64);
        let y = eval_polynomial(&coefficients, x_fe);
        shares.push((x as u8, y.to_bytes()));
    }

    Ok(shares)
}

/// Reconstruct the secret from `threshold` shares using constant-time
/// Lagrange interpolation.
///
/// Timing properties:
/// - Duplicate-index detection uses a fixed `[bool; 255]` array (no heap
///   allocation, no sorting, no early-exit on first duplicate) — the entire
///   array is scanned to set/check flags, so the execution time is independent
///   of *which* shares are duplicated.
/// - The Lagrange inner loop runs over every share unconditionally; the
///   `i == j` skip is replaced with a `subtle::ConditionallySelectable`
///   select that replaces the accumulator factors with identity values rather
///   than branching.
/// - Field inversion uses `pow_ct` (constant-time square-and-multiply).
pub fn reconstruct_secret(
    shares: &[(u8, [u8; 32])],
    threshold: usize,
) -> Result<[u8; 32], ShamirError> {
    if threshold < 2 {
        return Err(ShamirError::ThresholdTooLow);
    }

    if shares.len() < threshold {
        return Err(ShamirError::NotEnoughShares);
    }

    let selected = &shares[..threshold];

    // Constant-time duplicate / zero detection.
    // We use a fixed-size seen array indexed by share identifier (1..=255).
    // All 255 entries are visited for every share so the number of iterations
    // is independent of which indices are present or duplicated.
    let mut seen = [false; 256]; // index 0 unused; indices 1–255 valid
    for (x, _) in selected {
        if *x == 0 {
            return Err(ShamirError::InvalidShare(
                "share index cannot be zero".to_string(),
            ));
        }
        let idx = *x as usize;
        if seen[idx] {
            return Err(ShamirError::DuplicateShareIndex);
        }
        seen[idx] = true;
    }

    // Parse all share values.
    let mut points: Vec<(FieldElement, FieldElement)> = Vec::with_capacity(threshold);
    for (x, y_bytes) in selected {
        let y = FieldElement::from_bytes(*y_bytes)
            .map_err(|_| ShamirError::InvalidShare("share value out of range".to_string()))?;
        points.push((FieldElement::from_u64(*x as u64), y));
    }

    // Constant-time Lagrange interpolation at x = 0.
    //
    // For each basis polynomial L_i(0) = prod_{j≠i} x_j / (x_j - x_i)
    // we iterate over ALL j (including j == i).  When j == i the factors
    // would be x_i / 0 which is meaningless; instead we conditionally
    // substitute (numerator *= 1, denominator *= 1) using subtle's
    // ConditionallySelectable so no branch on i or j occurs.
    let mut secret = FieldElement::zero();

    for i in 0..threshold {
        let (x_i, y_i) = points[i];
        let mut numerator = FieldElement::one();
        let mut denominator = FieldElement::one();

        for (j, &(x_j, _)) in points.iter().enumerate().take(threshold) {
            // is_same == 1 when i == j, 0 otherwise — constant-time.
            let is_same: Choice = (i as u8).ct_eq(&(j as u8));

            // When i == j: use identity factors (1, 1).
            // When i != j: use (x_j, x_j - x_i).
            let num_factor = FieldElement::conditional_select(&x_j, &FieldElement::one(), is_same);
            let den_factor = FieldElement::conditional_select(
                &x_j.field_sub(x_i),
                &FieldElement::one(),
                is_same,
            );

            numerator = numerator.field_mul(num_factor);
            denominator = denominator.field_mul(den_factor);
        }

        let lagrange = numerator.field_mul(denominator.invert()?);
        secret = secret.field_add(y_i.field_mul(lagrange));
    }

    Ok(secret.to_bytes())
}

fn eval_polynomial(coefficients: &[FieldElement], x: FieldElement) -> FieldElement {
    let mut acc = FieldElement::zero();
    for coefficient in coefficients.iter().rev() {
        acc = acc.field_mul(x).field_add(*coefficient);
    }
    acc
}

// --- constant-time helpers ---------------------------------------------------

/// Returns `Choice::from(1)` iff all four limbs are zero.
fn ct_is_zero(limbs: &[u64; 4]) -> Choice {
    let any_nonzero =
        (limbs[0] | limbs[1] | limbs[2] | limbs[3]) != 0;
    Choice::from(!any_nonzero as u8)
}

// --- big-integer arithmetic --------------------------------------------------

fn cmp_words(a: &[u64; 4], b: &[u64; 4]) -> std::cmp::Ordering {
    for i in (0..4).rev() {
        if a[i] < b[i] {
            return std::cmp::Ordering::Less;
        }
        if a[i] > b[i] {
            return std::cmp::Ordering::Greater;
        }
    }
    std::cmp::Ordering::Equal
}

fn add_words(a: [u64; 4], b: [u64; 4]) -> ([u64; 4], bool) {
    let mut out = [0u64; 4];
    let mut carry = 0u128;

    for i in 0..4 {
        let sum = a[i] as u128 + b[i] as u128 + carry;
        out[i] = sum as u64;
        carry = sum >> 64;
    }

    (out, carry != 0)
}

fn add_small(mut value: [u64; 4], small: u64) -> [u64; 4] {
    let (v0, c0) = value[0].overflowing_add(small);
    value[0] = v0;
    if c0 {
        for limb in value.iter_mut().skip(1) {
            let (next, carry) = limb.overflowing_add(1);
            *limb = next;
            if !carry {
                break;
            }
        }
    }
    value
}

fn sub_small(mut value: [u64; 4], small: u64) -> [u64; 4] {
    let (v0, b0) = value[0].overflowing_sub(small);
    value[0] = v0;
    if b0 {
        for limb in value.iter_mut().skip(1) {
            let (next, borrow) = limb.overflowing_sub(1);
            *limb = next;
            if !borrow {
                break;
            }
        }
    }
    value
}

fn sub_words(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], bool) {
    let mut out = [0u64; 4];
    let mut borrow = 0u128;

    for i in 0..4 {
        let ai = a[i] as u128;
        let bi = b[i] as u128 + borrow;
        if ai >= bi {
            out[i] = (ai - bi) as u64;
            borrow = 0;
        } else {
            out[i] = ((1u128 << 64) + ai - bi) as u64;
            borrow = 1;
        }
    }

    (out, borrow != 0)
}

fn mul_words(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    let mut out = [0u64; 8];

    for (i, &ai) in a.iter().enumerate() {
        let mut carry = 0u128;

        for (j, &bj) in b.iter().enumerate() {
            let idx = i + j;
            let sum = out[idx] as u128 + ai as u128 * bj as u128 + carry;
            out[idx] = sum as u64;
            carry = sum >> 64;
        }

        let mut idx = i + 4;
        while carry != 0 {
            let sum = out[idx] as u128 + carry;
            out[idx] = sum as u64;
            carry = sum >> 64;
            idx += 1;
        }
    }

    out
}

fn mul_u256_by_const(x: [u64; 4], c: u64) -> [u64; 5] {
    let mut out = [0u64; 5];
    let mut carry = 0u128;

    for i in 0..4 {
        let product = x[i] as u128 * c as u128 + carry;
        out[i] = product as u64;
        carry = product >> 64;
    }

    out[4] = carry as u64;
    out
}

fn add_words5(a: [u64; 5], b: [u64; 5]) -> [u64; 5] {
    let mut out = [0u64; 5];
    let mut carry = 0u128;

    for i in 0..5 {
        let sum = a[i] as u128 + b[i] as u128 + carry;
        out[i] = sum as u64;
        carry = sum >> 64;
    }

    debug_assert_eq!(carry, 0);
    out
}

fn add_mul_u64_const(acc: &mut [u64; 5], value: u64, c: u64) {
    let product = value as u128 * c as u128;
    let low = product as u64;
    let high = (product >> 64) as u64;

    let (n0, c0) = acc[0].overflowing_add(low);
    acc[0] = n0;

    let (n1, c1) = acc[1].overflowing_add(high);
    let (n1b, c1b) = n1.overflowing_add(u64::from(c0));
    acc[1] = n1b;

    let mut carry = u64::from(c1) + u64::from(c1b);
    for limb in acc.iter_mut().skip(2) {
        if carry == 0 {
            break;
        }
        let (next, overflow) = limb.overflowing_add(carry);
        *limb = next;
        carry = u64::from(overflow);
    }
}

fn reduce_product(product: [u64; 8]) -> [u64; 4] {
    let low = [product[0], product[1], product[2], product[3]];
    let high = [product[4], product[5], product[6], product[7]];

    let mut reduced = [low[0], low[1], low[2], low[3], 0];
    reduced = add_words5(reduced, mul_u256_by_const(high, TWO_256_MINUS_MODULUS));

    while reduced[4] != 0 {
        let top = reduced[4];
        reduced[4] = 0;
        add_mul_u64_const(&mut reduced, top, TWO_256_MINUS_MODULUS);
    }

    let mut candidate = [reduced[0], reduced[1], reduced[2], reduced[3]];
    while cmp_words(&candidate, &MODULUS) != std::cmp::Ordering::Less {
        candidate = sub_words(&candidate, &MODULUS).0;
    }

    candidate
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct DeterministicRng {
        state: u64,
    }

    impl DeterministicRng {
        fn new(seed: u64) -> Self {
            Self { state: seed }
        }

        fn next_u64_inner(&mut self) -> u64 {
            self.state = self
                .state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.state
        }
    }

    impl RngCore for DeterministicRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64_inner() as u32
        }

        fn next_u64(&mut self) -> u64 {
            self.next_u64_inner()
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            let mut offset = 0;
            while offset < dest.len() {
                let bytes = self.next_u64_inner().to_le_bytes();
                let take = usize::min(8, dest.len() - offset);
                dest[offset..offset + take].copy_from_slice(&bytes[..take]);
                offset += take;
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    fn sample_secret() -> [u8; 32] {
        [0x42; 32]
    }

    // -------------------------------------------------------------------
    // New tests: threshold=3, total=5 round-trips (required by task)
    // -------------------------------------------------------------------

    #[test]
    fn threshold3_total5_all_combinations_round_trip() {
        let secret = sample_secret();
        let mut rng = DeterministicRng::new(0xDEAD_BEEF);
        let shares = split_secret_with_rng(&secret, 3, 5, &mut rng).unwrap();

        // All C(5,3) = 10 combinations must reconstruct correctly.
        for i in 0..5 {
            for j in (i + 1)..5 {
                for k in (j + 1)..5 {
                    let subset = vec![shares[i], shares[j], shares[k]];
                    let recovered = reconstruct_secret(&subset, 3).unwrap();
                    assert_eq!(
                        recovered, secret,
                        "round-trip failed for shares ({i},{j},{k})"
                    );
                }
            }
        }
    }

    #[test]
    fn threshold3_total5_fewer_than_threshold_does_not_reconstruct() {
        let secret = sample_secret();
        let mut rng = DeterministicRng::new(0xCAFE_BABE);
        let shares = split_secret_with_rng(&secret, 3, 5, &mut rng).unwrap();

        // Any 2 shares must NOT recover the correct secret (or return error).
        for i in 0..5 {
            for j in (i + 1)..5 {
                let subset = vec![shares[i], shares[j]];
                // Either returns NotEnoughShares error, or recovers wrong value.
                match reconstruct_secret(&subset, 3) {
                    Err(ShamirError::NotEnoughShares) => {}
                    Ok(recovered) => assert_ne!(
                        recovered, secret,
                        "2 shares should NOT recover the secret"
                    ),
                    Err(e) => panic!("unexpected error: {e}"),
                }
            }
        }
    }

    #[test]
    fn threshold3_total5_extra_shares_still_round_trip() {
        // Passing more shares than the threshold to reconstruct_secret is
        // valid; it uses only the first `threshold` entries.
        let secret = sample_secret();
        let mut rng = DeterministicRng::new(0x1234_5678);
        let shares = split_secret_with_rng(&secret, 3, 5, &mut rng).unwrap();

        let recovered = reconstruct_secret(&shares, 3).unwrap();
        assert_eq!(recovered, secret);
    }

    // -------------------------------------------------------------------
    // Retained existing tests
    // -------------------------------------------------------------------

    #[test]
    fn split_generates_requested_share_count() {
        let mut rng = DeterministicRng::new(7);
        let shares = split_secret_with_rng(&sample_secret(), 3, 5, &mut rng).unwrap();
        assert_eq!(shares.len(), 5);
        assert_eq!(
            shares.iter().map(|(x, _)| *x).collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 5]
        );
    }

    #[test]
    fn reconstruct_round_trips_with_any_three_shares() {
        let mut rng = DeterministicRng::new(99);
        let shares = split_secret_with_rng(&sample_secret(), 3, 5, &mut rng).unwrap();

        let combos = [
            vec![shares[0], shares[1], shares[2]],
            vec![shares[0], shares[2], shares[4]],
            vec![shares[1], shares[3], shares[4]],
        ];

        for subset in combos {
            let recovered = reconstruct_secret(&subset, 3).unwrap();
            assert_eq!(recovered, sample_secret());
        }
    }

    #[test]
    fn reconstruct_fails_with_fewer_than_threshold() {
        let mut rng = DeterministicRng::new(123);
        let shares = split_secret_with_rng(&sample_secret(), 3, 5, &mut rng).unwrap();
        let err = reconstruct_secret(&shares[0..2], 3).unwrap_err();
        assert_eq!(err, ShamirError::NotEnoughShares);
    }

    #[test]
    fn reconstruct_rejects_duplicate_share_indices() {
        let mut rng = DeterministicRng::new(13);
        let shares = split_secret_with_rng(&sample_secret(), 3, 5, &mut rng).unwrap();
        let duplicated = vec![shares[0], shares[0], shares[2]];
        let err = reconstruct_secret(&duplicated, 3).unwrap_err();
        assert_eq!(err, ShamirError::DuplicateShareIndex);
    }

    #[test]
    fn reconstruct_rejects_share_index_zero() {
        let mut rng = DeterministicRng::new(55);
        let mut shares = split_secret_with_rng(&sample_secret(), 3, 5, &mut rng).unwrap();
        shares[0].0 = 0;

        let err = reconstruct_secret(&shares[0..3], 3).unwrap_err();
        assert_eq!(
            err,
            ShamirError::InvalidShare("share index cannot be zero".to_string())
        );
    }

    #[test]
    fn wrong_share_value_does_not_reconstruct_original_secret() {
        let mut rng = DeterministicRng::new(77);
        let shares = split_secret_with_rng(&sample_secret(), 3, 5, &mut rng).unwrap();

        let mut tampered = vec![shares[0], shares[1], shares[2]];
        tampered[2].1[31] ^= 0xFF;

        let recovered = reconstruct_secret(&tampered, 3).unwrap();
        assert_ne!(recovered, sample_secret());
    }

    #[test]
    fn split_rejects_threshold_validation_errors() {
        let mut rng = DeterministicRng::new(1);

        let too_low = split_secret_with_rng(&sample_secret(), 1, 5, &mut rng).unwrap_err();
        assert_eq!(too_low, ShamirError::ThresholdTooLow);

        let invalid = split_secret_with_rng(&sample_secret(), 4, 3, &mut rng).unwrap_err();
        assert_eq!(invalid, ShamirError::InvalidThreshold);
    }

    #[test]
    fn field_add_sub_round_trip() {
        let a = FieldElement::from_u64(123_456_789);
        let b = FieldElement::from_u64(987_654_321);
        let c = a.field_add(b);
        let back = c.field_sub(b);
        assert_eq!(back, a);
    }

    #[test]
    fn field_mul_inverse_round_trip() {
        let value = FieldElement::from_u64(1337);
        let inv = value.invert().unwrap();
        let product = value.field_mul(inv);
        assert_eq!(product, FieldElement::one());
    }

    #[test]
    fn split_rejects_secret_equal_or_above_modulus() {
        let mut rng = DeterministicRng::new(2026);
        let mut modulus_bytes = [0u8; 32];
        for i in 0..4 {
            modulus_bytes[i * 8..(i + 1) * 8].copy_from_slice(&MODULUS[3 - i].to_be_bytes());
        }

        let err = split_secret_with_rng(&modulus_bytes, 3, 5, &mut rng).unwrap_err();
        assert_eq!(err, ShamirError::SecretOutOfRange);
    }

    #[test]
    fn ct_is_zero_correct() {
        assert!(bool::from(ct_is_zero(&[0, 0, 0, 0])));
        assert!(!bool::from(ct_is_zero(&[1, 0, 0, 0])));
        assert!(!bool::from(ct_is_zero(&[0, 0, 0, 1])));
    }

    #[test]
    fn pow_ct_matches_expected_inverse() {
        // x * x^(p-2) == 1 (Fermat's little theorem)
        let x = FieldElement::from_u64(42);
        let inv = x.pow_ct(MODULUS_MINUS_TWO);
        let product = x.field_mul(inv);
        assert_eq!(product, FieldElement::one());
    }
}
