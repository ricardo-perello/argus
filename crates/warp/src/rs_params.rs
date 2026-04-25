use ia_core::CodeSecurityParams;

/// Reed-Solomon code security parameters for WARP's instance-aware security profile.
///
/// This is a local struct — not `ReedSolomon<F>` itself — so that the orphan
/// rule is satisfied: `CodeSecurityParams` (from `ia-core`) and `ReedSolomon<F>`
/// (from `ark-codes`) are both foreign to this crate, but a local struct may
/// implement a foreign trait.
///
/// Construct from your `ReedSolomon<F>` when deriving `WARPSecurityParams`:
///
/// ```ignore
/// let code_params = ReedSolomonParams::new(
///     code.code_len(),
///     code.message_len(),
///     F::MODULUS_BIT_SIZE,
/// );
/// ```
#[derive(Clone, Debug)]
pub struct ReedSolomonParams {
    /// Codeword length n.
    pub n: usize,
    /// Message length (dimension) k.
    pub k: usize,
    /// Approximate bit-length of the field size: |F| ≈ 2^field_size_bits.
    pub field_size_bits: u32,
}

impl ReedSolomonParams {
    pub fn new(n: usize, k: usize, field_size_bits: u32) -> Self {
        Self {
            n,
            k,
            field_size_bits,
        }
    }

    fn field_size_inv(&self) -> f64 {
        2_f64.powi(-(self.field_size_bits as i32))
    }
}

impl CodeSecurityParams for ReedSolomonParams {
    /// Relative minimum distance δ = 1 − k/n.
    fn distance(&self) -> f64 {
        1.0 - self.k as f64 / self.n as f64
    }

    /// Upper bound on the list-decoding list size |Λ(C, δ)|.
    ///
    /// Conservative bound: at most n codewords in any list.
    /// TODO: tighten to O(n / δ) via the Johnson bound — confirm with Chiesa.
    fn list_size_bound(&self) -> f64 {
        self.n as f64
    }

    /// BCIKS20 bound: err_PG(C, degree, δ) ≤ (degree + 1) · n² / |F|.
    ///
    /// This is the probability that a random degree-`degree` linear combination
    /// of vectors individually δ-close to codewords is still δ-close.
    fn proximity_generator_error(&self, degree: usize) -> f64 {
        (degree + 1) as f64 * (self.n as f64).powi(2) * self.field_size_inv()
    }
}
