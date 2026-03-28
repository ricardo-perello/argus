//! Composable security metadata (`SecurityErrorBound`, `SecurityProfile`).

extern crate alloc;

use alloc::vec::Vec;

/// An error bound expressed as a function of the adversary's query budget `t`.
///
/// Internally stored as a sum of `fn(u64) -> f64` terms so that sequential
/// composition (union bound) is just vector concatenation -- no closures or
/// heap-allocated trait objects required.
#[derive(Clone)]
pub struct SecurityErrorBound(Vec<fn(u64) -> f64>);

impl SecurityErrorBound {
    /// A single-term error function.
    pub fn new(f: fn(u64) -> f64) -> Self {
        Self(alloc::vec![f])
    }

    /// The zero error function (identically 0 for all `t`).
    pub fn zero() -> Self {
        Self(Vec::new())
    }

    /// Evaluate the error bound at query budget `t`.
    pub fn evaluate(&self, t: u64) -> f64 {
        self.0.iter().map(|f| f(t)).sum()
    }

    /// Additive composition: `(self + other)(t) = self(t) + other(t)`.
    pub fn compose(&self, other: &Self) -> Self {
        let mut terms = Vec::with_capacity(self.0.len() + other.0.len());
        terms.extend_from_slice(&self.0);
        terms.extend_from_slice(&other.0);
        Self(terms)
    }
}

impl core::fmt::Debug for SecurityErrorBound {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecurityErrorBound({} terms)", self.0.len())
    }
}

/// Security metadata for an interactive protocol.
///
/// Error bounds are functions of the adversary's query budget `t`,
/// matching the formalism of Chiesa--Orrù 2025 (Theorems 1 & 2).
#[derive(Debug, Clone)]
pub struct SecurityProfile {
    /// State-restoration soundness error ε^sr(t).
    pub soundness_error: SecurityErrorBound,
    /// State-restoration knowledge soundness error κ^sr(t).
    pub knowledge_soundness_error: SecurityErrorBound,
    /// Honest-verifier zero-knowledge error z(t).
    pub hvzk_error: SecurityErrorBound,
    /// Number of public-coin rounds.
    pub num_rounds: usize,
    /// Verifier challenge lengths `l_V(i)` in sponge alphabet units.
    pub verifier_challenge_lengths: Vec<usize>,
}

impl SecurityProfile {
    /// Compose two protocol profiles (union bound on errors, concatenate rounds).
    pub fn compose(&self, other: &Self) -> Self {
        let mut verifier_challenge_lengths =
            Vec::with_capacity(self.num_rounds + other.num_rounds);
        verifier_challenge_lengths.extend_from_slice(&self.verifier_challenge_lengths);
        verifier_challenge_lengths.extend_from_slice(&other.verifier_challenge_lengths);

        Self {
            soundness_error: self.soundness_error.compose(&other.soundness_error),
            knowledge_soundness_error: self
                .knowledge_soundness_error
                .compose(&other.knowledge_soundness_error),
            hvzk_error: self.hvzk_error.compose(&other.hvzk_error),
            num_rounds: self.num_rounds + other.num_rounds,
            verifier_challenge_lengths,
        }
    }
}
