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

/// Security metadata provider for an interactive protocol.
///
/// Separate from `InteractiveArgument` / `InteractiveReduction` so that protocols
/// without fully specified bounds can still implement the core traits.
/// Composition structs (`ChainedReduction`, `ReducedArgument`) provide conditional
/// impls when both sub-protocols implement this.
pub trait ProtocolSecurity {
    fn security(&self) -> SecurityProfile;
}

impl core::fmt::Debug for SecurityErrorBound {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecurityErrorBound({} terms)", self.0.len())
    }
}

/// Security metadata for an interactive protocol.
///
/// Error bounds are functions of the adversary's query budget `t`,
/// matching the formalism of Chiesa--Orru 2025 (Theorems 6.1, 6.2, 7.1).
///
/// # Soundness notions
///
/// - **Plain soundness** (`plain_soundness_error`): classical soundness, no
///   rewinding.  Relevant for interactive (live-channel) execution.
/// - **Round-by-round (RBR) soundness** (`rbr_soundness_errors`): per-round
///   local soundness condition.  Composes by concatenation.
/// - **State-restoration (SR) soundness**: derived from RBR via
///   `sr_soundness_error() = sum_i rbr_soundness_errors[i]`.  This is the
///   input to DSFS Theorem 6.1.
/// - **SR knowledge soundness** (`sr_knowledge_soundness_error`): used by
///   DSFS Theorem 6.2.
#[derive(Debug, Clone)]
pub struct SecurityProfile {
    /// Plain soundness error epsilon(t).
    /// Relevant for live/interactive execution where SR is not needed.
    pub plain_soundness_error: SecurityErrorBound,
    /// Per-round RBR soundness errors [epsilon_1^rbr, ..., epsilon_mu^rbr].
    /// Length equals the number of public-coin rounds.
    pub rbr_soundness_errors: Vec<SecurityErrorBound>,
    /// State-restoration knowledge soundness error kappa^sr(t).
    ///
    /// TODO(Alessandro): this is currently a flat stored field set by protocol
    /// authors.  If CY24 provides a round-by-round knowledge soundness notion
    /// analogous to RBR soundness, this should become a *derived* field with the
    /// correct formula:
    ///   kappa^sr(s, t, n) <= (t + k) * kappa^rbr(n)
    /// (CY24 Theorem 31.3.1).  If knowledge soundness is only defined at the SR
    /// level (as in DSFS Theorem 6.2), the flat stored field is correct.
    /// Please confirm before changing.
    pub sr_knowledge_soundness_error: SecurityErrorBound,
    /// Honest-verifier zero-knowledge error z(t).
    pub hvzk_error: SecurityErrorBound,
    /// Verifier challenge lengths `l_V(i)` in sponge alphabet units.
    pub verifier_challenge_lengths: Vec<usize>,
}

impl SecurityProfile {
    /// Number of public-coin rounds, derived from RBR vector length.
    pub fn num_rounds(&self) -> usize {
        self.rbr_soundness_errors.len()
    }

    /// Derive SR soundness from RBR: epsilon^sr(t) = sum_i epsilon_i^rbr(t).
    ///
    /// This is the bound used by DSFS Theorem 6.1 to lift interactive
    /// soundness to NARG soundness.
    ///
    /// TODO(Alessandro): this formula gives *standard* soundness via union bound
    /// (CY24 Claim 31.1.3), not SR soundness.  The correct SR soundness bound is
    ///   epsilon^sr(s, t, n) <= (t + k) * epsilon^rbr(n)
    /// where t is the adversary's query budget, k = num_rounds() is the round
    /// complexity, and epsilon^rbr(n) is the (uniform) per-round RBR error
    /// (CY24 Theorem 31.2.1).  For heterogeneous per-round errors the exact
    /// statement should be confirmed against CY24 before implementing.
    pub fn sr_soundness_error(&self) -> SecurityErrorBound {
        self.rbr_soundness_errors
            .iter()
            .fold(SecurityErrorBound::zero(), |acc, e| acc.compose(e))
    }

    /// Compose two protocol profiles sequentially.
    ///
    /// - RBR soundness errors: concatenated (the correct composition).
    /// - Plain soundness / SR knowledge soundness / HVZK: union bound.
    /// - Challenge lengths: concatenated.
    pub fn compose(&self, other: &Self) -> Self {
        let mut rbr_soundness_errors = Vec::with_capacity(
            self.rbr_soundness_errors.len() + other.rbr_soundness_errors.len(),
        );
        rbr_soundness_errors.extend_from_slice(&self.rbr_soundness_errors);
        rbr_soundness_errors.extend_from_slice(&other.rbr_soundness_errors);

        let mut verifier_challenge_lengths = Vec::with_capacity(
            self.verifier_challenge_lengths.len() + other.verifier_challenge_lengths.len(),
        );
        verifier_challenge_lengths.extend_from_slice(&self.verifier_challenge_lengths);
        verifier_challenge_lengths.extend_from_slice(&other.verifier_challenge_lengths);

        Self {
            plain_soundness_error: self
                .plain_soundness_error
                .compose(&other.plain_soundness_error),
            rbr_soundness_errors,
            sr_knowledge_soundness_error: self
                .sr_knowledge_soundness_error
                .compose(&other.sr_knowledge_soundness_error),
            hvzk_error: self.hvzk_error.compose(&other.hvzk_error),
            verifier_challenge_lengths,
        }
    }
}
