//! Composable security metadata (`SecurityErrorBound`, `SecurityProfile`).

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::{ArgumentCore, ReductionCore};

/// An error bound expressed as a function of the adversary's query budget `t`.
///
/// Internally stored as a sum of `Arc<dyn Fn(u64) -> f64 + Send + Sync>` terms
/// so that sequential composition (union bound) is just vector concatenation.
/// Closures capturing protocol parameters (field sizes, code distances, list
/// sizes, etc.) are fully supported; bare `fn` pointers are accepted as-is
/// since all `fn` items implement `Fn + Send + Sync`.
#[derive(Clone)]
pub struct SecurityErrorBound(Vec<Arc<dyn Fn(u64) -> f64 + Send + Sync>>);

impl SecurityErrorBound {
    /// A single-term error function.  Accepts both bare `fn` items and closures.
    pub fn new(f: impl Fn(u64) -> f64 + Send + Sync + 'static) -> Self {
        Self(alloc::vec![Arc::new(f)])
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
        terms.extend(self.0.iter().cloned());
        terms.extend(other.0.iter().cloned());
        Self(terms)
    }
}

/// Instance-aware security metadata for an interactive argument.
///
/// The returned [`SecurityProfile`] is always tied to either a concrete instance
/// (via [`Self::profile_for_concrete_instance`]) or to an explicit worst-case instance
/// bound (via [`Self::profile_for_instance_bound`]). This matches the formal convention
/// that soundness errors are functions of the false instance `x`, or of a size
/// bound `n` obtained by maximizing over possible instances.
///
/// Protocols with instance-independent security can use `()` for both associated
/// types and ignore the arguments in `profile_for_instance_params` /
/// `profile_for_instance_bound`.
pub trait ArgumentSecurity: ArgumentCore {
    /// Compact security-relevant parameters derived from a concrete instance.
    type InstanceParams;
    /// A worst-case/adaptive bound for a family of instances.
    type InstanceBound;

    /// Extract the parameters that the concrete-instance security bound depends on.
    fn instance_security_params(&self, instance: &Self::Instance) -> Self::InstanceParams;

    /// Convert concrete-instance parameters into a worst-case bound that contains them.
    fn instance_bound_for_instance_params(
        &self,
        params: &Self::InstanceParams,
    ) -> Self::InstanceBound;

    /// Build the security profile for a concrete instance summarized by `params`.
    fn profile_for_instance_params(&self, params: &Self::InstanceParams) -> SecurityProfile;

    /// Build the worst-case security profile for all instances covered by `bound`.
    fn profile_for_instance_bound(&self, bound: &Self::InstanceBound) -> SecurityProfile;

    /// Convenience: extract params from `instance`, then build the concrete profile.
    fn profile_for_concrete_instance(&self, instance: &Self::Instance) -> SecurityProfile {
        let params = self.instance_security_params(instance);
        self.profile_for_instance_params(&params)
    }

    /// Convenience: extract params from `instance`, then return a covering bound.
    fn instance_bound_for_concrete_instance(
        &self,
        instance: &Self::Instance,
    ) -> Self::InstanceBound {
        let params = self.instance_security_params(instance);
        self.instance_bound_for_instance_params(&params)
    }
}

/// Instance-aware security metadata for an interactive reduction.
///
/// Reductions need one additional piece of information beyond arguments: a bound
/// on the target instance produced by the verifier. Sequential composition uses
/// this target bound to evaluate the security of the next protocol without
/// needing to run the transcript just to learn the concrete target instance.
pub trait ReductionSecurity: ReductionCore {
    /// Compact security-relevant parameters derived from a concrete source instance.
    type SourceParams;
    /// A worst-case/adaptive bound for source instances.
    type SourceBound;
    /// A worst-case/adaptive bound for target instances produced by this reduction.
    type TargetBound;

    /// Extract the parameters that the concrete-source security bound depends on.
    fn source_security_params(&self, instance: &Self::SourceInstance) -> Self::SourceParams;

    /// Convert concrete source parameters into a worst-case bound that contains them.
    fn source_bound_for_source_params(&self, params: &Self::SourceParams) -> Self::SourceBound;

    /// Bound the target instance family produced from concrete source parameters.
    fn target_bound_for_source_params(&self, params: &Self::SourceParams) -> Self::TargetBound;

    /// Bound the target instance family produced from any source in `bound`.
    fn target_bound_for_source_bound(&self, bound: &Self::SourceBound) -> Self::TargetBound;

    /// Build the reduction security profile for a concrete source summarized by `params`.
    fn profile_for_source_params(&self, params: &Self::SourceParams) -> SecurityProfile;

    /// Build the worst-case reduction profile for all source instances covered by `bound`.
    fn profile_for_source_bound(&self, bound: &Self::SourceBound) -> SecurityProfile;

    /// Convenience: extract params from `instance`, then build the concrete profile.
    fn profile_for_source_instance(&self, instance: &Self::SourceInstance) -> SecurityProfile {
        let params = self.source_security_params(instance);
        self.profile_for_source_params(&params)
    }

    /// Convenience: extract params from `instance`, then return a covering source bound.
    fn source_bound_for_concrete_instance(
        &self,
        instance: &Self::SourceInstance,
    ) -> Self::SourceBound {
        let params = self.source_security_params(instance);
        self.source_bound_for_source_params(&params)
    }

    /// Convenience: extract params from `instance`, then return the induced target bound.
    fn target_bound_for_source_instance(
        &self,
        instance: &Self::SourceInstance,
    ) -> Self::TargetBound {
        let params = self.source_security_params(instance);
        self.target_bound_for_source_params(&params)
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
/// matching the formalism of Chiesa--Orru 2025 (Theorems 6.1, 6.2, 7.1).
///
/// # Soundness notions
///
/// - **Plain soundness** (`plain_soundness_error`): classical soundness, no
///   rewinding.  Relevant for interactive (live-channel) execution.
/// - **Round-by-round (RBR) soundness** (`rbr_soundness_errors`): per-round
///   local soundness condition.  Composes by concatenation.
/// - **State-restoration (SR) soundness**: derived from RBR via
///   `sr_soundness_error(t)`.  This is the input to DSFS Theorem 6.1.
/// - **RBR knowledge soundness** (`rbr_knowledge_soundness_errors`): per-round
///   local knowledge condition.  Composes by concatenation.  SR knowledge
///   soundness is derived from this via `sr_knowledge_soundness_error(t)`.
///   This is the input to DSFS Theorem 6.2.
#[derive(Debug, Clone)]
pub struct SecurityProfile {
    /// Plain soundness error epsilon(t).
    /// Relevant for live/interactive execution where SR is not needed.
    pub plain_soundness_error: SecurityErrorBound,
    /// Per-round RBR soundness errors [epsilon_1^rbr, ..., epsilon_mu^rbr].
    /// Length equals the number of public-coin rounds.
    pub rbr_soundness_errors: Vec<SecurityErrorBound>,
    /// Per-round RBR knowledge soundness errors [kappa_1^rbr, ..., kappa_mu^rbr].
    /// Length equals the number of public-coin rounds.
    pub rbr_knowledge_soundness_errors: Vec<SecurityErrorBound>,
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

    /// Derive the state-restoration soundness error at query budget `t`:
    ///
    /// ```text
    ///   eps^sr(t)  <=  t * max_i eps_i^rbr  +  sum_i eps_i^rbr
    /// ```
    ///
    /// # Grounding (CY24 Ch. 31, checked against the primary text)
    ///
    /// This is a *refinement of the proof* of CY24 Theorem 31.2.1, **not** the
    /// theorem's stated bound. The theorem *states* the uniform form
    /// `eps^sr <= (t + k) * eps^rbr`, where `eps^rbr = max_i eps_i^rbr` and the
    /// per-round errors `(eps_i^rbr)_{i in [k]}` are Definition 31.1.2. Its proof
    /// upper-bounds the doom-escape probability by a union bound over the `t + k`
    /// moves of `tr^sr_full`: the `t` state-restoration moves, plus `k`
    /// "completion" moves that are deterministically one-per-round. Charging the
    /// `k` completion moves at their own per-round error (Eq. 31.2, *before* the
    /// book relaxes each term to `max`) and the `t` adversarial moves at `max`
    /// yields exactly `t * max_i eps_i + sum_i eps_i`, which is `<= (t + k) * max`
    /// for all inputs. So this is a valid upper bound, strictly tighter than the
    /// stated theorem whenever the per-round errors are heterogeneous (e.g. WARP).
    ///
    /// Two endpoints anchor it: at `t = 0` it equals `sum_i eps_i^rbr`, the exact
    /// standard-soundness bound of Claim 31.1.3; at `k = 1` it equals
    /// `(t + 1) * max` — the stated theorem (so a one-round protocol such as
    /// Schnorr sits on the theorem and cannot exercise the refinement).
    ///
    /// Note on the `t` argument: CY24's per-round errors are functions of the
    /// *instance size n*, not of `t` (which only counts moves). The refinement
    /// above assumes the per-round [`SecurityErrorBound`]s are `t`-independent —
    /// capture instance/code parameters in the closures, not `t`. A genuinely
    /// `t`-dependent RBR term would place `t` both as the multiplier here and
    /// inside `eps_i(t)`, which is not what the proof gives.
    ///
    /// Returns 0.0 for protocols with no rounds.
    pub fn sr_soundness_error(&self, t: u64) -> f64 {
        if self.rbr_soundness_errors.is_empty() {
            return 0.0;
        }
        let evaluated: alloc::vec::Vec<f64> = self
            .rbr_soundness_errors
            .iter()
            .map(|e| e.evaluate(t))
            .collect();
        let max_rbr = evaluated.iter().cloned().fold(0.0_f64, f64::max);
        let sum_rbr: f64 = evaluated.iter().sum();
        (t as f64) * max_rbr + sum_rbr
    }

    /// Derive the state-restoration knowledge soundness error at query budget `t`:
    ///
    /// ```text
    ///   kappa^sr(t)  <=  t * max_i kappa_i^rbr  +  sum_i kappa_i^rbr
    /// ```
    ///
    /// The knowledge analogue of [`Self::sr_soundness_error`]: a refinement of the
    /// proof of CY24 Theorem 31.3.1 (per-round errors are Definition 31.1.6), with
    /// the identical `t + k` move-counting argument. The book's extractor is
    /// *straightline* (Construction 31.3.2 just runs the round-by-round extractor
    /// on the prover messages), so the extraction time carries through unchanged —
    /// it is not modeled here, only the error. Same `t`-vs-`n` caveat as
    /// [`Self::sr_soundness_error`] applies. Returns 0.0 for protocols with no
    /// rounds.
    pub fn sr_knowledge_soundness_error(&self, t: u64) -> f64 {
        if self.rbr_knowledge_soundness_errors.is_empty() {
            return 0.0;
        }
        let evaluated: alloc::vec::Vec<f64> = self
            .rbr_knowledge_soundness_errors
            .iter()
            .map(|e| e.evaluate(t))
            .collect();
        let max_rbr = evaluated.iter().cloned().fold(0.0_f64, f64::max);
        let sum_rbr: f64 = evaluated.iter().sum();
        (t as f64) * max_rbr + sum_rbr
    }

    /// Compose two protocol profiles sequentially.
    ///
    /// - RBR soundness / knowledge errors: concatenated (the correct composition).
    /// - Plain soundness / HVZK: union bound.
    /// - Challenge lengths: concatenated.
    pub fn compose(&self, other: &Self) -> Self {
        let mut rbr_soundness_errors =
            Vec::with_capacity(self.rbr_soundness_errors.len() + other.rbr_soundness_errors.len());
        rbr_soundness_errors.extend_from_slice(&self.rbr_soundness_errors);
        rbr_soundness_errors.extend_from_slice(&other.rbr_soundness_errors);

        let mut rbr_knowledge_soundness_errors = Vec::with_capacity(
            self.rbr_knowledge_soundness_errors.len() + other.rbr_knowledge_soundness_errors.len(),
        );
        rbr_knowledge_soundness_errors.extend_from_slice(&self.rbr_knowledge_soundness_errors);
        rbr_knowledge_soundness_errors.extend_from_slice(&other.rbr_knowledge_soundness_errors);

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
            rbr_knowledge_soundness_errors,
            hvzk_error: self.hvzk_error.compose(&other.hvzk_error),
            verifier_challenge_lengths,
        }
    }
}
