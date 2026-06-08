//! Index-aware security metadata for preprocessed protocols.
//!
//! Mirrors [`crate::ArgumentSecurity`] and
//! [`crate::ReductionSecurity`], but threads through index-derived
//! parameters and bounds so a single preprocessed index can be reused across
//! many per-claim instances without recomputing the index portion of the
//! security profile.

use crate::{ArgumentCore, Indexer, ReductionCore, SecurityErrorBound, SecurityProfile};

/// Index-aware argument security metadata, implemented by the indexer role.
///
/// The security profile may depend on both the static index and the per-claim
/// instance. Separating the two lets callers cache the index-derived portion
/// across instances under the same preprocessed verifier key.
pub trait PreprocessingArgumentSecurity: ArgumentCore + Indexer {
    /// Compact security-relevant parameters derived from a concrete index.
    type IndexParams;
    /// A worst-case/adaptive bound for a family of indices.
    type IndexBound;
    /// Compact security-relevant parameters derived from a concrete per-claim
    /// instance under a fixed index.
    type InstanceParams;
    /// A worst-case/adaptive bound for a family of per-claim instances under a
    /// fixed index.
    type InstanceBound;

    fn index_security_params(&self, ix: &Self::Index) -> Self::IndexParams;

    fn index_bound_for_index_params(&self, params: &Self::IndexParams) -> Self::IndexBound;

    /// One-time soundness error from binding a proof to the committed index (the
    /// offline/preprocessing phase), as a function of the query budget `t`.
    ///
    /// **Added once** to the compiled NARG soundness and knowledge-soundness
    /// bounds; **not** part of the per-round state-restoration budget, and
    /// **not** part of zero knowledge (the offline phase does not affect ZK —
    /// CY24 §32.8.4).
    ///
    /// # Grounding (CY24 §32.7 COS transformation, §32.8.1)
    ///
    /// In COS the verifier index key is `vik = (rt_0, rho_0)`: a Merkle
    /// commitment `rt_0` to the encoded verifier index `i_v` (length `l_0`) and a
    /// hash `rho_0 = f_0(i)` of the raw index (Construction 32.3.1). COS soundness
    /// is the underlying error plus a small additive offline term (§32.8.1):
    ///
    /// ```text
    ///   eps_offline  =  (t_MT0 + 2*l_0)^2 / 2^(lambda+1)   // E1: binding of rt_0
    ///                +  t_0^2          / 2^(lambda+1)       // E2: collision in f_0
    /// ```
    ///
    /// Two regimes, both expressible here:
    /// - **Verifier holds the full authentic index** (non-succinct): return
    ///   [`SecurityErrorBound::zero`]. There is no committed index a prover can
    ///   equivocate (`E1 = 0`), and any index digest absorbed for domain
    ///   separation is not load-bearing — the verifier checks against the real
    ///   material — so it is covered by the FS transcript soundness rather than a
    ///   separate term (`E2` moot; CY24 §32.7 fn. 3).
    /// - **Succinct (Merkle-committed, prover-opened) verifier index**: return
    ///   the full `E1 + E2` term, reading `l_0` from `ix_params`.
    ///
    /// This method is **required** (no default): a zero default would let a future
    /// succinct-verifier protocol silently report zero offline error — the unsafe
    /// direction. Protocols whose verifier holds the full index return
    /// [`SecurityErrorBound::zero`] *explicitly*.
    ///
    /// The duplex-sponge instantiation replaces `1/2^lambda` with the
    /// commitment's collision resistance; this is an analogy to the
    /// random-oracle bound above, not a separately proven DSFS-COS theorem.
    fn offline_binding_error(&self, ix_params: &Self::IndexParams) -> SecurityErrorBound;

    fn instance_security_params(
        &self,
        ix_params: &Self::IndexParams,
        instance: &Self::Instance,
    ) -> Self::InstanceParams;

    fn instance_bound_for_instance_params(
        &self,
        ix_params: &Self::IndexParams,
        params: &Self::InstanceParams,
    ) -> Self::InstanceBound;

    fn profile_for_instance_params(
        &self,
        ix_params: &Self::IndexParams,
        instance_params: &Self::InstanceParams,
    ) -> SecurityProfile;

    fn profile_for_instance_bound(
        &self,
        ix_bound: &Self::IndexBound,
        instance_bound: &Self::InstanceBound,
    ) -> SecurityProfile;

    /// Convenience: extract index and instance params from concrete values,
    /// then build the profile.
    fn profile_for_concrete(&self, ix: &Self::Index, instance: &Self::Instance) -> SecurityProfile {
        let ix_params = self.index_security_params(ix);
        let instance_params = self.instance_security_params(&ix_params, instance);
        self.profile_for_instance_params(&ix_params, &instance_params)
    }
}

/// Index-aware reduction security metadata, implemented by the indexer role.
pub trait PreprocessingReductionSecurity: ReductionCore + Indexer {
    /// Compact security-relevant parameters derived from a concrete index.
    type IndexParams;
    /// A worst-case/adaptive bound for a family of indices.
    type IndexBound;
    /// Compact security-relevant parameters derived from a concrete source
    /// instance under a fixed index.
    type SourceParams;
    /// A worst-case/adaptive bound for source instances under a fixed index.
    type SourceBound;
    /// A worst-case/adaptive bound for target instances produced by this
    /// reduction under a fixed index.
    type TargetBound;

    fn index_security_params(&self, ix: &Self::Index) -> Self::IndexParams;

    fn index_bound_for_index_params(&self, params: &Self::IndexParams) -> Self::IndexBound;

    /// One-time offline index-binding soundness error, added once to the compiled
    /// NARG soundness and knowledge bounds (not to the SR budget, not to ZK). See
    /// [`PreprocessingArgumentSecurity::offline_binding_error`] for the full
    /// grounding (CY24 §32.7 / §32.8.1). Required (no default) for the same
    /// safety reason; verifiers that hold the full authentic index return
    /// [`SecurityErrorBound::zero`] explicitly.
    fn offline_binding_error(&self, ix_params: &Self::IndexParams) -> SecurityErrorBound;

    fn source_security_params(
        &self,
        ix_params: &Self::IndexParams,
        instance: &Self::SourceInstance,
    ) -> Self::SourceParams;

    fn source_bound_for_source_params(
        &self,
        ix_params: &Self::IndexParams,
        params: &Self::SourceParams,
    ) -> Self::SourceBound;

    fn target_bound_for_source_params(
        &self,
        ix_params: &Self::IndexParams,
        params: &Self::SourceParams,
    ) -> Self::TargetBound;

    fn target_bound_for_source_bound(
        &self,
        ix_bound: &Self::IndexBound,
        bound: &Self::SourceBound,
    ) -> Self::TargetBound;

    fn profile_for_source_params(
        &self,
        ix_params: &Self::IndexParams,
        source_params: &Self::SourceParams,
    ) -> SecurityProfile;

    fn profile_for_source_bound(
        &self,
        ix_bound: &Self::IndexBound,
        source_bound: &Self::SourceBound,
    ) -> SecurityProfile;

    /// Convenience: extract index and source params from concrete values,
    /// then build the profile.
    fn profile_for_concrete_source(
        &self,
        ix: &Self::Index,
        instance: &Self::SourceInstance,
    ) -> SecurityProfile {
        let ix_params = self.index_security_params(ix);
        let source_params = self.source_security_params(&ix_params, instance);
        self.profile_for_source_params(&ix_params, &source_params)
    }
}
