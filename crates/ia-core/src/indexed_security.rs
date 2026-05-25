//! Index-aware security metadata for preprocessed protocols.
//!
//! Mirrors [`crate::security::ArgumentSecurity`] and
//! [`crate::security::ReductionSecurity`], but threads through index-derived
//! parameters and bounds so a single preprocessed index can be reused across
//! many per-claim instances without recomputing the index portion of the
//! security profile.

use crate::SecurityProfile;
use crate::indexed::{PreprocessingInteractiveArgument, PreprocessingInteractiveReduction};

/// Index-aware security metadata for an [`PreprocessingInteractiveArgument`].
///
/// The security profile may depend on both the static index and the per-claim
/// instance. Separating the two lets callers cache the index-derived portion
/// across instances under the same preprocessed verifier key.
pub trait PreprocessingArgumentSecurity: PreprocessingInteractiveArgument {
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

/// Index-aware security metadata for an [`PreprocessingInteractiveReduction`].
pub trait PreprocessingReductionSecurity: PreprocessingInteractiveReduction {
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
