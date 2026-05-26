//! Marker traits for preprocessed non-interactive protocols.

use crate::{NonInteractiveArgument, NonInteractiveReduction, Preprocessed};

/// Non-interactive argument produced from a preprocessed body.
///
/// A marker trait combining [`NonInteractiveArgument`] with the
/// [`Preprocessed`] capability. The actual
/// accessors (`prover_key`, `verifier_key`, `committed_index`) live on
/// `Preprocessed`, which is the single discoverable home for preprocessing
/// keys regardless of which lattice plane (IA/IR or NARG) the wrapper sits on.
///
/// Plain NARGs (e.g. `DsfsArgument<plain_ia>`) do NOT implement `Preprocessed` and
/// therefore do NOT satisfy this bound: the type system enforces that a
/// generic consumer with bound `T: PreprocessingNonInteractiveArgument` provably
/// receives a NARG built from a preprocessed body.
pub trait PreprocessingNonInteractiveArgument: NonInteractiveArgument + Preprocessed {}

impl<T> PreprocessingNonInteractiveArgument for T where T: NonInteractiveArgument + Preprocessed {}

/// Non-interactive reduction produced from a preprocessed body.
///
/// Reduction counterpart to [`PreprocessingNonInteractiveArgument`]; same
/// composition, same strong-typing argument.
pub trait PreprocessingNonInteractiveReduction: NonInteractiveReduction + Preprocessed {}

impl<T> PreprocessingNonInteractiveReduction for T where T: NonInteractiveReduction + Preprocessed {}
