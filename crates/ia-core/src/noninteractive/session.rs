//! Shared session type for compiled non-interactive protocols.

/// The public session / context data bound into a compiled non-interactive proof.
///
/// Hoisted into its own trait so the prover and verifier halves of every
/// non-interactive role trait shares the same orthogonal session vocabulary.
pub trait NonInteractiveSession {
    /// Public session or context data bound into the non-interactive proof.
    type Session;
}
