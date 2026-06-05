//! Shared session type for compiled non-interactive protocols.

/// The public session / context data bound into a compiled non-interactive proof.
///
/// Hoisted into its own trait so the prover and verifier halves of every
/// non-interactive leaf trait share a *single* `Session` associated type. A value
/// that is both a prover and a verifier then has exactly one session type, and
/// `N::Session` stays unambiguous for any `N` bounded on either half (or on a
/// full-trait conjunction).
pub trait NonInteractiveSession {
    /// Public session or context data bound into the non-interactive proof.
    type Session;
}
