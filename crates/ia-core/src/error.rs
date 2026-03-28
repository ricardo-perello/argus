//! Verification errors and result type.

/// Verification failed.
#[derive(Debug, Clone, Copy)]
pub struct VerificationError;

/// Result type for verification operations.
pub type VerificationResult<T> = Result<T, VerificationError>;
