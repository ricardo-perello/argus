//! Verification errors and result type.

/// Verification failed.
#[derive(Debug, Clone, Copy)]
pub struct VerificationError;

/// Result type for verification operations.
pub type VerificationResult<T> = Result<T, VerificationError>;

impl From<spongefish::VerificationError> for VerificationError {
    fn from(_: spongefish::VerificationError) -> Self {
        VerificationError
    }
}