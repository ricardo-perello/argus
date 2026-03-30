//! Session ID derivation (σ-proofs–compatible).

use sha3::digest::{ExtendableOutput, Update, XofReader};

/// Derive the 64-byte spongefish session field from an arbitrary `session_id`, matching σ-proofs
/// [`fiat_shamir::derive_session_id`](https://github.com/sigma-rs/sigma-proofs/blob/main/src/fiat_shamir.rs).
pub fn derive_session_id(session_id: &[u8]) -> [u8; 64] {
    const RATE: usize = 168;
    const DOMAIN: &[u8] = b"fiat-shamir/session-id";

    let mut initial_block = [0u8; RATE];
    initial_block[..DOMAIN.len()].copy_from_slice(DOMAIN);

    let mut shake = sha3::Shake128::default();
    shake.update(&initial_block);
    shake.update(session_id);

    let mut reader = shake.finalize_xof();
    let mut derived = [0u8; 64];
    reader.read(&mut derived[32..]);
    derived
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_session_id_is_deterministic() {
        let a = derive_session_id(b"test-session");
        let b = derive_session_id(b"test-session");
        assert_eq!(a, b);
    }

    #[test]
    fn derive_session_id_differs_for_distinct_inputs() {
        assert_ne!(derive_session_id(b"a"), derive_session_id(b"b"));
    }
}
