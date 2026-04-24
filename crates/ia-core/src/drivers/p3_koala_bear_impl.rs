//! Plonky3 `KoalaBear` codec implementation.

use p3_field::PrimeField32;
use p3_koala_bear::KoalaBear;

use crate::{Decoding, Encoding, NargDeserialize, VerificationError, VerificationResult};

impl Decoding<[u8]> for KoalaBear {
    type Repr = [u8; 8];

    fn decode(buf: Self::Repr) -> Self {
        let n = u64::from_le_bytes(buf);
        Self::new((n % u64::from(Self::ORDER_U32)) as u32)
    }
}

impl NargDeserialize for KoalaBear {
    fn deserialize_from_narg(buf: &mut &[u8]) -> VerificationResult<Self> {
        if buf.len() < 4 {
            return Err(VerificationError);
        }

        let mut repr = [0u8; 4];
        repr.copy_from_slice(&buf[..4]);
        let value = u32::from_be_bytes(repr);

        if value >= Self::ORDER_U32 {
            return Err(VerificationError);
        }

        *buf = &buf[4..];
        Ok(Self::new(value))
    }
}

impl Encoding<[u8]> for KoalaBear {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.as_canonical_u32().to_be_bytes()
    }
}
