use ark_ff::{Field, PrimeField};
use std::collections::HashMap;

pub mod poly;
pub mod poseidon;

pub type FastMap<F> = HashMap<usize, F, nohash_hasher::BuildNoHashHasher<usize>>;

pub fn chunk_size<F: Field + PrimeField>() -> usize {
    let mut buf = Vec::new();
    F::zero().serialize_uncompressed(&mut buf).unwrap();
    buf.len()
}

pub fn bytes_to_vec_f<F: Field + PrimeField>(bytes: &[u8]) -> Vec<F> {
    bytes
        .chunks(chunk_size::<F>())
        .map(|chunk| F::from_le_bytes_mod_order(chunk))
        .collect()
}

pub fn byte_to_binary_field_array<F: Field>(byte: &u8) -> Vec<F> {
    (0..8)
        .map(|i| {
            let val = (byte >> i) & 1 == 1;
            F::from(val)
        })
        .collect::<Vec<_>>()
}

pub fn binary_field_elements_to_usize<F: Field>(elements: &[F]) -> usize {
    elements
        .iter()
        .rev()
        .fold(0, |acc, &b| (acc << 1) | b.is_one() as usize)
}

pub fn concat_slices<F: Clone>(a: &[F], b: &[F]) -> Vec<F> {
    let mut v = Vec::<F>::with_capacity(a.len() + b.len());
    v.extend_from_slice(a);
    v.extend_from_slice(b);
    v
}

pub fn scale_and_sum<F: Field>(vectors: &[Vec<F>], scalars: &[F]) -> Vec<F> {
    let n = vectors[0].len();
    let mut result = vec![F::default(); n];
    vectors.iter().zip(scalars).for_each(|(v, &a)| {
        result.iter_mut().zip(v).for_each(|(r, &x)| *r += a * x);
    });
    result
}

pub trait BoolResult {
    fn ok_or_err<E>(self, err: E) -> Result<(), E>;
}

impl BoolResult for bool {
    #[inline]
    fn ok_or_err<E>(self, err: E) -> Result<(), E> {
        if self { Ok(()) } else { Err(err) }
    }
}
