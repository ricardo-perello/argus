use ark_codes::traits::LinearCode;
use ark_ff::Field;
use ark_serialize::CanonicalSerialize;
use ia_core::CommittedIndexBytes;

use crate::protocol::warp::WarpStaticMaterial;
use crate::protocol::WarpMerkle;
use crate::relations::r1cs::R1CSConstraints;
use crate::relations::BundledPESAT;

/// Tag prefixed to the canonical bytes returned by
/// `WarpVerifierKey::committed_index`. Distinct from any other Argus tag so
/// preprocessing DSFS cannot confuse a WARP verifier index with another
/// preprocessing protocol's commitment.
const WARP_VK_COMMIT_TAG: &[u8] = b"argus:warp:vk:v1";
const WARP_VK_COMMIT_MATERIAL_TAG: &[u8] = b"argus:warp:vk-material:v1";

fn update_commit_bytes(hasher: &mut blake3::Hasher, label: &[u8], bytes: &[u8]) {
    let label_len = u64::try_from(label.len()).expect("WARP commitment label length exceeds u64");
    let bytes_len = u64::try_from(bytes.len()).expect("WARP commitment field length exceeds u64");
    hasher.update(&label_len.to_le_bytes());
    hasher.update(label);
    hasher.update(&bytes_len.to_le_bytes());
    hasher.update(bytes);
}

fn update_commit_usize(hasher: &mut blake3::Hasher, label: &[u8], value: usize) {
    let value = u64::try_from(value).expect("WARP commitment usize value exceeds u64");
    update_commit_bytes(hasher, label, &value.to_le_bytes());
}

fn update_commit_canonical<T: CanonicalSerialize + ?Sized>(
    hasher: &mut blake3::Hasher,
    label: &[u8],
    value: &T,
) {
    let mut bytes = Vec::new();
    value
        .serialize_uncompressed(&mut bytes)
        .expect("WARP verifier-key commitment serialization failed");
    update_commit_bytes(hasher, label, &bytes);
}

fn update_commit_linear_combination<F: Field>(
    hasher: &mut blake3::Hasher,
    label: &[u8],
    lc: &[(F, usize)],
) {
    update_commit_bytes(hasher, b"lc", label);
    update_commit_usize(hasher, b"lc.len", lc.len());
    for (coeff, column) in lc {
        update_commit_usize(hasher, b"lc.column", *column);
        update_commit_canonical(hasher, b"lc.coeff", coeff);
    }
}

fn update_commit_constraints<F: Field>(
    hasher: &mut blake3::Hasher,
    constraints: &R1CSConstraints<F>,
) {
    update_commit_usize(hasher, b"r1cs.rows", constraints.len());
    for (a, b, c) in constraints {
        update_commit_linear_combination(hasher, b"a", a);
        update_commit_linear_combination(hasher, b"b", b);
        update_commit_linear_combination(hasher, b"c", c);
    }
}

pub(crate) fn committed_index_for<F, P, C, MT>(
    material: &WarpStaticMaterial<F, P, C, MT>,
) -> CommittedIndexBytes
where
    F: Field,
    P: BundledPESAT<F, Constraints = R1CSConstraints<F>, Config = (usize, usize, usize)>,
    C: LinearCode<F> + Clone + CanonicalSerialize,
    MT: WarpMerkle<F>,
{
    // Dimensions (M, N, k) are derived from the relation, not passed in — they
    // are the same `(m, n, k)` the indexer reads from `relation.config()`.
    let (m, n, k) = material.relation.config();
    let mut hasher = blake3::Hasher::new();
    update_commit_bytes(&mut hasher, b"tag", WARP_VK_COMMIT_MATERIAL_TAG);
    update_commit_usize(&mut hasher, b"vk.m", m);
    update_commit_usize(&mut hasher, b"vk.n", n);
    update_commit_usize(&mut hasher, b"vk.k", k);
    update_commit_usize(&mut hasher, b"config.l", material.config.l);
    update_commit_usize(&mut hasher, b"config.l1", material.config.l1);
    update_commit_usize(&mut hasher, b"config.s", material.config.s);
    update_commit_usize(&mut hasher, b"config.t", material.config.t);
    update_commit_usize(&mut hasher, b"config.p_conf.0", material.config.p_conf.0);
    update_commit_usize(&mut hasher, b"config.p_conf.1", material.config.p_conf.1);
    update_commit_usize(&mut hasher, b"config.p_conf.2", material.config.p_conf.2);
    update_commit_usize(&mut hasher, b"config.n", material.config.n);
    update_commit_usize(
        &mut hasher,
        b"code.message_len",
        material.code.message_len(),
    );
    update_commit_usize(&mut hasher, b"code.code_len", material.code.code_len());
    update_commit_canonical(&mut hasher, b"code", &material.code);
    update_commit_canonical(
        &mut hasher,
        b"mt.leaf_hash_params",
        &material.merkle_params.leaf_hash,
    );
    update_commit_canonical(
        &mut hasher,
        b"mt.two_to_one_hash_params",
        &material.merkle_params.two_to_one_hash,
    );
    update_commit_constraints(&mut hasher, material.relation.constraints());

    let digest = hasher.finalize();
    let mut out = Vec::with_capacity(WARP_VK_COMMIT_TAG.len() + digest.as_bytes().len());
    out.extend_from_slice(WARP_VK_COMMIT_TAG);
    out.extend_from_slice(digest.as_bytes());
    CommittedIndexBytes::new(out)
}
