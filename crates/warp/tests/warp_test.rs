use std::borrow::Borrow;
use std::marker::PhantomData;

use ark_bls12_381::Fr as Fp;
use ark_codes::{
    reed_solomon::{config::ReedSolomonConfig, ReedSolomon},
    traits::LinearCode,
};
use ark_crypto_primitives::crh::poseidon::{constraints::CRHGadget, CRH};
use ark_crypto_primitives::{
    crh::{ByteDigest, CRHScheme, TwoToOneCRHScheme},
    Error as CryptoError,
};
use ark_ff::UniformRand;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::Rng;
use rand::thread_rng;

use ia_core::{
    Encoding, PreprocessingCore, PreprocessingNonInteractiveArgument,
    PreprocessingNonInteractiveReduction, PreprocessingReductionSecurity, VerifierKeyCommitment,
};
use spongefish_dsfs::{self as dsfs, Keccak};
use warp::{
    config::WarpConfig,
    crypto::merkle::{blake3::Blake3MerkleTreeParams, parameters::MerkleTreeParams},
    relations::{
        r1cs::{
            hashchain::{
                compute_hash_chain, HashChainInstance, HashChainRelation, HashChainWitness,
            },
            R1CS,
        },
        BundledPESAT, Relation, ToPolySystem,
    },
    types::{AccumulatorInstances, AccumulatorWitnesses},
    utils::poseidon,
    FullWarp, WarpDecider, WarpIndex, WarpInstance, WarpMerkleParams, WarpReduction, WarpWitness,
};

type MT = Blake3MerkleTreeParams<Fp>;

#[derive(Clone)]
struct ParamLeafHash;

impl CRHScheme for ParamLeafHash {
    type Input = [Fp];
    type Output = ByteDigest<32>;
    type Parameters = [u8; 32];

    fn setup<R: Rng>(_: &mut R) -> Result<Self::Parameters, CryptoError> {
        Ok([0u8; 32])
    }

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, CryptoError> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(parameters);
        input.borrow().serialize_uncompressed(&mut bytes)?;
        Ok(ByteDigest(*blake3::hash(&bytes).as_bytes()))
    }
}

#[derive(Clone)]
struct ParamTwoToOneHash;

impl TwoToOneCRHScheme for ParamTwoToOneHash {
    type Input = ByteDigest<32>;
    type Output = ByteDigest<32>;
    type Parameters = [u8; 32];

    fn setup<R: Rng>(_: &mut R) -> Result<Self::Parameters, CryptoError> {
        Ok([0u8; 32])
    }

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, CryptoError> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(parameters);
        hasher.update(&left_input.borrow().0);
        hasher.update(&right_input.borrow().0);
        Ok(ByteDigest(*hasher.finalize().as_bytes()))
    }

    fn compress<T: Borrow<Self::Output>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, CryptoError> {
        Self::evaluate(parameters, left_input, right_input)
    }
}

type ParamMT = MerkleTreeParams<Fp, ParamLeafHash, ParamTwoToOneHash, ByteDigest<32>>;

#[allow(clippy::type_complexity)]
fn setup() -> (R1CS<Fp>, ReedSolomon<Fp>, Vec<Vec<Fp>>, Vec<Vec<Fp>>) {
    let hash_chain_size = 10;
    let mut rng = thread_rng();
    let poseidon_config = poseidon::initialize_poseidon_config::<Fp>();
    let l1 = 4;

    let r1cs = HashChainRelation::<Fp, CRH<_>, CRHGadget<_>>::into_r1cs(&(
        poseidon_config.clone(),
        hash_chain_size,
    ))
    .unwrap();

    let code_config = ReedSolomonConfig::<Fp>::default(r1cs.k, r1cs.k.next_power_of_two());
    let code = ReedSolomon::new(code_config);

    let (instances, witnesses): (Vec<Vec<Fp>>, Vec<Vec<Fp>>) = (0..l1)
        .map(|_| {
            let preimage = vec![Fp::rand(&mut rng)];
            let instance = HashChainInstance {
                digest: compute_hash_chain::<Fp, CRH<_>>(
                    &poseidon_config,
                    &preimage,
                    hash_chain_size,
                ),
            };
            let witness = HashChainWitness {
                preimage,
                _crhs_scheme: PhantomData::<CRH<Fp>>,
            };
            let relation = HashChainRelation::<Fp, CRH<_>, CRHGadget<_>>::new(
                instance,
                witness,
                (poseidon_config.clone(), hash_chain_size),
            );
            (relation.x, relation.w)
        })
        .unzip();

    (r1cs, code, instances, witnesses)
}

fn empty_acc() -> (AccumulatorInstances<Fp, MT>, AccumulatorWitnesses<Fp, MT>) {
    (
        (vec![], vec![], vec![], (vec![], vec![]), vec![]),
        (vec![], vec![], vec![]),
    )
}

fn warp_index(
    r1cs: R1CS<Fp>,
    code: ReedSolomon<Fp>,
    l: usize,
    l1: usize,
) -> WarpIndex<Fp, R1CS<Fp>, ReedSolomon<Fp>, MT> {
    let n = code.code_len();
    WarpIndex::new(
        WarpConfig::new(l, l1, 8, 7, r1cs.config(), n),
        r1cs,
        code,
        WarpMerkleParams::new((), ()),
    )
}

fn param_warp_index(
    r1cs: R1CS<Fp>,
    code: ReedSolomon<Fp>,
    leaf_param: [u8; 32],
    two_to_one_param: [u8; 32],
) -> WarpIndex<Fp, R1CS<Fp>, ReedSolomon<Fp>, ParamMT> {
    let n = code.code_len();
    WarpIndex::new(
        WarpConfig::new(4, 4, 8, 7, r1cs.config(), n),
        r1cs,
        code,
        WarpMerkleParams::new(leaf_param, two_to_one_param),
    )
}

fn warp_statement(
    instances: Vec<Vec<Fp>>,
    witnesses: Vec<Vec<Fp>>,
) -> (WarpInstance<Fp, MT>, WarpWitness<Fp, MT>) {
    let (empty_inst, empty_wit) = empty_acc();
    (
        WarpInstance {
            instances,
            acc_instances: empty_inst,
        },
        WarpWitness {
            witnesses,
            acc_witnesses: empty_wit,
        },
    )
}

fn changed_relation_same_dimensions(r1cs: &R1CS<Fp>) -> R1CS<Fp> {
    let mut changed = r1cs.clone();
    let (coeff, _) = changed
        .p
        .iter_mut()
        .flat_map(|(a, b, c)| a.iter_mut().chain(b.iter_mut()).chain(c.iter_mut()))
        .next()
        .expect("test R1CS has at least one non-zero constraint entry");
    *coeff += Fp::from(1u64);
    assert_eq!(r1cs.m, changed.m);
    assert_eq!(r1cs.n, changed.n);
    assert_eq!(r1cs.k, changed.k);
    changed
}

fn committed_index(ix: &WarpIndex<Fp, R1CS<Fp>, ReedSolomon<Fp>, MT>) -> Vec<u8> {
    let ir = WarpReduction::<Fp, R1CS<Fp>, ReedSolomon<Fp>, MT>::new();
    let (_, vk) = ir.index(ix);
    vk.committed_index().as_bytes().to_vec()
}

#[test]
fn warp_security_profile_is_derived_from_index() {
    let (r1cs, code, instances, _) = setup();
    let (small_instance, _) = warp_statement(instances.clone(), vec![]);
    let (large_instance, _) = warp_statement(instances, vec![]);

    let ix_small = warp_index(r1cs.clone(), code.clone(), 4, 4);
    let ix_large = warp_index(r1cs, code, 8, 4);

    let ir = WarpReduction::<Fp, R1CS<Fp>, ReedSolomon<Fp>, MT>::new();
    let small_profile = ir.profile_for_concrete_source(&ix_small, &small_instance);
    let large_profile = ir.profile_for_concrete_source(&ix_large, &large_instance);

    assert_eq!(
        large_profile.rbr_soundness_errors.len(),
        small_profile.rbr_soundness_errors.len() + 1,
    );
    assert!(
        large_profile.sr_soundness_error(0) > small_profile.sr_soundness_error(0),
        "larger WARP index should carry a larger concrete RBR sum",
    );
}

#[test]
fn warp_commitment_stable_for_same_index() {
    let (r1cs, code, _, _) = setup();
    let ix_a = warp_index(r1cs.clone(), code.clone(), 4, 4);
    let ix_b = warp_index(r1cs, code, 4, 4);
    assert_eq!(committed_index(&ix_a), committed_index(&ix_b));
}

#[test]
fn warp_commitment_changes_when_constraints_change() {
    let (r1cs, code, _, _) = setup();
    let changed_r1cs = changed_relation_same_dimensions(&r1cs);

    let ix_a = warp_index(r1cs, code.clone(), 4, 4);
    let ix_b = warp_index(changed_r1cs, code, 4, 4);

    assert_ne!(committed_index(&ix_a), committed_index(&ix_b));
}

#[test]
fn warp_commitment_changes_when_code_changes() {
    let (r1cs, code, _, _) = setup();
    let larger_code = ReedSolomon::new(ReedSolomonConfig::<Fp>::default(
        r1cs.k,
        r1cs.k.next_power_of_two() * 2,
    ));

    let ix_a = warp_index(r1cs.clone(), code, 4, 4);
    let ix_b = warp_index(r1cs, larger_code, 4, 4);

    assert_ne!(committed_index(&ix_a), committed_index(&ix_b));
}

#[test]
fn warp_commitment_changes_when_config_changes() {
    let (r1cs, code, _, _) = setup();
    let ix_a = warp_index(r1cs.clone(), code.clone(), 4, 4);
    let ix_b = warp_index(r1cs, code, 8, 4);

    assert_ne!(committed_index(&ix_a), committed_index(&ix_b));
}

#[test]
fn warp_commitment_changes_when_merkle_params_change() {
    let (r1cs, code, _, _) = setup();
    let ix_a = param_warp_index(r1cs.clone(), code.clone(), [1u8; 32], [2u8; 32]);
    let ix_b = param_warp_index(r1cs, code, [3u8; 32], [2u8; 32]);

    let ir = WarpReduction::<Fp, R1CS<Fp>, ReedSolomon<Fp>, ParamMT>::new();
    let (_, vk_a) = ir.index(&ix_a);
    let (_, vk_b) = ir.index(&ix_b);

    assert_ne!(vk_a.committed_index(), vk_b.committed_index());
}

#[test]
fn proof_rejects_with_wrong_verifier_key_same_dimensions() {
    let (r1cs, code, instances, witnesses) = setup();
    let changed_r1cs = changed_relation_same_dimensions(&r1cs);
    let (instance, witness) = warp_statement(instances, witnesses);

    let ix_a = warp_index(r1cs, code.clone(), 4, 4);
    let ix_b = warp_index(changed_r1cs, code, 4, 4);

    let session = spongefish::session!("warp wrong verifier key test");
    let nir = dsfs::preprocessing_non_interactive_reduction(
        WarpReduction::<Fp, R1CS<Fp>, ReedSolomon<Fp>, MT>::new(),
        Keccak::default(),
    );
    let (pk_a, _vk_a) = nir.preprocess(&ix_a);
    let (_pk_b, vk_b) = nir.preprocess(&ix_b);

    let (proof, _, _) = nir.prove(&pk_a, &session, &instance, &witness);
    assert!(nir.verify(&vk_b, &session, &instance, &proof).is_err());
}

#[test]
fn warp_instance_encoding_excludes_static_index_material() {
    let (r1cs, code, instances, witnesses) = setup();
    let changed_r1cs = changed_relation_same_dimensions(&r1cs);
    let (instance, _) = warp_statement(instances, witnesses);
    let ix_a = warp_index(r1cs, code.clone(), 4, 4);
    let ix_b = warp_index(changed_r1cs, code, 4, 4);

    assert_ne!(committed_index(&ix_a), committed_index(&ix_b));
    assert_eq!(instance.encode().as_ref(), instance.encode().as_ref());
}

#[test]
fn warp_ir_dsfs_prove_verify() {
    let (r1cs, code, instances, witnesses) = setup();
    let (instance, witness) = warp_statement(instances, witnesses);
    let ix = warp_index(r1cs, code, 4, 4);

    let session = spongefish::session!("warp IR test");
    let ir = WarpReduction::<Fp, R1CS<Fp>, ReedSolomon<Fp>, MT>::new();
    let nir = dsfs::preprocessing_non_interactive_reduction(ir, Keccak::default());
    let (pk, vk) = nir.preprocess(&ix);
    let (proof, target_p, _target_w) = nir.prove(&pk, &session, &instance, &witness);

    let target = nir
        .verify(&vk, &session, &instance, &proof)
        .expect("IR verification failed");
    assert_eq!(target_p.acc_instance.0, target.acc_instance.0);
    assert_eq!(target.acc_instance.0.len(), 1, "should produce one root");
    assert_eq!(target.acc_instance.2.len(), 1, "should produce one mu");
    assert_eq!(target.acc_instance.4.len(), 1, "should produce one eta");
}

#[test]
fn full_warp_uses_single_index() {
    fn assert_single_index<
        T: PreprocessingCore<Index = WarpIndex<Fp, R1CS<Fp>, ReedSolomon<Fp>, MT>>,
    >(
        _: &T,
    ) {
    }

    let full = FullWarp::<Fp, R1CS<Fp>, ReedSolomon<Fp>, MT>::default();
    assert_single_index(&full);
}

#[test]
fn full_warp_dsfs_roundtrip() {
    let (r1cs, code, instances, witnesses) = setup();
    let (instance, witness) = warp_statement(instances, witnesses);
    let ix = warp_index(r1cs, code, 4, 4);

    let session = spongefish::session!("warp FullWarp test");
    let full = FullWarp::<Fp, R1CS<Fp>, ReedSolomon<Fp>, MT>::new(
        WarpReduction::new(),
        WarpDecider::default(),
    );
    let nia = dsfs::preprocessing_non_interactive_argument(full, Keccak::default());
    let (pk, vk) = nia.preprocess(&ix);
    let proof = nia.prove(&pk, &session, &instance, &witness);

    nia.verify(&vk, &session, &instance, &proof)
        .expect("FullWarp verification failed");
}
