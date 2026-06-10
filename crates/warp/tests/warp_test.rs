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

use ia_core::prelude::*;
use ia_core::{
    CommittedIndex, Encoding, Indexer, NargProof, PreprocessingArgumentSecurity,
    PreprocessingReductionSecurity, SecurityErrorBound,
};
use spongefish_dsfs::{self as dsfs, Keccak, NargSecurity, STD_SPONGE_PARAMS};
use warp::{
    config::WarpConfig,
    crypto::merkle::{blake3::Blake3MerkleTreeParams, parameters::MerkleTreeParams},
    errors::WARPError,
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
    FullWarpIndexer, FullWarpProver, FullWarpVerifier, WarpDeciderIndexer, WarpIndex, WarpInstance,
    WarpMerkleParams, WarpReductionIndexer, WarpReductionProver, WarpReductionVerifier,
    WarpWitness,
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

#[allow(clippy::type_complexity)]
fn deterministic_setup() -> (R1CS<Fp>, ReedSolomon<Fp>, Vec<Vec<Fp>>, Vec<Vec<Fp>>) {
    let hash_chain_size = 10;
    let poseidon_config = poseidon::initialize_poseidon_config::<Fp>();
    let l1 = 4;

    let r1cs = HashChainRelation::<Fp, CRH<_>, CRHGadget<_>>::into_r1cs(&(
        poseidon_config.clone(),
        hash_chain_size,
    ))
    .unwrap();
    let code_config = ReedSolomonConfig::<Fp>::default(r1cs.k, r1cs.k.next_power_of_two());
    let code = ReedSolomon::new(code_config);

    let (instances, witnesses): (Vec<Vec<Fp>>, Vec<Vec<Fp>>) = (1..=l1)
        .map(|value| {
            let preimage = vec![Fp::from(value as u64)];
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
    let indexer = WarpReductionIndexer::<Fp, R1CS<Fp>, ReedSolomon<Fp>, MT>::new();
    let (pk, vk) = indexer.preprocess(ix);
    assert_eq!(pk.committed_index(), vk.committed_index());
    vk.committed_index().as_bytes().to_vec()
}

#[test]
fn warp_security_profile_is_derived_from_index() {
    let (r1cs, code, instances, _) = setup();
    let (small_instance, _) = warp_statement(instances.clone(), vec![]);
    let (large_instance, _) = warp_statement(instances, vec![]);

    let ix_small = warp_index(r1cs.clone(), code.clone(), 4, 4);
    let ix_large = warp_index(r1cs, code, 8, 4);

    let indexer = WarpReductionIndexer::<Fp, R1CS<Fp>, ReedSolomon<Fp>, MT>::new();
    let small_profile = indexer.profile_for_concrete_source(&ix_small, &small_instance);
    let large_profile = indexer.profile_for_concrete_source(&ix_large, &large_instance);

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
fn warp_commitment_matches_golden_bytes() {
    let (r1cs, code, _, _) = deterministic_setup();
    let ix = warp_index(r1cs, code, 4, 4);

    assert_eq!(
        committed_index(&ix),
        vec![
            97, 114, 103, 117, 115, 58, 119, 97, 114, 112, 58, 118, 107, 58, 118, 49, 151, 204,
            105, 107, 74, 8, 252, 4, 93, 139, 224, 11, 229, 126, 113, 186, 63, 29, 5, 59, 72, 48,
            24, 138, 206, 66, 78, 128, 98, 168, 4, 198,
        ]
    );
}

#[test]
fn r1cs_description_is_stable_and_constraint_sensitive() {
    let (r1cs, _, _, _) = deterministic_setup();
    let changed = changed_relation_same_dimensions(&r1cs);

    assert_eq!(r1cs.description(), r1cs.clone().description());
    assert_ne!(r1cs.description(), changed.description());
}

#[test]
fn r1cs_reports_malformed_evaluation_inputs() {
    let (r1cs, _, _, _) = deterministic_setup();

    assert!(matches!(
        r1cs.eval_p_i(&[], 0),
        Err(WARPError::R1CSWitnessSize(0, _))
    ));
    assert!(matches!(
        r1cs.evaluate_bundled(&[], &vec![Fp::from(0u64); r1cs.n]),
        Err(WARPError::ZeroEvaderSize(0, 0))
    ));
}

#[test]
fn warp_commitment_changes_when_constraints_change() {
    let (r1cs, code, _, _) = setup();
    let changed_r1cs = changed_relation_same_dimensions(&r1cs);

    let ix_a = warp_index(r1cs, code.clone(), 4, 4);
    let ix_b = warp_index(changed_r1cs, code, 4, 4);

    assert_ne!(committed_index(&ix_a), committed_index(&ix_b));
}

// --- Offline index-binding error (CY24 §32.7 COS, §32.8.1) ------------------

#[test]
fn warp_reduction_offline_binding_is_zero_while_nonsuccinct() {
    // WARP's verifier holds the full index material (non-succinct): there is no
    // committed index a prover can equivocate, and the absorbed index digest is
    // pure FS domain separation (not load-bearing). So the offline binding error
    // is zero. The (t+2*l0)^2/2^257 + t^2/2^257 term (CY24 §32.8.1) activates
    // only once WARP has a succinct/holographic verifier index.
    let (r1cs, code, _, _) = setup();
    let ix = warp_index(r1cs, code, 4, 4);
    let indexer = WarpReductionIndexer::<Fp, R1CS<Fp>, ReedSolomon<Fp>, MT>::new();
    let offline = indexer.offline_binding_error(&indexer.index_security_params(&ix));
    for &t in &[0u64, 1 << 20, 1 << 40] {
        assert_eq!(offline.evaluate(t), 0.0);
    }
}

#[test]
fn warp_decider_has_no_offline_binding() {
    // The decider holds the full verifier key and runs a deterministic local
    // check: no index commitment for a prover to equivocate.
    let indexer = WarpDeciderIndexer::<Fp, R1CS<Fp>, ReedSolomon<Fp>, MT>::default();
    let offline = indexer.offline_binding_error(&());
    for &t in &[0u64, 1 << 20, 1 << 40] {
        assert_eq!(offline.evaluate(t), 0.0);
    }
}

#[test]
fn warp_decider_keys_share_the_same_commitment() {
    let (r1cs, code, _, _) = setup();
    let ix = warp_index(r1cs, code, 4, 4);
    let indexer = WarpDeciderIndexer::<Fp, R1CS<Fp>, ReedSolomon<Fp>, MT>::default();
    let (pk, vk) = indexer.preprocess(&ix);
    assert_eq!(pk.committed_index(), vk.committed_index());
}

#[test]
fn offline_binding_convention_adds_to_soundness_and_knowledge_not_zk() {
    // Documents the NARG combination convention (CY24 §32.8.1–§32.8.4): an
    // offline binding term is added once to soundness and knowledge, never to
    // ZK. WARP's current term is zero (non-succinct verifier), so we use a
    // synthetic succinct-verifier term to exercise the convention.
    let (r1cs, code, instances, _) = setup();
    let (instance, _) = warp_statement(instances, vec![]);
    let ix = warp_index(r1cs, code, 4, 4);
    let indexer = WarpReductionIndexer::<Fp, R1CS<Fp>, ReedSolomon<Fp>, MT>::new();
    let profile = indexer.profile_for_concrete_source(&ix, &instance);

    let narg = NargSecurity {
        ia: profile,
        sponge: STD_SPONGE_PARAMS,
    };

    // Synthetic succinct-index term: (t + 2*l0)^2 / 2^257 + t^2 / 2^257.
    let l0 = 1u64 << 4; // illustrative encoded-index length
    let offline = SecurityErrorBound::new(move |t| {
        let (t, l0) = (t as f64, l0 as f64);
        ((t + 2.0 * l0).powi(2) + t * t) * 2f64.powi(-257)
    });

    let t = 1u64 << 30;
    let off = offline.evaluate(t);
    assert!(off > 0.0);

    let final_soundness = narg.soundness_error(t) + off;
    let final_knowledge = narg.knowledge_soundness_error(t) + off;
    assert!((final_soundness - narg.soundness_error(t) - off).abs() <= off * 1e-9);
    assert!((final_knowledge - narg.knowledge_soundness_error(t) - off).abs() <= off * 1e-9);
    // The offline term is never added to ZK (structural: it is simply not part
    // of the zk_error accounting, which depends only on the sponge and hvzk).
    let _zk = narg.zk_error(t);
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

    let indexer = WarpReductionIndexer::<Fp, R1CS<Fp>, ReedSolomon<Fp>, ParamMT>::new();
    let (_, vk_a) = indexer.preprocess(&ix_a);
    let (_, vk_b) = indexer.preprocess(&ix_b);

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
    let indexer = WarpReductionIndexer::<Fp, R1CS<Fp>, ReedSolomon<Fp>, MT>::new();
    let prover = dsfs::preprocessing_non_interactive_reduction_prover(
        WarpReductionProver::<Fp, R1CS<Fp>, ReedSolomon<Fp>, MT>::default(),
        Keccak::default(),
    );
    let verifier = dsfs::preprocessing_non_interactive_reduction_verifier(
        WarpReductionVerifier::<Fp, R1CS<Fp>, ReedSolomon<Fp>, MT>::default(),
        Keccak::default(),
    );
    let (pk_a, _vk_a) = indexer.preprocess(&ix_a);
    let (_pk_b, vk_b) = indexer.preprocess(&ix_b);

    let (proof, _, _) = prover.prove(&pk_a, &session, &instance, &witness);
    assert!(verifier.verify(&vk_b, &session, &instance, &proof).is_err());
}

#[test]
fn proof_rejects_with_wrong_source_instance_same_index() {
    // A proof generated against one WarpInstance must not verify against a
    // *different* source instance under the same index/verifier key.
    //
    // `WarpReductionVerifier::verify` ignores its `instance` argument and reconstructs
    // the source claims from prover messages, so this binding does NOT come from
    // the reduction's verify logic. It comes from the DSFS layer absorbing
    // `WarpInstance::encode()` as public input before the first challenge: a
    // different source instance yields different Fiat-Shamir challenges, which
    // makes the prover's sumcheck messages fail to verify.
    let (r1cs, code, instances_a, witnesses_a) = setup();
    // `setup()` derives r1cs/code deterministically but samples fresh random
    // instances, so this is the same index with a different source instance.
    let (_, _, instances_b, _) = setup();
    assert_ne!(instances_a, instances_b, "source instances must differ");

    let (instance_a, witness_a) = warp_statement(instances_a, witnesses_a);
    let (instance_b, _) = warp_statement(instances_b, vec![]);
    let ix = warp_index(r1cs, code, 4, 4);

    let session = spongefish::session!("warp wrong source instance test");
    let indexer = WarpReductionIndexer::<Fp, R1CS<Fp>, ReedSolomon<Fp>, MT>::new();
    let prover = dsfs::preprocessing_non_interactive_reduction_prover(
        WarpReductionProver::<Fp, R1CS<Fp>, ReedSolomon<Fp>, MT>::default(),
        Keccak::default(),
    );
    let verifier = dsfs::preprocessing_non_interactive_reduction_verifier(
        WarpReductionVerifier::<Fp, R1CS<Fp>, ReedSolomon<Fp>, MT>::default(),
        Keccak::default(),
    );
    let (pk, vk) = indexer.preprocess(&ix);

    let (proof, _, _) = prover.prove(&pk, &session, &instance_a, &witness_a);
    assert!(
        verifier.verify(&vk, &session, &instance_b, &proof).is_err(),
        "proof for instance_a must reject when verified against instance_b",
    );
}

/// One WARP step on `instances` with empty accumulators (l2 = 0) yields a single
/// accumulator (instance + witness), produced by the honest prover.
fn build_accumulator(
    r1cs: &R1CS<Fp>,
    code: &ReedSolomon<Fp>,
    instances: Vec<Vec<Fp>>,
    witnesses: Vec<Vec<Fp>>,
) -> (AccumulatorInstances<Fp, MT>, AccumulatorWitnesses<Fp, MT>) {
    let l1 = instances.len();
    let (empty_inst, empty_wit) = empty_acc();
    let instance = WarpInstance {
        instances,
        acc_instances: empty_inst,
    };
    let witness = WarpWitness {
        witnesses,
        acc_witnesses: empty_wit,
    };
    let ix = warp_index(r1cs.clone(), code.clone(), l1, l1); // l = l1, l2 = 0
    let session = spongefish::session!("warp accumulator build");
    let indexer = WarpReductionIndexer::<Fp, R1CS<Fp>, ReedSolomon<Fp>, MT>::new();
    let prover = dsfs::preprocessing_non_interactive_reduction_prover(
        WarpReductionProver::<Fp, R1CS<Fp>, ReedSolomon<Fp>, MT>::default(),
        Keccak::default(),
    );
    let (pk, _vk) = indexer.preprocess(&ix);
    let (_proof, target, target_w) = prover.prove(&pk, &session, &instance, &witness);
    (target.acc_instance, target_w)
}

fn concat_acc_instances(
    a: AccumulatorInstances<Fp, MT>,
    b: AccumulatorInstances<Fp, MT>,
) -> AccumulatorInstances<Fp, MT> {
    let (mut ar, mut aa, mut am, (mut at, mut ax), mut ae) = a;
    let (br, ba, bm, (bt, bx), be) = b;
    ar.extend(br);
    aa.extend(ba);
    am.extend(bm);
    at.extend(bt);
    ax.extend(bx);
    ae.extend(be);
    (ar, aa, am, (at, ax), ae)
}

fn concat_acc_witnesses(
    a: AccumulatorWitnesses<Fp, MT>,
    b: AccumulatorWitnesses<Fp, MT>,
) -> AccumulatorWitnesses<Fp, MT> {
    let (mut at, mut ac, mut aw) = a;
    let (bt, bc, bw) = b;
    at.extend(bt);
    ac.extend(bc);
    aw.extend(bw);
    (at, ac, aw)
}

#[test]
fn warp_reduction_accumulation_l2_nonzero() {
    // Exercises the accumulation path (l2 > 0): the verifier sources the
    // accumulators from `instance.acc_instances` (the change under test) rather
    // than the channel. Build two accumulators from two l2 = 0 steps, fold them
    // in a final l = 4, l1 = 2, l2 = 2 step.
    let (r1cs, code, insts, wits) = setup();
    let acc_a = build_accumulator(&r1cs, &code, insts[0..2].to_vec(), wits[0..2].to_vec());
    let acc_b = build_accumulator(&r1cs, &code, insts[2..4].to_vec(), wits[2..4].to_vec());

    let (_, _, insts2, wits2) = setup();
    let fresh_insts = insts2[0..2].to_vec();
    let fresh_wits = wits2[0..2].to_vec();

    let acc_instances = concat_acc_instances(acc_a.0, acc_b.0);
    let acc_witnesses = concat_acc_witnesses(acc_a.1, acc_b.1);

    let instance = WarpInstance {
        instances: fresh_insts,
        acc_instances,
    };
    let witness = WarpWitness {
        witnesses: fresh_wits,
        acc_witnesses,
    };

    let ix = warp_index(r1cs, code, 4, 2); // l = 4, l1 = 2 -> l2 = 2
    let session = spongefish::session!("warp l2 accumulation test");
    let indexer = WarpReductionIndexer::<Fp, R1CS<Fp>, ReedSolomon<Fp>, MT>::new();
    let prover = dsfs::preprocessing_non_interactive_reduction_prover(
        WarpReductionProver::<Fp, R1CS<Fp>, ReedSolomon<Fp>, MT>::default(),
        Keccak::default(),
    );
    let verifier = dsfs::preprocessing_non_interactive_reduction_verifier(
        WarpReductionVerifier::<Fp, R1CS<Fp>, ReedSolomon<Fp>, MT>::default(),
        Keccak::default(),
    );
    let (pk, vk) = indexer.preprocess(&ix);
    let (proof, target_p, _) = prover.prove(&pk, &session, &instance, &witness);
    let target = verifier
        .verify(&vk, &session, &instance, &proof)
        .expect("l2 > 0 reduction verification failed");
    assert_eq!(target.acc_instance.0, target_p.acc_instance.0);
    assert_eq!(target.acc_instance.0.len(), 1, "should produce one root");
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
    let indexer = WarpReductionIndexer::<Fp, R1CS<Fp>, ReedSolomon<Fp>, MT>::new();
    let prover = dsfs::preprocessing_non_interactive_reduction_prover(
        WarpReductionProver::<Fp, R1CS<Fp>, ReedSolomon<Fp>, MT>::default(),
        Keccak::default(),
    );
    let verifier = dsfs::preprocessing_non_interactive_reduction_verifier(
        WarpReductionVerifier::<Fp, R1CS<Fp>, ReedSolomon<Fp>, MT>::default(),
        Keccak::default(),
    );
    let (pk, vk) = indexer.preprocess(&ix);
    let (proof, target_p, _target_w) = prover.prove(&pk, &session, &instance, &witness);

    let target = verifier
        .verify(&vk, &session, &instance, &proof)
        .expect("IR verification failed");
    assert_eq!(target_p.acc_instance.0, target.acc_instance.0);
    assert_eq!(target.acc_instance.0.len(), 1, "should produce one root");
    assert_eq!(target.acc_instance.2.len(), 1, "should produce one mu");
    assert_eq!(target.acc_instance.4.len(), 1, "should produce one eta");
}

#[test]
fn full_warp_uses_single_index() {
    fn assert_single_index<T: Indexer<Index = WarpIndex<Fp, R1CS<Fp>, ReedSolomon<Fp>, MT>>>(
        _: &T,
    ) {
    }

    let (r1cs, code, _, _) = setup();
    let ix = warp_index(r1cs, code, 4, 4);
    let full = FullWarpIndexer::<Fp, R1CS<Fp>, ReedSolomon<Fp>, MT>::default();
    let reduction = WarpReductionIndexer::<Fp, R1CS<Fp>, ReedSolomon<Fp>, MT>::default();
    assert_single_index(&full);

    let (full_pk, full_vk) = full.preprocess(&ix);
    let (reduction_pk, reduction_vk) = reduction.preprocess(&ix);
    assert_eq!(full_pk.committed_index(), reduction_pk.committed_index());
    assert_eq!(full_vk.committed_index(), reduction_vk.committed_index());
}

#[test]
fn full_warp_dsfs_roundtrip() {
    let (r1cs, code, instances, witnesses) = deterministic_setup();
    let (instance, witness) = warp_statement(instances, witnesses);
    let ix = warp_index(r1cs, code, 4, 4);

    let session = spongefish::session!("warp FullWarp test");
    let indexer = FullWarpIndexer::<Fp, R1CS<Fp>, ReedSolomon<Fp>, MT>::default();
    let prover = dsfs::preprocessing_non_interactive_argument_prover(
        FullWarpProver::<Fp, R1CS<Fp>, ReedSolomon<Fp>, MT>::default(),
        Keccak::default(),
    );
    let verifier = dsfs::preprocessing_non_interactive_argument_verifier(
        FullWarpVerifier::<Fp, R1CS<Fp>, ReedSolomon<Fp>, MT>::default(),
        Keccak::default(),
    );
    let (pk, vk) = indexer.preprocess(&ix);
    let proof = prover.prove(&pk, &session, &instance, &witness);

    verifier
        .verify(&vk, &session, &instance, &proof)
        .expect("FullWarp verification failed");

    assert_eq!(proof.len(), 226_848);
    assert_eq!(
        *blake3::hash(proof.as_bytes()).as_bytes(),
        [
            69, 19, 86, 146, 216, 207, 234, 1, 201, 152, 144, 131, 54, 126, 242, 38, 136, 148, 151,
            29, 245, 114, 207, 230, 122, 218, 223, 74, 36, 243, 176, 39,
        ],
    );

    let mut trailing = proof.into_bytes();
    trailing.push(0);
    assert!(
        verifier
            .verify(&vk, &session, &instance, &NargProof::from_bytes(trailing),)
            .is_err(),
        "FullWarp verifier must reject trailing proof bytes",
    );
}
