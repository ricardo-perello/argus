use std::marker::PhantomData;

use ark_bls12_381::Fr as Fp;
use ark_codes::{
    reed_solomon::{config::ReedSolomonConfig, ReedSolomon},
    traits::LinearCode,
};
use ark_crypto_primitives::crh::poseidon::{constraints::CRHGadget, CRH};
use ark_ff::UniformRand;
use rand::thread_rng;

use warp::{
    config::WARPConfig,
    crypto::merkle::blake3::Blake3MerkleTreeParams,
    protocol::warp::WARP,
    relations::{
        r1cs::{
            hashchain::{compute_hash_chain, HashChainInstance, HashChainRelation, HashChainWitness},
            R1CS,
        },
        BundledPESAT, Relation, ToPolySystem,
    },
    types::{AccumulatorInstances, AccumulatorWitnesses},
    utils::poseidon,
};

use dsfs::{SpongeProver, SpongeVerifier};

type MT = Blake3MerkleTreeParams<Fp>;

static INSTANCE_TAG: &[u8; 16] = b"warp-test-inst00";

fn make_prover() -> SpongeProver {
    let protocol_id = spongefish::protocol_id(core::format_args!("argus::warp::test"));
    let session = spongefish::session!("warp test session");
    let domsep = spongefish::DomainSeparator::new(protocol_id)
        .session(session)
        .instance(INSTANCE_TAG);
    SpongeProver::new(domsep.std_prover())
}

fn make_verifier(narg_string: &[u8]) -> SpongeVerifier<'_> {
    let protocol_id = spongefish::protocol_id(core::format_args!("argus::warp::test"));
    let session = spongefish::session!("warp test session");
    let domsep = spongefish::DomainSeparator::new(protocol_id)
        .session(session)
        .instance(INSTANCE_TAG);
    SpongeVerifier::new(domsep.std_verifier(narg_string))
}

fn setup() -> (
    R1CS<Fp>,
    ReedSolomon<Fp>,
    Vec<Vec<Fp>>,
    Vec<Vec<Fp>>,
) {
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

#[test]
fn warp_bootstrap_prove_verify_decide() {
    let (r1cs, code, instances, witnesses) = setup();
    let l1 = instances.len();

    let warp_config = WARPConfig::new(l1, l1, 8, 7, r1cs.config(), code.code_len());
    let warp = WARP::<Fp, R1CS<Fp>, _, MT>::new(
        warp_config,
        code.clone(),
        r1cs.clone(),
        (),
        (),
    );

    let pk = (r1cs.clone(), r1cs.m, r1cs.n, r1cs.k);
    let vk = (r1cs.m, r1cs.n, r1cs.k);
    let (empty_inst, empty_wit) = empty_acc();

    // Bootstrap: prove with empty accumulator
    let mut prover_ch = make_prover();

    let (acc_x, acc_w, proof) = warp
        .prove_with_channel(
            &mut prover_ch,
            &pk,
            &instances,
            &witnesses,
            &empty_inst,
            &empty_wit,
        )
        .expect("prove failed");

    let narg_string = prover_ch.narg_string().to_vec();
    println!("NARG string: {} bytes", narg_string.len());

    // Verify
    let mut verifier_ch = make_verifier(&narg_string);

    warp.verify_with_channel(&mut verifier_ch, vk, &acc_x, &proof)
        .expect("verification failed");
    println!("Verification: OK");

    // Decide
    warp.decide(&acc_w, &acc_x).expect("decider failed");
    println!("Decider: OK");
}

#[test]
fn warp_full_accumulation_cycle() {
    let (r1cs, code, instances, witnesses) = setup();
    let l1 = instances.len();

    let warp_config = WARPConfig::new(l1, l1, 8, 7, r1cs.config(), code.code_len());
    let warp = WARP::<Fp, R1CS<Fp>, _, MT>::new(
        warp_config.clone(),
        code.clone(),
        r1cs.clone(),
        (),
        (),
    );

    let pk = (r1cs.clone(), r1cs.m, r1cs.n, r1cs.k);
    let vk = (r1cs.m, r1cs.n, r1cs.k);
    let (empty_inst, empty_wit) = empty_acc();

    // Phase 1: bootstrap l1 proofs with empty accumulator to build up state
    let mut acc_roots = vec![];
    let mut acc_alphas = vec![];
    let mut acc_mus = vec![];
    let mut acc_taus = vec![];
    let mut acc_xs = vec![];
    let mut acc_etas = vec![];
    let mut acc_tds = vec![];
    let mut acc_f = vec![];
    let mut acc_ws = vec![];

    for i in 0..l1 {
        let mut prover_ch = make_prover();
        let (acc_instance, acc_witness, _proof) = warp
            .prove_with_channel(
                &mut prover_ch,
                &pk,
                &instances,
                &witnesses,
                &empty_inst,
                &empty_wit,
            )
            .expect("bootstrap prove failed");

        acc_roots.push(acc_instance.0[0].clone());
        acc_alphas.push(acc_instance.1[0].clone());
        acc_mus.push(acc_instance.2[0]);
        acc_taus.push(acc_instance.3 .0[0].clone());
        acc_xs.push(acc_instance.3 .1[0].clone());
        acc_etas.push(acc_instance.4[0]);

        acc_tds.push(acc_witness.0.into_iter().next().unwrap());
        acc_f.push(acc_witness.1.into_iter().next().unwrap());
        acc_ws.push(acc_witness.2.into_iter().next().unwrap());

        println!("Bootstrap proof {i}: OK");
    }

    // Phase 2: full accumulation proof with both fresh + accumulated instances
    let full_acc_inst: AccumulatorInstances<Fp, MT> = (
        acc_roots,
        acc_alphas,
        acc_mus,
        (acc_taus, acc_xs),
        acc_etas,
    );
    let full_acc_wit: AccumulatorWitnesses<Fp, MT> = (acc_tds, acc_f, acc_ws);

    let l_full = 2 * l1;
    let full_config = WARPConfig::<_, R1CS<Fp>>::new(
        l_full,
        l1,
        8,
        7,
        r1cs.config(),
        code.code_len(),
    );
    let warp_full = WARP::<Fp, R1CS<Fp>, _, MT>::new(
        full_config,
        code.clone(),
        r1cs.clone(),
        (),
        (),
    );

    let mut prover_ch = make_prover();
    let (acc_x, acc_w, proof) = warp_full
        .prove_with_channel(
            &mut prover_ch,
            &pk,
            &instances,
            &witnesses,
            &full_acc_inst,
            &full_acc_wit,
        )
        .expect("full accumulation prove failed");

    let narg_string = prover_ch.narg_string().to_vec();
    println!(
        "Full accumulation NARG string: {} bytes",
        narg_string.len()
    );

    // Verify
    let mut verifier_ch = make_verifier(&narg_string);
    warp_full
        .verify_with_channel(&mut verifier_ch, vk, &acc_x, &proof)
        .expect("full accumulation verification failed");
    println!("Full accumulation verification: OK");

    // Decide
    warp_full
        .decide(&acc_w, &acc_x)
        .expect("full accumulation decider failed");
    println!("Full accumulation decider: OK");
}
