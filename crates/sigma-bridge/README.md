# sigma-bridge

Nizk-style **batchable** and **compact** Fiat–Shamir drivers matching the σ-proofs [`fiat_shamir`](https://github.com/sigma-rs/sigma-proofs/blob/main/src/fiat_shamir.rs) transcript (public commitment absorb, challenge squeeze, response serialization).

- Use [`derive_session_id`](./src/session.rs) for the same 64-byte session field as σ-proofs `Nizk`.
- Use [`dsfs::StdHash`](https://github.com/arkworks-rs/spongefish) with these APIs for transcript compatibility with spongefish `std_prover` / `std_verifier`.

## Spongefish / σ-proofs versions

The published `sigma-proofs` crate depends on **spongefish 0.4**; Argus pins **spongefish 1.x** from git. Cargo cannot link both in one crate, so this crate defines a minimal [`SigmaProtocol`](./src/traits.rs) trait aligned with σ-proofs. When σ-proofs upgrades to the same spongefish as Argus, you can `impl` that upstream trait for wrapper types or depend on σ-proofs directly and delete the local trait.

## Golden vectors vs `Nizk`

Byte-identical proofs vs `Nizk::prove_batchable` / `prove_compact` should be checked **after** spongefish versions unify, or by generating vectors from σ-proofs in a separate binary locked to spongefish 0.4. The unit tests here use a toy `u32` protocol to regression-test round-trip behavior for both [`StdHash`](./src/fiat_shamir.rs) and Keccak.
