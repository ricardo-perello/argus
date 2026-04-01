# DSFS v2: Keccak Transcript, Optional Salt, and Sponge Parameters

## What changed

DSFS v2 keeps the IA abstraction unchanged and updates only the DSFS compiler layer so transcript behavior is explicit, deterministic, and centralized.

The three concrete changes are:

1. Use **Keccak** (not `StdHash = Shake128`) for transcript state in DSFS channels.
2. Support transcript salt via a **const generic salt length** with a default no-salt API.
3. Provide a **compiling sponge-parameter helper** derived from duplex sponge const parameters.

## Keccak transcript instantiation

Previously, DSFS used:

- `domsep.std_prover()`
- `domsep.std_verifier(proof)`

Those constructors use `StdHash` (Shake128).  
In v2, DSFS uses domain-separator generic constructors with explicit Keccak:

- `domsep.to_prover(Keccak::default())`
- `domsep.to_verifier(Keccak::default(), proof)`

Where:

- `type Keccak = spongefish::instantiations::Keccak`
- `Keccak = DuplexSponge<KeccakF1600, 200, 136>`

This change is applied to both IA (`prove`/`verify`) and IR (`prove_reduction`/`verify_reduction`) DSFS entry points.

## Salt handling model

v2 introduces explicit salted variants:

- `prove_with_salt::<IA, SALT_LEN>(...)`
- `verify_with_salt::<IA, SALT_LEN>(...)`
- `prove_reduction_with_salt::<IR, SALT_LEN>(...)`
- `verify_reduction_with_salt::<IR, SALT_LEN>(...)`

Salt flow:

1. DSFS allocates `let mut salt = [0u8; SALT_LEN];`
2. Fills it from prover RNG (`rng().fill_bytes(&mut salt)`).
3. Absorbs it with `prover_message(&salt)` **before** calling `IA::prove` / `IR::prove`.
4. Verifier reads and absorbs exactly the same salt via `prover_message::<[u8; SALT_LEN]>()` before `IA::verify` / `IR::verify`.

This ensures salt is part of the explicit transcript and replayed deterministically.

### Default behavior (no extra generic needed)

Rust does not allow default const generics on free functions on stable.  
So v2 provides default wrappers that keep call sites simple:

- `prove::<IA>(...)` delegates to `prove_with_salt::<IA, 0>(...)`
- `verify::<IA>(...)` delegates to `verify_with_salt::<IA, 0>(...)`
- `prove_reduction::<IR>(...)` delegates to `prove_reduction_with_salt::<IR, 0>(...)`
- `verify_reduction::<IR>(...)` delegates to `verify_reduction_with_salt::<IR, 0>(...)`

So users can keep writing `dsfs::prove::<MyIA>(...)` and only use `*_with_salt` when needed.

## Sponge parameters (extension trait)

v2 exposes `DuplexSpongeParamsExt` on spongefish’s `DuplexSponge<P, WIDTH, RATE>`:

```rust
pub trait DuplexSpongeParamsExt {
    fn sponge_params(&self) -> SpongeParams;
}
```

Implemented for all `DuplexSponge<P, WIDTH, RATE>` with `P: Permutation<WIDTH>`.  
For example: `Keccak::default().sponge_params()`.

It returns:

- `alphabet_size = 256.0`
- `capacity = (WIDTH - RATE) as u64`
- `rate = RATE as u64`
- `delta = 1`

This replaces the earlier free-function shape that did not compile with correct const generics.

## Security parameter defaults

`STD_SPONGE_PARAMS` now reflects Keccak transcript parameters in DSFS:

- `capacity = 64`
- `rate = 136`
- `alphabet_size = 256.0`
- `delta = 1`

## Modular sponge (Keccak vs StdHash)

DSFS channels and compile entry points are generic over a byte-oriented duplex sponge `H` (see `ByteDuplexSponge` in `dsfs::compile`).

- **Default:** existing `prove` / `verify` / `prove_reduction` / `verify_reduction` (and `*_with_salt`) still use **Keccak** (`Keccak::default()`).
- **Explicit sponge:** use `prove_with_sponge`, `prove_with_sponge_and_salt`, `verify_with_sponge`, `verify_with_sponge_and_salt`, and the reduction variants, passing e.g. `dsfs::StdHash::default()` for spongefish **std_prover** / **std_verifier** (SHAKE128) compatibility.

Security bookkeeping: `STD_SPONGE_PARAMS` remains tied to Keccak; for StdHash-style transcripts use `STD_HASH_SPONGE_PARAMS` with `NargSecurity::for_ia_with` / `for_reduction_with`.

The `sigma-bridge` crate provides Nizk-layout batchable/compact drivers and σ-proofs–compatible `derive_session_id`.

## What did not change

Core IA protocol traits are unchanged relative to DSFS v1:

- `InteractiveArgument`, `InteractiveReduction`
- `ProtocolSecurity` and security metadata APIs in `ia-core`

(Note: separate `Prove<P>`/`Verify<V>` and `ReduceProve<P>`/`ReduceVerify<V>` traits were later collapsed into generic methods on `InteractiveArgument`/`InteractiveReduction` in the v5 interface — see `iarg-interface-v5.md`.)

**Channel tweak:** `ProverChannel::send_prover_message` now requires `NargSerialize` (in addition to `Encoding`), matching spongefish `prover_message`. Live-channel and sponge adapters were updated accordingly.

In other words: IA defines protocol logic; DSFS still exclusively owns transcript/sponge behavior.
