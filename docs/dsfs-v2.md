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

## Sponge parameters helper

v2 adds a compiling helper:

```rust
pub fn sponge_params_from_duplex_sponge<
    P: Permutation<WIDTH>,
    const WIDTH: usize,
    const RATE: usize,
>() -> SpongeParams
```

It returns:

- `alphabet_size = 256.0`
- `capacity = (WIDTH - RATE) as u64`
- `rate = RATE as u64`
- `delta = 1`

This replaces the previous non-compiling shape that used incorrect const-generic types/signatures.

## Security parameter defaults

`STD_SPONGE_PARAMS` now reflects Keccak transcript parameters in DSFS:

- `capacity = 64`
- `rate = 136`
- `alphabet_size = 256.0`
- `delta = 1`

## What did not change

No IA-layer trait/interface changes were made:

- `InteractiveArgument`, `Prove`, `Verify`
- `InteractiveReduction`, `ReduceProve`, `ReduceVerify`
- IA security metadata APIs in `ia-core`

In other words: IA defines protocol logic; DSFS still exclusively owns transcript/sponge behavior.
