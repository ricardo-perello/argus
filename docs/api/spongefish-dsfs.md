# `spongefish-dsfs`

`spongefish-dsfs` is the DSFS compiler backend used by Argus. It compiles
interactive arguments and reductions into non-interactive proof artifacts while
owning all transcript mechanics.

## Plain Arguments

```rust
let nia = spongefish_dsfs::plain_non_interactive_argument(
    argument,
    spongefish_dsfs::Keccak::default(),
);

let proof = nia.prove(&session, &instance, &witness);
nia.verify(&session, &instance, &proof)?;
```

The returned value implements `ia_core::NonInteractiveArgument`.

Use `plain_non_interactive_argument_with_salt` when the proof layout includes an
explicit prover salt.

## Plain Reductions

```rust
let nir = spongefish_dsfs::plain_non_interactive_reduction(
    reduction,
    spongefish_dsfs::Keccak::default(),
);

let (proof, target_instance, target_witness) =
    nir.prove(&session, &source_instance, &source_witness);

let verified_target =
    nir.verify(&session, &source_instance, &proof)?;
```

The returned value implements `ia_core::NonInteractiveReduction`.

## Preprocessing

Preprocessing wrappers store the protocol body and sponge configuration, but no
keys:

```rust
let pnia = spongefish_dsfs::preprocessing_non_interactive_argument(
    preprocessing_argument,
    spongefish_dsfs::Keccak::default(),
);

let (pk, vk) = pnia.preprocess(&index);
let proof = pnia.prove(&pk, &session, &instance, &witness);
pnia.verify(&vk, &session, &instance, &proof)?;
```

Reductions use the same pattern:

```rust
let pnir = spongefish_dsfs::preprocessing_non_interactive_reduction(
    preprocessing_reduction,
    spongefish_dsfs::Keccak::default(),
);

let (pk, vk) = pnir.preprocess(&index);
let (proof, target, target_witness) =
    pnir.prove(&pk, &session, &source_instance, &source_witness);
let verified_target = pnir.verify(&vk, &session, &source_instance, &proof)?;
```

Internally the backend derives `pk.committed_index()` on the prover side and
`vk.committed_index()` on the verifier side. It absorbs those bytes paired with
the ordinary instance before the first verifier challenge, then calls keyed
protocol execution with the bare instance.

## Sponge Choice

The Argus standard DSFS path uses `Keccak`.

`StdHash` is available for explicit compatibility paths. Treat sponge choice as
part of the compiled proof format: changing it requires reviewing protocol id,
domain separation, and test vectors.

## Security Helpers

Argument helpers:

- `security_for_concrete_instance`
- `security_for_instance_bound`
- `security_for_concrete_instance_with`
- `security_for_instance_bound_with`

Reduction helpers:

- `reduction_security_for_source_instance`
- `reduction_security_for_source_bound`
- `reduction_security_for_source_instance_with`
- `reduction_security_for_source_bound_with`

The `_with` variants take explicit `SpongeParams`.

## Transcript Ownership

DSFS owns public-input absorption, prover-message absorption, challenge
derivation, proof byte serialization, deterministic replay, and malformed-proof
rejection. Protocol code should not duplicate any of that logic.
