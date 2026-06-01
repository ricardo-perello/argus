# `spongefish::dsfs`

`spongefish::dsfs` is the DSFS compiler backend used by Argus. It compiles the
same IA/IR channel programs into non-interactive proof artifacts.

The public API now uses semantic constructors: the call names the
non-interactive object being constructed.

## Arguments

```rust
let nia = spongefish_dsfs::plain_non_interactive_argument(
    argument,
    spongefish_dsfs::Keccak::default(),
);

let proof = nia.prove(&session, &instance, &witness);
nia.verify(&session, &instance, &proof)?;
```

The concrete wrapper is `DsfsArgument<IA, S, DS, SALT_LEN>`, but most callers
interact with it through `ia_core::NonInteractiveArgument`.

Use `plain_non_interactive_argument_with_salt` when the proof layout includes an
explicit prover salt.

## Reductions

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

The concrete wrapper is `DsfsReduction<IR, S, DS, SALT_LEN>`.

## Preprocessing Arguments and Reductions

For preprocessing cores, construct the stateless DSFS wrapper, run preprocessing
to obtain keys, and pass the relevant key into each call:

```rust
let nia = spongefish_dsfs::preprocessing_non_interactive_argument(
    preprocessing_argument,
    spongefish_dsfs::Keccak::default(),
);

let (pk, vk) = nia.preprocess(&index);
let proof = nia.prove(&pk, &session, &instance, &witness);
nia.verify(&vk, &session, &instance, &proof)?;

let nir = spongefish_dsfs::preprocessing_non_interactive_reduction(
    preprocessing_reduction,
    spongefish_dsfs::Keccak::default(),
);

let (pk, vk) = nir.preprocess(&index);
let (proof, target, target_witness) =
    nir.prove(&pk, &session, &source_instance, &source_witness);
let verified_target = nir.verify(&vk, &session, &source_instance, &proof)?;
```

The second constructor parameter is named `duplex_sponge` in the API; the
corresponding type parameter is `DS`.

Preprocessing wrappers store the protocol body and sponge, but no keys. They
accept bare per-claim instances. Internally the backend derives
`pk.committed_index()` on the prover side and `vk.committed_index()` on the
verifier side, then absorbs:

```text
IndexedInstanceRef { committed_index, instance }
```

before any verifier challenge is squeezed, then calls keyed protocol execution:

```text
prove(ch, pk, instance, witness)
verify(ch, vk, instance)
```

Applications that persist preprocessing keys pass those keys directly to
`prove` and `verify`; no wrapper stores keys.

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

DSFS owns transcript mechanics. It must absorb public inputs before the first
challenge, absorb prover messages before challenge derivation, replay
deterministically, and reject malformed proof byte streams.

Plain protocols absorb the ordinary instance. Preprocessing protocols absorb
the committed index plus the ordinary instance. Protocol code never performs
either absorption itself.

See [Transcript Invariants](../security/transcript-invariants.md).
