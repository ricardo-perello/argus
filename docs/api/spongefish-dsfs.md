# `spongefish::dsfs`

`spongefish::dsfs` is the DSFS compiler backend used by Argus.

It compiles the same IA/IR channel programs into non-interactive proof artifacts.

## Arguments

```rust
let proof = spongefish::dsfs::prove(&argument, session, &instance, &witness);
spongefish::dsfs::verify(&argument, session, &instance, proof.as_bytes())?;
```

Salted and custom-sponge variants are available when the transcript format
requires them.

## Reductions

```rust
let (target_instance, target_witness, proof) =
    spongefish::dsfs::prove_reduction(&reduction, session, &source_instance, &source_witness);

let target_instance =
    spongefish::dsfs::verify_reduction(&reduction, session, &source_instance, proof.as_bytes())?;
```

## Security Helpers

Argument helpers:

- `security_for_concrete_instance`,
- `security_for_instance_bound`,
- `security_for_concrete_instance_with`,
- `security_for_instance_bound_with`.

Reduction helpers:

- `reduction_security_for_source_instance`,
- `reduction_security_for_source_bound`,
- `reduction_security_for_source_instance_with`,
- `reduction_security_for_source_bound_with`.

The `_with` variants take explicit `SpongeParams`.

## Transcript Ownership

DSFS owns transcript mechanics. It must absorb public inputs before the first
challenge, absorb prover messages before challenge derivation, replay
deterministically, and reject malformed proof byte streams.

See [Transcript Invariants](../security/transcript-invariants.md).
