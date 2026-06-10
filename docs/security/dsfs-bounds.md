# DSFS Bounds

The DSFS backend evaluates NARG security from an instance-aware
`SecurityProfile` plus sponge parameters.

For arguments, use one of:

```rust,ignore
dsfs::security_for_concrete_instance(&argument, &instance);
dsfs::security_for_instance_bound(&argument, &bound);
```

For reductions, use one of:

```rust,ignore
dsfs::reduction_security_for_source_instance(&reduction, &source_instance);
dsfs::reduction_security_for_source_bound(&reduction, &source_bound);
```

Custom-sponge variants end in `_with` and take explicit `SpongeParams`.

## Which Helper to Use

Use a concrete-instance helper when the statement is known and you want the
profile for exactly that statement.

Use a bound helper when a caller wants a worst-case guarantee over a family, or
when composition has produced only a target-instance bound.

## Sponge Parameters

`STD_SPONGE_PARAMS` describes the Argus standard Keccak DSFS transcript.

Use `STD_HASH_SPONGE_PARAMS` only for explicit `StdHash` compatibility paths,
such as matching external spongefish or `sigma-proofs` layouts.

Changing sponge parameters is a transcript-level change. Review protocol id and
domain-separation requirements before doing it.
