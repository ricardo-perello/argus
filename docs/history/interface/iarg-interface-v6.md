# IA v6: instance-aware security metadata

## Motivation

v5 made security metadata opt-in via `ProtocolSecurity`, but the method
`security(&self) -> SecurityProfile` only saw the protocol handle. This does not
match the soundness definitions used by CY24, CCH+19, Holmgren, or IOR-style
reductions: soundness errors are functions of a concrete false instance `x`, or
of a worst-case bound `n` obtained by maximizing over a family of instances.

v6 keeps protocol execution unchanged and makes only the security metadata API
instance-aware.

## Security traits

Arguments implement `ArgumentSecurity`:

```rust
pub trait ArgumentSecurity: InteractiveArgument {
    type InstanceParams;
    type InstanceBound;

    fn instance_security_params(&self, instance: &Self::Instance) -> Self::InstanceParams;
    fn instance_bound_for_instance_params(&self, params: &Self::InstanceParams) -> Self::InstanceBound;
    fn profile_for_instance_params(&self, params: &Self::InstanceParams) -> SecurityProfile;
    fn profile_for_instance_bound(&self, bound: &Self::InstanceBound) -> SecurityProfile;

    fn profile_for_concrete_instance(&self, instance: &Self::Instance) -> SecurityProfile { ... }
    fn instance_bound_for_concrete_instance(&self, instance: &Self::Instance) -> Self::InstanceBound { ... }
}
```

Reductions implement `ReductionSecurity`:

```rust
pub trait ReductionSecurity: InteractiveReduction {
    type SourceParams;
    type SourceBound;
    type TargetBound;

    fn source_security_params(&self, instance: &Self::SourceInstance) -> Self::SourceParams;
    fn source_bound_for_source_params(&self, params: &Self::SourceParams) -> Self::SourceBound;
    fn target_bound_for_source_params(&self, params: &Self::SourceParams) -> Self::TargetBound;
    fn target_bound_for_source_bound(&self, bound: &Self::SourceBound) -> Self::TargetBound;
    fn profile_for_source_params(&self, params: &Self::SourceParams) -> SecurityProfile;
    fn profile_for_source_bound(&self, bound: &Self::SourceBound) -> SecurityProfile;
}
```

Protocols with instance-independent security use `()` for the params and bound
types. Concrete protocols should extract small security parameter structs rather
than close over full instances inside every error term.

## Composition

RBR profiles still compose by concatenating per-round error vectors, but composed
security now threads instance bounds:

- `ChainedReduction` evaluates the first reduction on the concrete source
  params/bound, asks it for the induced target bound, then evaluates the second
  reduction on that bound.
- `ReducedArgument` does the same, using the reduction's target bound to evaluate
  the final argument.

This is deliberately bound-based for intermediate stages: the verifier-produced
target instance is transcript-dependent, so automatic composition cannot rely on
a concrete target instance before executing the protocol.

## DSFS security helpers

The DSFS security API now requires either a concrete instance or an explicit
bound:

```rust
dsfs::security_for_concrete_instance(&ia, &instance);
dsfs::security_for_instance_bound(&ia, &bound);
dsfs::reduction_security_for_source_instance(&ir, &source_instance);
dsfs::reduction_security_for_source_bound(&ir, &source_bound);
```

Custom sponge variants add `_with` and take `SpongeParams`.

## What did not change

- `InteractiveArgument` / `InteractiveReduction` execution methods.
- Channel APIs.
- DSFS transcript ordering, public input absorption, replay, or EOF checks.
- `SecurityProfile` evaluation once a concrete or bounded profile has been built.
