# Instance-Aware Security

Security profiles are functions of the statement being proved, or of a
worst-case family of statements.

The API separates these two cases.

## Concrete Profile

A concrete profile is used when the exact instance is known:

```text
profile_for_concrete_instance(x)
```

The implementation first extracts compact security-relevant parameters from
`x`, then builds the profile from those parameters. This is the right mode when
you want the tight-ish bound for a specific proof statement.

Examples of parameters include:

- number of variables,
- code length,
- constraint count,
- degree bound,
- number of OOD samples,
- number of query rounds.

## Bound Profile

A bound profile is used when the verifier or caller wants a worst-case family:

```text
profile_for_instance_bound(n)
```

Here `n` is not necessarily a single integer. It is any protocol-defined bound
type that covers a family of instances.

For WARP, the bound currently mirrors `WARPSecurityParams`, with fields
interpreted as maxima. For Schnorr, the bound is `()` because the tracked error
is instance-independent.

## Arguments

`ArgumentSecurity` exposes:

- `InstanceParams`: compact parameters derived from a concrete instance,
- `InstanceBound`: a worst-case family bound,
- `instance_security_params`,
- `instance_bound_for_instance_params`,
- `profile_for_instance_params`,
- `profile_for_instance_bound`,
- convenience methods for concrete instances.

The name `profile_for_concrete_instance` is intentionally explicit at call
sites: it means the profile is tied to the exact instance, not just the protocol
type.

## Reductions

`ReductionSecurity` has source params and source bounds, plus a target bound.
The target bound is what makes automatic composition possible.

A reduction can say:

```text
from this source instance or source family,
the verifier-produced target instance belongs to this target family.
```

Then the next reduction or final argument can evaluate its own security profile
from that bound.

## Constant-Error Protocols

If a protocol's tracked security does not vary with the instance, use:

```rust
type InstanceParams = ();
type InstanceBound = ();
```

The methods can ignore their arguments and return the same profile each time.
