# Security Overview

Argus tracks two related things:

- how a protocol is executed,
- what formal error profile is associated with that execution.

Execution lives in the protocol and backend traits. Security metadata lives in
`ArgumentSecurity`, `ReductionSecurity`, `SecurityProfile`, and DSFS helper
functions.

## Security Profiles

A `SecurityProfile` contains:

- plain soundness error,
- per-round RBR soundness errors,
- per-round RBR knowledge soundness errors,
- HVZK error,
- verifier challenge lengths.

The profile is not global to a protocol object. It is evaluated for either a
concrete instance or an explicit worst-case instance-family bound.

## Why Instance-Aware

For many protocols, the per-round soundness error depends on instance-derived
parameters: number of variables, code length, field size, number of constraints,
list-size bounds, or protocol-specific degree bounds.

That is why the API asks for:

- a profile from concrete instance parameters,
- a profile from an explicit worst-case bound.

Constant-error protocols can use `()` for both parameter and bound types.

## DSFS Bounds

The DSFS backend converts the interactive profile into NARG security bounds by
combining:

- SR soundness or SR knowledge soundness derived from the RBR vector,
- sponge parameters,
- challenge lengths,
- adversarial query budget.

See [DSFS Bounds](dsfs-bounds.md).
