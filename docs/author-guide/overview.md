# Author Guide

Protocol authors start from the interactive conversation, not from proof bytes.

Argus separates that conversation into native production roles:

```text
prover role
  prove(channel, instance, witness)

verifier role
  verify(channel, instance)

optional indexer role
  preprocess(index) -> (prover_key, verifier_key)
```

Each executable role is a channel program. The backend decides whether it runs
live or is compiled with DSFS:

```text
native prover/verifier roles
        |
        v
ia-core channel traits
        |
        +-- spongefish-dsfs: transcript + proof bytes
        |
        +-- live-channel: interactive messages
```

The protocol must not know whether a challenge came from a live verifier or a
sponge.

## Pick the Shape

Choose argument or reduction separately for each role:

- `InteractiveArgumentProver` / `InteractiveArgumentVerifier`: accept/reject.
- `InteractiveReductionProver` / `InteractiveReductionVerifier`: produce a
  target claim.
- preprocessing variants of those four traits: execution with one role-specific
  key.
- `Indexer`: derive matching prover and verifier keys from static index data.

There are no full prover-plus-verifier conjunction traits. A verifier type does
not expose a witness or prover key, and an indexer exposes no execution method.

The short authoring macros keep that boundary while avoiding duplicated public
shape:

```rust,ignore
ia_core::impl_interactive_argument! {
    impl {
        prover: MyProver,
        verifier: MyVerifier,
    }
    {
        /* protocol id, instance, witness, prove, verify */
    }
}
```

This emits independent role implementations; it does not create a combined
runtime object or conjunction trait. Use
`impl_interactive_argument_prover!` and
`impl_interactive_argument_verifier!` when roles require different bounds or
must be authored separately. Preprocessing has the same shared form plus
role-specific `*_indexer!`, `*_prover!`, and `*_verifier!` macros.

## Keep the Boundary Clean

Inside protocol code, use only:

```rust,ignore
channel.send_prover_message(&message);
let challenge = channel.read_verifier_message();

let message = channel.read_prover_message()?;
let challenge = channel.send_verifier_message();
```

Do not instantiate a sponge, absorb public input, squeeze a challenge, parse
proof bytes, or perform Fiat-Shamir logic in the protocol body. Those jobs belong
to the backend.

Start with [Protocol Types](protocol-types.md), then implement the Schnorr-style
roles in [First Argument](first-argument.md).
