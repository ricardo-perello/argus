# Backends

Backends execute protocol channel programs.

## `spongefish::dsfs`

The DSFS backend compiles an `InteractiveArgument` into a non-interactive
argument and an `InteractiveReduction` into a non-interactive reduction.

Constructors name the compiled object:

```rust
let nia = spongefish_dsfs::non_interactive_argument(argument, sponge);
let nir = spongefish_dsfs::non_interactive_reduction(reduction, sponge);
```

For indexed bodies, the same constructors return an unprepared handle whose
`.prepare(&ix)` method stores preprocessing keys and returns a prepared
non-interactive argument or reduction.

It is responsible for:

- deriving the domain separator,
- absorbing public inputs before the first challenge,
- absorbing committed verifier-index bytes for prepared protocols,
- absorbing prover messages before challenges,
- squeezing verifier challenges,
- serializing prover messages into proof bytes,
- deterministic verifier replay,
- checking that verification consumes the expected proof bytes.

The Argus standard DSFS sponge is Keccak. `StdHash` is used only when explicitly
selected for compatibility with spongefish or `sigma-proofs` layouts.

## `live-channel`

The live backend runs prover and verifier code in separate threads using `mpsc`.
It preserves the same channel interface while using actual verifier-sampled
coins instead of Fiat-Shamir challenges.

Use it to sanity-check the interactive behavior of a protocol.

## Backend Boundary

Protocol code depends on `ia-core`, not on transcript internals. If a change
affects sponge choice, salt policy, proof layout, absorb/squeeze order, or
domain separation, it belongs in the backend layer and should be reviewed
against the transcript invariants.
