# Argus Documentation

Argus gives protocol authors a clean Rust interface for public-coin interactive
arguments and reductions.

The motivation is simple: transcript libraries can already build
Fiat-Shamir proofs, but without a protocol interface the prover and verifier
often describe the transcript imperatively. Sponge calls, challenge derivation,
and proof layout become entangled with the mathematical protocol. That is the
right level of abstraction for a transcript backend. It is not the right level
for a reusable IA or IR.

Argus separates those jobs. A protocol family is written as native prover and
verifier channel programs: the prover sends messages and reads public coins;
the verifier reads messages and sends public coins. A backend gives those
operations concrete meaning.

```text
prover role + verifier role
    |
    v
ia-core channels
    |
    +-- spongefish-dsfs -> non-interactive proof
    |
    +-- live-channel    -> interactive execution
    |
    +-- future compiler target, such as IOP + commitment -> IA
```

This makes the IA layer useful in both directions. Its roles can be consumed by
DSFS, run directly as an interactive protocol, or serve as the output interface
for a future compiler that lowers a richer formalism into an interactive
argument.

## Where To Start

- [Getting Started](getting-started.md): commands and the shortest runnable path.
- [Architecture Overview](architecture/overview.md): the main design story.
- [Channel Model](architecture/channel-model.md): what protocol code may and may
  not do.
- [Author Guide](author-guide/overview.md): how to write protocols.
- [Transcript Invariants](security/transcript-invariants.md): rules for backend
  and transcript changes.
- [Final Report](final-report.md): point-in-time academic project report.

## Project Shape

Argus covers a matrix of protocol shapes:

- argument or reduction,
- interactive or non-interactive,
- plain or preprocessing.

The Rust API uses capability-specific traits instead of one maximal protocol
type. A plain interactive argument cannot accidentally call preprocessing APIs,
while preprocessing protocols still share the same channel machinery and
composition model.
