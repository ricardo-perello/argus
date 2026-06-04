# Backends

Backends execute Argus channel programs.

## `spongefish-dsfs`

`spongefish-dsfs` compiles interactive arguments and reductions into
non-interactive proof artifacts.

```rust
let nia = spongefish_dsfs::plain_non_interactive_argument(argument, sponge);
let nir = spongefish_dsfs::plain_non_interactive_reduction(reduction, sponge);
```

For preprocessing protocols, the compiled wrapper remains stateless with
respect to keys:

```rust
let pnia = spongefish_dsfs::preprocessing_non_interactive_argument(body, sponge);
let (pk, vk) = pnia.preprocess(&index);

let proof = pnia.prove(&pk, &session, &instance, &witness);
pnia.verify(&vk, &session, &instance, &proof)?;
```

The DSFS backend is responsible for:

- deriving the transcript domain separator,
- absorbing protocol/session/public-input data before the first challenge,
- absorbing committed-index bytes for preprocessing protocols,
- absorbing prover messages before challenge derivation,
- squeezing verifier challenges,
- serializing proof bytes,
- replaying verification deterministically,
- rejecting malformed or trailing proof bytes.

The Argus standard DSFS sponge is Keccak. `StdHash` is available for explicit
compatibility paths, especially existing spongefish or `sigma-proofs` layouts.
Changing sponge choice, salt policy, proof layout, or transcript initialization
requires a protocol-id/domain-separation review.

## `live-channel`

`live-channel` runs prover and verifier code in separate threads using `mpsc`.
The verifier samples public coins and sends them to the prover. It is useful for
checking that a protocol really has a public-coin interaction shape before it is
compiled with DSFS.

The live backend produces no NARG proof. It is an execution backend, not a proof
serialization backend.

## Future Backends

The channel interface is intentionally backend-agnostic. A future backend could
use a different transport, a different transcript implementation, or a compiler
that emits IA/IR channel programs from another formalism. The stable rule is
that transcript mechanics stay outside protocol code.
