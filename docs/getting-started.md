# Getting Started

This page is the shortest path from a fresh checkout to a running protocol.

## Build and Test

```bash
cargo build
cargo test
```

Run the smallest example as a DSFS-compiled non-interactive proof:

```bash
cargo run -p argus-examples --bin schnorr
```

Run the same Schnorr conversation with live prover and verifier threads:

```bash
cargo run -p argus-examples --bin schnorr -- --live
```

The examples form an incremental ladder:

```bash
cargo run -p argus-examples --bin dleq
cargo run -p argus-examples --bin preprocessed_lookup
cargo run -p argus-examples --bin preprocessed_sumcheck
cargo run -p argus-examples --bin composition
cargo run -p argus-examples --bin multiparty_threads
```

The full example map lives in `crates/argus-examples/README.md`.

## First Protocol Shape

Argus models proving and verification as native, independent roles. A plain
argument therefore starts with two concrete types:

```rust,ignore
struct MyProver;
struct MyVerifier;
```

When both roles share their generic bounds, author them together:

```rust,ignore
ia_core::impl_interactive_argument! {
    impl {
        prover: MyProver,
        verifier: MyVerifier,
    }
    {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            ia_core::pad_protocol_id(b"my-protocol")
        }

        type Instance = MyInstance;
        type Witness = MyWitness;

        fn prove<C: ProverChannel<Unit = u8>>(
            &self,
            channel: &mut C,
            instance: &Self::Instance,
            witness: &Self::Witness,
        ) {
            channel.send_prover_message(/* ... */);
            let challenge = channel.read_verifier_message();
            /* continue the protocol */
        }

        fn verify<C: VerifierChannel<Unit = u8>>(
            &self,
            channel: &mut C,
            instance: &Self::Instance,
        ) -> VerificationResult<()> {
            let message = channel.read_prover_message()?;
            let challenge = channel.send_verifier_message();
            /* check the conversation */
            Ok(())
        }
    }
}
```

The macro emits two independent implementations. The verifier type still has
no witness capability. Use the role-specific `_prover!` and `_verifier!` forms
when the roles need different bounds. Protocol code uses only channel
operations; it never instantiates a sponge, absorbs public input, derives a
Fiat-Shamir challenge, or inspects proof bytes.

## Compile with DSFS

Compile each role independently:

```rust,ignore
use ia_core::prelude::*;
use spongefish_dsfs as dsfs;

let prover = dsfs::plain_non_interactive_argument_prover(
    MyProver,
    dsfs::Keccak::default(),
);
let verifier = dsfs::plain_non_interactive_argument_verifier(
    MyVerifier,
    dsfs::Keccak::default(),
);

let proof = prover.prove(&session, &instance, &witness);
verifier.verify(&session, &instance, &proof)?;
```

For preprocessing protocols, indexing is a third independent role:

```rust,ignore
let (pk, vk) = MyIndexer.preprocess(&index);

let prover = dsfs::preprocessing_non_interactive_argument_prover(
    MyPreprocessedProver,
    dsfs::Keccak::default(),
);
let verifier = dsfs::preprocessing_non_interactive_argument_verifier(
    MyPreprocessedVerifier,
    dsfs::Keccak::default(),
);

let proof = prover.prove(&pk, &session, &instance, &witness);
verifier.verify(&vk, &session, &instance, &proof)?;
```

DSFS stores neither key and does not run indexing. It binds the committed index
from the key supplied to each role before deriving the first challenge.

Next: [Author Guide](author-guide/overview.md).
