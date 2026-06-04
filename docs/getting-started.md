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

Run the same Schnorr protocol with live prover and verifier threads:

```bash
cargo run -p argus-examples --bin schnorr -- --live
```

Other useful examples:

```bash
cargo run -p argus-examples --bin sumcheck
cargo run -p argus-examples --bin sumcheck_commit
cargo run -p argus-examples --bin composition
cargo run -p argus-examples --bin preprocessed_lookup
cargo run -p argus-examples --bin warp_accumulate
```

## First Protocol Shape

Most protocols start as an interactive argument:

```rust
ia_core::impl_interactive_argument! {
    impl InteractiveArgument for MyProtocol {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            ia_core::pad_protocol_id(b"my-protocol")
        }

        type Instance = MyInstance;
        type Witness = MyWitness;

        fn prove<P: ProverChannel<Unit = u8>>(
            &self,
            ch: &mut P,
            instance: &Self::Instance,
            witness: &Self::Witness,
        ) {
            ch.send_prover_message(/* ... */);
            let challenge = ch.read_verifier_message();
            /* continue the protocol */
        }

        fn verify<V: VerifierChannel<Unit = u8>>(
            &self,
            ch: &mut V,
            instance: &Self::Instance,
        ) -> VerificationResult<()> {
            let message = ch.read_prover_message()?;
            let challenge = ch.send_verifier_message();
            /* check the transcript */
            Ok(())
        }
    }
}
```

The protocol body should read like the mathematical protocol. It should not
instantiate sponges, absorb public input, derive Fiat-Shamir challenges, or
inspect proof bytes.

## Compile with DSFS

```rust
use ia_core::NonInteractiveArgument;
use spongefish_dsfs as dsfs;

let nia = dsfs::plain_non_interactive_argument(
    MyProtocol,
    dsfs::Keccak::default(),
);

let proof = nia.prove(&session, &instance, &witness);
nia.verify(&session, &instance, &proof)?;
```

For preprocessing protocols, the compiled object stores no keys:

```rust
let pnia = dsfs::preprocessing_non_interactive_argument(
    MyPreprocessedProtocol,
    dsfs::Keccak::default(),
);

let (pk, vk) = pnia.preprocess(&index);
let proof = pnia.prove(&pk, &session, &instance, &witness);
pnia.verify(&vk, &session, &instance, &proof)?;
```

Next: [Author Guide](author-guide/overview.md).
