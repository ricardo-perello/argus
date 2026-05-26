# Getting Started

Build everything:

```bash
cargo build
```

Run the full test suite:

```bash
cargo test
```

Run examples:

```bash
cargo run -p argus-examples --bin schnorr
cargo run -p argus-examples --bin schnorr -- --live
cargo run -p argus-examples --bin sumcheck
cargo run -p argus-examples --bin sumcheck_commit
cargo run -p argus-examples --bin composition
cargo run -p argus-examples --bin warp_accumulate
```

Run only WARP tests:

```bash
cargo test -p warp
```

Build local rustdoc:

```bash
cargo doc --workspace --no-deps
```

## Implementing a protocol

1. Define the public instance and private witness types.
2. Write one macro authoring block with `ia_core::impl_interactive_argument!`
   or `ia_core::impl_interactive_reduction!`.
3. Use only the channel API inside protocol code.
4. Optionally implement `ArgumentSecurity` or `ReductionSecurity`.
5. Run through `spongefish::dsfs` or `live-channel`.

For example, a plain argument author writes:

```rust
ia_core::impl_interactive_argument! {
    impl InteractiveArgument for MyProtocol {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            ia_core::pad_protocol_id(b"my-protocol")
        }

        type Instance = MyInstance;
        type Witness = MyWitness;

        fn prove<P: ProverChannel>(
            &self,
            ch: &mut P,
            instance: &Self::Instance,
            witness: &Self::Witness,
        ) {
            /* send prover messages, read verifier challenges */
        }

        fn verify<V: VerifierChannel>(
            &self,
            ch: &mut V,
            instance: &Self::Instance,
        ) -> VerificationResult<()> {
            /* read prover messages, send verifier challenges */
            Ok(())
        }
    }
}
```

The macro expands to `ProtocolCore`, `ArgumentCore`, and `InteractiveArgument`
impls. Manual impls are still supported for low-level adapters and tests.

DSFS construction is explicit:

```rust
let nia = spongefish_dsfs::plain_non_interactive_argument(body, spongefish_dsfs::Keccak::default());
let proof = nia.prove(&session, &instance, &witness);
nia.verify(&session, &instance, &proof)?;
```

For preprocessed protocols, use `ia_core::impl_preprocessing_argument!` or
`ia_core::impl_preprocessing_reduction!`. The block adds `Index`, `ProverKey`,
`VerifierKey`, and `index(ix) -> (pk, vk)`, then prepare the DSFS wrapper:

```rust
let nia = spongefish_dsfs::preprocessing_non_interactive_argument(preprocessing_protocol, sponge)
    .prepare(&index);
```

Protocol code must never instantiate sponges or perform Fiat-Shamir logic.
