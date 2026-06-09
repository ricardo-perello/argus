# First Argument

This chapter uses Schnorr to show native prover and verifier authoring.

The relation is:

```text
R_schnorr = { ((G, X), x) : X = x * G }
```

The public instance is `(G, X)` and the private witness is `x`.

## Define Native Roles

Use distinct concrete types. This is what prevents verifier-only code from
acquiring the witness algorithm through its type:

```rust,ignore
struct SchnorrProver<G: CurveGroup>(core::marker::PhantomData<G>);
struct SchnorrVerifier<G: CurveGroup>(core::marker::PhantomData<G>);
```

Both roles use the same protocol identifier and public instance type. The
shared macro writes that common shape once while still emitting separate impls.

```rust,ignore
ia_core::impl_interactive_argument! {
    impl<G> {
        prover: SchnorrProver<G>,
        verifier: SchnorrVerifier<G>,
    }
    where
        G: CurveGroup + PrimeGroup + Encoding + Deserialize,
        G::ScalarField: PrimeField + Encoding + Decoding + Deserialize,
    {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            ia_core::pad_protocol_id(b"schnorr")
        }

        type Instance = [G; 2];
        type Witness = G::ScalarField;

        fn prove<C: ProverChannel<Unit = u8>>(
            &self,
            channel: &mut C,
            instance: &Self::Instance,
            witness: &Self::Witness,
        ) {
            let k = G::ScalarField::rand(&mut OsRng);
            let commitment = instance[0] * k;

            channel.send_prover_message(&commitment);
            let challenge: G::ScalarField = channel.read_verifier_message();
            let response = k + challenge * witness;
            channel.send_prover_message(&response);
        }

        fn verify<C: VerifierChannel<Unit = u8>>(
            &self,
            channel: &mut C,
            instance: &Self::Instance,
        ) -> VerificationResult<()> {
            let commitment: G = channel.read_prover_message()?;
            let challenge: G::ScalarField = channel.send_verifier_message();
            let response: G::ScalarField = channel.read_prover_message()?;

            if instance[0] * response == commitment + instance[1] * challenge {
                Ok(())
            } else {
                Err(VerificationError)
            }
        }
    }
}
```

`Witness` and `prove` are emitted only for `SchnorrProver`; `verify` is emitted
only for `SchnorrVerifier`. Use the suffix macros when the two roles need
different bounds or are maintained separately.

The prover sends a commitment, reads a challenge, and sends a response. The
verifier reads the same commitment, produces the same public-coin position, and
reads the response. Neither role says how the challenge is implemented:

- DSFS squeezes it from the transcript.
- `live-channel` samples it and sends it to the prover.

The full implementation is in
`crates/argus-examples/src/bin/schnorr.rs`.

## Protocol IDs

`protocol_id` is domain-separation input. Both roles of one protocol must return
the same identifier. If a backend changes sponge choice, salt policy, or proof
layout, the backend-level protocol identifier must also be reviewed.

## Add Security Metadata

Implement `ArgumentSecurity` on `SchnorrVerifier`, not on the prover. Security
metadata describes verifier rounds and public-instance-dependent bounds; it does
not require witness capability.
