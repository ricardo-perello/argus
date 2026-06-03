# First Argument

The easiest way to implement an Argus protocol is to write the interactive
conversation first. This chapter uses Schnorr as the running example.

The relation is:

```text
R_schnorr = { ((G, X), x) : X = x · G }
```

The protocol proves knowledge of `x` such that `X = x · G`:

```text
Common input: (G, X)

  Prover P(x)                                  Verifier V(G, X)
  -----------                                  ----------------

  sample k
  K = k · G

        K ----------------------------------->

                                                sample public c

        <----------------------------------- c

  r = k + c · x

        r ----------------------------------->

                                                accept iff
                                                G · r = K + c · X
```

The Argus implementation should mirror that diagram. The public data goes in
`Instance`; the private data goes in `Witness`:

```text
Instance = (G, X)
Witness  = x
```

## Put Data in the Right Place

First decide what data belongs to the protocol object, the instance, and the
witness. For Schnorr, all mathematical data is either public instance data or
private witness data. The protocol object only names the protocol family and
the curve type:

```rust
// No statement or witness data lives here. Those are passed as `Instance`
// and `Witness` below. This type just selects the Schnorr protocol over `G`.
struct Schnorr<G: CurveGroup>(core::marker::PhantomData<G>);

impl<G: CurveGroup> Default for Schnorr<G> {
    fn default() -> Self {
        Self(core::marker::PhantomData)
    }
}
```

## Implement the Argument

Most authors use the macro surface. It expands into the underlying core traits,
but keeps the author block close to the mathematical protocol.

```rust
ia_core::impl_interactive_argument! {
    impl<G> InteractiveArgument for Schnorr<G>
    where
        // The channel sends group elements and field elements as byte strings.
        G: CurveGroup + PrimeGroup + Encoding + Deserialize,
        G::ScalarField: PrimeField + Encoding + Decoding + Deserialize,
    {
        // Domain-separation label for this protocol body.
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            ia_core::pad_protocol_id(b"schnorr")
        }

        // Public statement: generator and public key.
        type Instance = [G; 2];
        // Private witness: secret scalar x with X = x * G.
        type Witness = G::ScalarField;

        #[allow(non_snake_case)]
        fn prove<P: ProverChannel<Unit = u8>>(
            &self,
            ch: &mut P,
            instance: &[G; 2],
            witness: &G::ScalarField,
        ) {
            // First prover message: commitment K = k * G.
            let k = G::ScalarField::rand(&mut OsRng);
            let K = instance[0] * k;
            ch.send_prover_message(&K);

            // Public-coin challenge from whichever backend is running us.
            let c: G::ScalarField = ch.read_verifier_message();

            // Final prover message: response r = k + c * x.
            let r = k + c * witness;
            ch.send_prover_message(&r);
        }

        #[allow(non_snake_case)]
        fn verify<V: VerifierChannel<Unit = u8>>(
            &self,
            ch: &mut V,
            instance: &[G; 2],
        ) -> VerificationResult<()> {
            let (G_gen, X) = (instance[0], instance[1]);

            // Same transcript shape as the prover: read K, produce c, read r.
            let K: G = ch.read_prover_message()?;
            let c: G::ScalarField = ch.send_verifier_message();
            let r: G::ScalarField = ch.read_prover_message()?;

            // Relation check implied by the Schnorr transcript.
            if G_gen * r == K + X * c {
                Ok(())
            } else {
                Err(VerificationError)
            }
        }
    }
}
```

The full version lives in
`crates/argus-examples/src/bin/schnorr.rs`.

## Read the Block as a Protocol

The prover code sends `K`, reads `c`, then sends `r`. The verifier code reads
`K`, sends `c`, then reads `r`.

Neither side says where `c` comes from. That is why the same body can run in two
ways:

- DSFS squeezes `c` from a transcript.
- `live-channel` samples `c` and sends it to the prover.

The next two chapters show both executions:
[Compile with DSFS](dsfs.md) and [Run Interactively](live.md).

## Protocol IDs

`protocol_id` is domain-separation input. Leaf protocols often use:

```rust
ia_core::pad_protocol_id(b"schnorr")
```

For composed protocols, Argus derives protocol IDs from the component tree using
injective encodings. If a backend changes sponge choice, salt policy, or proof
layout, that backend-level protocol identifier must also be reviewed.

## Add Security Metadata Later

The executable protocol does not require a security profile. When the protocol
is ready, implement `ArgumentSecurity` to record soundness, knowledge soundness,
HVZK, and challenge length metadata. This is separate from the channel
conversation so examples and tests can first focus on behavior.
