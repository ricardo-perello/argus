# Domain Separation

Domain separation binds a proof to the protocol, compilation format, and public
context it is supposed to represent.

The short rule is:

> If changing a value changes the protocol or proof format, that change must be
> visible to the backend before the first challenge.

## Protocol ID

`ProtocolCore::protocol_id(&self)` identifies the compiled protocol body.

It is a method, not only an associated constant, because real protocol objects
may carry immutable configuration. For example, a WHIR-style protocol object may
store rates, code information, dimensions, or mode choices.

Any data in `self` that affects the message flow, verifier challenges, accepted
statements, proof layout, soundness profile, or transcript semantics must be
reflected in `protocol_id(&self)` or otherwise absorbed as public input before
the first challenge.

What `self` must not contain is transcript state. The protocol object may
describe the configured protocol; it must not carry a sponge, mutable transcript,
challenge counter, or hidden verifier state. Transcript state belongs to the
backend channel.

## DSFS Inputs

DSFS derives transcript initialization from three public inputs:

| Input | Meaning |
| --- | --- |
| protocol id | which configured protocol body is being compiled |
| sponge info | which DSFS transcript format and sponge bootstrap are used |
| session | per-invocation public context |

After that initialization, DSFS absorbs the public statement before the first
challenge. For plain protocols this is the ordinary instance. For preprocessing
protocols it is the committed index paired with the ordinary instance:

```text
IndexedInstanceRef {
    committed_index,
    instance,
}
```

The protocol body receives the bare instance and key. It does not construct or
absorb this wrapper itself.

### Prefix-free instance framing

For the statement binding to be unambiguous, the absorbed instance bytes must be
**prefix-free**: no instance's encoding may be a prefix of another's. The sponge
absorbs a flat byte stream

```text
domsep(64) || instance || salt || prover messages...
```

with no implicit boundary after the instance, so a non-prefix-free encoding —
the identity encoding of `Vec<u8>` / `&[u8]`, whose length is not self-described,
is the classic example — could let two distinct statements share a transcript.

`spongefish` documents prefix-freeness as the caller's responsibility. Rather
than rely on every protocol author to choose a prefix-free `Instance` encoding,
**both** DSFS paths frame the instance with a tag and a `u64` length prefix
before absorbing it:

- the preprocessing path via `IndexedInstanceRef` (shown above), and
- the plain path via an internal `dsfs:plain-instance:v1`-tagged wrapper.

This makes the two paths consistent and the plain path robust by construction
regardless of the instance type.

**Tradeoff.** Framing is *absorb-only*: it changes nothing in the Argus
interfaces — the `Instance` type, the role traits, the `Dsfs*` constructors, and
every call site are untouched; only the bytes fed to the sponge change. The costs
are a few extra absorbed bytes per proof and a one-time transcript-format change.
The plain-path **tag itself versions the format**, so this change is deliberately
*not* tied to a `SPONGE_INFO` bump: `SPONGE_INFO` is keyed by sponge, so bumping
it would also re-version the preprocessing path and the `StdHash` σ-proofs interop
path, which do not go through these helpers and must stay byte-stable. The
low-level `SpongeProver` / `SpongeVerifier` channels do **not** frame for you;
callers that bypass the semantic constructors (e.g. σ-proofs byte-compat layouts)
own their instance encoding.

## Sponge Choice and Proof Layout

The DSFS-level protocol identity must change when any of these change:

- sponge choice,
- salt policy,
- proof byte layout,
- transcript initialization,
- public-input encoding.

Argus's standard DSFS path uses Keccak. `StdHash` is used only for explicit
compatibility paths, such as selected `sigma-proofs` layouts. Compatibility
tags from external formats may not equal the IA's own protocol id; treat them
as DSFS-level domain-separation inputs.

## Implementation Note

`spongefish-dsfs` uses spongefish's domain-separator derivation to combine:

```text
len(protocol_id) || protocol_id
len(sponge_info) || sponge_info
len(session) || session
```

The exact encoding is backend detail. The author-facing rule is that protocol
identity, compilation identity, session, committed index when present, and
instance are fixed before any verifier challenge is derived.
