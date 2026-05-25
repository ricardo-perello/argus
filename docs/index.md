# Argus Documentation

Argus is a Rust workspace for writing public-coin interactive protocols once
against a generic channel interface and running them through different backends.

The core split is:

- **Protocol code** uses only `ia-core` channel traits.
- **Backends** own execution mechanics such as transcript ordering, sponge
  absorption, challenge derivation, and interactive transport.
- **Security metadata** is instance-aware: a security profile is evaluated for a
  concrete instance or for an explicit instance-family bound.

## Recommended reading path

1. [Architecture overview](architecture/overview.md)
2. [Channel model](architecture/channel-model.md)
3. [IA, IR, and composition](architecture/ia-ir.md)
4. [Transcript invariants](security/transcript-invariants.md)
5. [Instance-aware security](security/instance-aware-security.md)
6. [ia-core API](api/ia-core.md)

Historical design iterations are preserved under [Documentation History](history/README.md).

## Active Design Plans

- [Protocol Core Tree and DSFS Constructors](protocol-core-dsfs-presentation.md)
  is the current presentation snapshot of the OOP-style core traits, semantic
  DSFS constructors, prepared wrappers, preprocessing composition, security metadata,
  and WARP shape.
- [Preprocessing Indexed Relations v2](preprocessing-indexed-relations-v2.md)
  is the standalone implementation plan for keyed preprocessing protocols, prepared
  DSFS wrappers, and WARP migration.
