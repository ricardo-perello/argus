# Argus

Argus is a modular implementation of the Duplex-Sponge Fiat–Shamir (DSFS)
compiler for public-coin Interactive Arguments (IA).

Architecture:

BCS[IOP, MT] = DSFS[IA]
where IA = IBCS[IOP, MT].

Subgoal 1:
- Define a clean IA interface.
- Implement DSFS using spongefish (Construction 4.3).

Subgoal 2:
- Express BCS as an interactive argument (IBCS).
- Compile via DSFS.

Design Principles:
- Strict separation between protocol semantics and transcript mechanics.
- All Fiat–Shamir logic centralized in DSFS.
- Deterministic replay guaranteed.
- No implicit sponge operations outside DSFS.