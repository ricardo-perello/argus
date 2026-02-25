# TODO
Goal: **BCS[IOP, MT] = DSFS[IA] where IA = IBCS[IOP, MT]**

## Warmup (start here)
- [ ] Apply DSFS to the Schnorr protocol (use spongefish example as reference)
- [ ] Apply DSFS to Sumcheck

## Subgoal 1: DSFS[IA]
- [ ] Design a DSL/interface for an Interactive Argument (IA) (round structure, public-coin, deterministic replay)
- [ ] Define the output NARG \(=\(P,V\)\) obtained by applying Fiat–Shamir to an IA
- [ ] Decide **which FS** is being realized:
  - [ ] “Ideal FS” model from the book (powerful oracles \(f_1,\dots,f_k\))
  - [ ] Real FS via duplex sponges (DSFS), per `https://eprint.iacr.org/2025/536`
- [ ] Study spongefish API (init / absorb / squeeze) and map it to Construction 4.3 needs
- [ ] Implement **Construction 4.3** DSFS wrapper around the IA interface (DSFS is the only place sponge ops occur)
- [ ] (TBD) Track/link to the relevant talk notes

## Subgoal 2: BCS[IOP, MT]
- [ ] Specify IBCS[IOP, MT] as an IA (BCS expressed as an interactive argument)
- [ ] Compile BCS via DSFS: DSFS[IA = IBCS[IOP, MT]]

## References
- DSFS paper: `https://eprint.iacr.org/2025/536`
- Implementation: `https://github.com/arkworks-rs/spongefish`

## People
- Giacomo F
- Michele O

