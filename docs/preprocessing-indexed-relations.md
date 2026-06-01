# Indexed Relations and Preprocessing

**Status:** Archived design draft.

This file used to contain the first preprocessing/indexed-relations proposal.
That proposal has been superseded by the implemented keys-as-inputs design.

Read the current docs instead:

- [Preprocessing Indexed Relations v2](preprocessing-indexed-relations-v2.md)
- [Protocol Core Tree and DSFS Constructors](protocol-core-dsfs-presentation.md)
- [ia-core API](api/ia-core.md)
- [spongefish::dsfs API](api/spongefish-dsfs.md)

Current code shape in one sentence: preprocessing protocols implement
`PreprocessingCore::preprocess(&ix) -> (pk, vk)`, both keys implement
`CommittedIndex`, and stateless DSFS wrappers take `&ProverKey` for `prove` and
`&VerifierKey` for `verify`.
