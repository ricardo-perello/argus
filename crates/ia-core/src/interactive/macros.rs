//! Role-specific protocol authoring macros.

#[doc(hidden)]
#[macro_export]
macro_rules! __ia_core_parse_role {
    ([$emit:ident] [$($generics:tt)*] for $ty:ty where $($tail:tt)*) => {
        $crate::__ia_core_parse_role_where!([$emit] [$($generics)*] [$ty] [] $($tail)*);
    };
    ([$emit:ident] [$($generics:tt)*] for $ty:ty { $($body:tt)* }) => {
        $crate::$emit!([$($generics)*] [$ty] [] { $($body)* });
    };
    ([$emit:ident] [$($generics:tt)*] $next:tt $($rest:tt)*) => {
        $crate::__ia_core_parse_role!([$emit] [$($generics)* $next] $($rest)*);
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __ia_core_parse_role_where {
    ([$emit:ident] [$($generics:tt)*] [$ty:ty] [$($where_clause:tt)*] { $($body:tt)* }) => {
        $crate::$emit!([$($generics)*] [$ty] [$($where_clause)*] { $($body)* });
    };
    (
        [$emit:ident] [$($generics:tt)*] [$ty:ty] [$($where_clause:tt)*]
        $next:tt $($rest:tt)*
    ) => {
        $crate::__ia_core_parse_role_where!(
            [$emit] [$($generics)*] [$ty] [$($where_clause)* $next] $($rest)*
        );
    };
}

/// Implement one native role of a plain interactive argument.
#[macro_export]
macro_rules! impl_interactive_argument {
    (prover impl $($rest:tt)*) => {
        $crate::__ia_core_parse_role!([__ia_core_emit_argument_prover] [] $($rest)*);
    };
    (verifier impl $($rest:tt)*) => {
        $crate::__ia_core_parse_role!([__ia_core_emit_argument_verifier] [] $($rest)*);
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __ia_core_emit_argument_prover {
    (
        [$($generics:tt)*] [$ty:ty] [$($where_clause:tt)*] {
            $(#[$protocol_attr:meta])*
            fn protocol_id(&self) -> impl AsRef<[u8]> $protocol_body:block
            $(#[$instance_attr:meta])*
            type Instance = $instance:ty;
            $(#[$witness_attr:meta])*
            type Witness = $witness:ty;
            $($methods:tt)*
        }
    ) => {
        impl $($generics)* $crate::ProtocolCore for $ty where $($where_clause)* {
            $(#[$protocol_attr])*
            fn protocol_id(&self) -> impl AsRef<[u8]> $protocol_body
        }
        impl $($generics)* $crate::ArgumentCore for $ty where $($where_clause)* {
            $(#[$instance_attr])*
            type Instance = $instance;
        }
        impl $($generics)* $crate::ArgumentProverCore for $ty where $($where_clause)* {
            $(#[$witness_attr])*
            type Witness = $witness;
        }
        impl $($generics)* $crate::InteractiveArgumentProver for $ty where $($where_clause)* {
            $($methods)*
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __ia_core_emit_argument_verifier {
    (
        [$($generics:tt)*] [$ty:ty] [$($where_clause:tt)*] {
            $(#[$protocol_attr:meta])*
            fn protocol_id(&self) -> impl AsRef<[u8]> $protocol_body:block
            $(#[$instance_attr:meta])*
            type Instance = $instance:ty;
            $($methods:tt)*
        }
    ) => {
        impl $($generics)* $crate::ProtocolCore for $ty where $($where_clause)* {
            $(#[$protocol_attr])*
            fn protocol_id(&self) -> impl AsRef<[u8]> $protocol_body
        }
        impl $($generics)* $crate::ArgumentCore for $ty where $($where_clause)* {
            $(#[$instance_attr])*
            type Instance = $instance;
        }
        impl $($generics)* $crate::InteractiveArgumentVerifier for $ty where $($where_clause)* {
            $($methods)*
        }
    };
}

/// Implement one native role of a plain interactive reduction.
#[macro_export]
macro_rules! impl_interactive_reduction {
    (prover impl $($rest:tt)*) => {
        $crate::__ia_core_parse_role!([__ia_core_emit_reduction_prover] [] $($rest)*);
    };
    (verifier impl $($rest:tt)*) => {
        $crate::__ia_core_parse_role!([__ia_core_emit_reduction_verifier] [] $($rest)*);
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __ia_core_emit_reduction_prover {
    (
        [$($generics:tt)*] [$ty:ty] [$($where_clause:tt)*] {
            $(#[$protocol_attr:meta])*
            fn protocol_id(&self) -> impl AsRef<[u8]> $protocol_body:block
            $(#[$source_instance_attr:meta])*
            type SourceInstance = $source_instance:ty;
            $(#[$target_instance_attr:meta])*
            type TargetInstance = $target_instance:ty;
            $(#[$source_witness_attr:meta])*
            type SourceWitness = $source_witness:ty;
            $(#[$target_witness_attr:meta])*
            type TargetWitness = $target_witness:ty;
            $($methods:tt)*
        }
    ) => {
        impl $($generics)* $crate::ProtocolCore for $ty where $($where_clause)* {
            $(#[$protocol_attr])*
            fn protocol_id(&self) -> impl AsRef<[u8]> $protocol_body
        }
        impl $($generics)* $crate::ReductionCore for $ty where $($where_clause)* {
            $(#[$source_instance_attr])*
            type SourceInstance = $source_instance;
            $(#[$target_instance_attr])*
            type TargetInstance = $target_instance;
        }
        impl $($generics)* $crate::ReductionProverCore for $ty where $($where_clause)* {
            $(#[$source_witness_attr])*
            type SourceWitness = $source_witness;
            $(#[$target_witness_attr])*
            type TargetWitness = $target_witness;
        }
        impl $($generics)* $crate::InteractiveReductionProver for $ty where $($where_clause)* {
            $($methods)*
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __ia_core_emit_reduction_verifier {
    (
        [$($generics:tt)*] [$ty:ty] [$($where_clause:tt)*] {
            $(#[$protocol_attr:meta])*
            fn protocol_id(&self) -> impl AsRef<[u8]> $protocol_body:block
            $(#[$source_instance_attr:meta])*
            type SourceInstance = $source_instance:ty;
            $(#[$target_instance_attr:meta])*
            type TargetInstance = $target_instance:ty;
            $($methods:tt)*
        }
    ) => {
        impl $($generics)* $crate::ProtocolCore for $ty where $($where_clause)* {
            $(#[$protocol_attr])*
            fn protocol_id(&self) -> impl AsRef<[u8]> $protocol_body
        }
        impl $($generics)* $crate::ReductionCore for $ty where $($where_clause)* {
            $(#[$source_instance_attr])*
            type SourceInstance = $source_instance;
            $(#[$target_instance_attr])*
            type TargetInstance = $target_instance;
        }
        impl $($generics)* $crate::InteractiveReductionVerifier for $ty where $($where_clause)* {
            $($methods)*
        }
    };
}

/// Implement one native role of a preprocessing interactive argument.
#[macro_export]
macro_rules! impl_preprocessing_argument {
    (indexer impl $($rest:tt)*) => {
        $crate::__ia_core_parse_role!([__ia_core_emit_argument_indexer] [] $($rest)*);
    };
    (prover impl $($rest:tt)*) => {
        $crate::__ia_core_parse_role!([__ia_core_emit_preprocessing_argument_prover] [] $($rest)*);
    };
    (verifier impl $($rest:tt)*) => {
        $crate::__ia_core_parse_role!([__ia_core_emit_preprocessing_argument_verifier] [] $($rest)*);
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __ia_core_emit_argument_indexer {
    (
        [$($generics:tt)*] [$ty:ty] [$($where_clause:tt)*] {
            $(#[$protocol_attr:meta])*
            fn protocol_id(&self) -> impl AsRef<[u8]> $protocol_body:block
            $(#[$instance_attr:meta])*
            type Instance = $instance:ty;
            $(#[$index_attr:meta])*
            type Index = $index:ty;
            $(#[$prover_key_attr:meta])*
            type ProverKey = $prover_key:ty;
            $(#[$verifier_key_attr:meta])*
            type VerifierKey = $verifier_key:ty;
            $($methods:tt)*
        }
    ) => {
        impl $($generics)* $crate::ProtocolCore for $ty where $($where_clause)* {
            $(#[$protocol_attr])*
            fn protocol_id(&self) -> impl AsRef<[u8]> $protocol_body
        }
        impl $($generics)* $crate::ArgumentCore for $ty where $($where_clause)* {
            $(#[$instance_attr])*
            type Instance = $instance;
        }
        impl $($generics)* $crate::Indexer for $ty where $($where_clause)* {
            $(#[$index_attr])*
            type Index = $index;
            $(#[$prover_key_attr])*
            type ProverKey = $prover_key;
            $(#[$verifier_key_attr])*
            type VerifierKey = $verifier_key;
            $($methods)*
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __ia_core_emit_preprocessing_argument_prover {
    (
        [$($generics:tt)*] [$ty:ty] [$($where_clause:tt)*] {
            $(#[$protocol_attr:meta])*
            fn protocol_id(&self) -> impl AsRef<[u8]> $protocol_body:block
            $(#[$instance_attr:meta])*
            type Instance = $instance:ty;
            $(#[$witness_attr:meta])*
            type Witness = $witness:ty;
            $(#[$prover_key_attr:meta])*
            type ProverKey = $prover_key:ty;
            $($methods:tt)*
        }
    ) => {
        impl $($generics)* $crate::ProtocolCore for $ty where $($where_clause)* {
            $(#[$protocol_attr])*
            fn protocol_id(&self) -> impl AsRef<[u8]> $protocol_body
        }
        impl $($generics)* $crate::ArgumentCore for $ty where $($where_clause)* {
            $(#[$instance_attr])*
            type Instance = $instance;
        }
        impl $($generics)* $crate::ArgumentProverCore for $ty where $($where_clause)* {
            $(#[$witness_attr])*
            type Witness = $witness;
        }
        impl $($generics)* $crate::PreprocessingInteractiveArgumentProver for $ty
        where $($where_clause)*
        {
            $(#[$prover_key_attr])*
            type ProverKey = $prover_key;
            $($methods)*
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __ia_core_emit_preprocessing_argument_verifier {
    (
        [$($generics:tt)*] [$ty:ty] [$($where_clause:tt)*] {
            $(#[$protocol_attr:meta])*
            fn protocol_id(&self) -> impl AsRef<[u8]> $protocol_body:block
            $(#[$instance_attr:meta])*
            type Instance = $instance:ty;
            $(#[$verifier_key_attr:meta])*
            type VerifierKey = $verifier_key:ty;
            $($methods:tt)*
        }
    ) => {
        impl $($generics)* $crate::ProtocolCore for $ty where $($where_clause)* {
            $(#[$protocol_attr])*
            fn protocol_id(&self) -> impl AsRef<[u8]> $protocol_body
        }
        impl $($generics)* $crate::ArgumentCore for $ty where $($where_clause)* {
            $(#[$instance_attr])*
            type Instance = $instance;
        }
        impl $($generics)* $crate::PreprocessingInteractiveArgumentVerifier for $ty
        where $($where_clause)*
        {
            $(#[$verifier_key_attr])*
            type VerifierKey = $verifier_key;
            $($methods)*
        }
    };
}

/// Implement one native role of a preprocessing interactive reduction.
#[macro_export]
macro_rules! impl_preprocessing_reduction {
    (indexer impl $($rest:tt)*) => {
        $crate::__ia_core_parse_role!([__ia_core_emit_reduction_indexer] [] $($rest)*);
    };
    (prover impl $($rest:tt)*) => {
        $crate::__ia_core_parse_role!([__ia_core_emit_preprocessing_reduction_prover] [] $($rest)*);
    };
    (verifier impl $($rest:tt)*) => {
        $crate::__ia_core_parse_role!([__ia_core_emit_preprocessing_reduction_verifier] [] $($rest)*);
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __ia_core_emit_reduction_indexer {
    (
        [$($generics:tt)*] [$ty:ty] [$($where_clause:tt)*] {
            $(#[$protocol_attr:meta])*
            fn protocol_id(&self) -> impl AsRef<[u8]> $protocol_body:block
            $(#[$source_instance_attr:meta])*
            type SourceInstance = $source_instance:ty;
            $(#[$target_instance_attr:meta])*
            type TargetInstance = $target_instance:ty;
            $(#[$index_attr:meta])*
            type Index = $index:ty;
            $(#[$prover_key_attr:meta])*
            type ProverKey = $prover_key:ty;
            $(#[$verifier_key_attr:meta])*
            type VerifierKey = $verifier_key:ty;
            $($methods:tt)*
        }
    ) => {
        impl $($generics)* $crate::ProtocolCore for $ty where $($where_clause)* {
            $(#[$protocol_attr])*
            fn protocol_id(&self) -> impl AsRef<[u8]> $protocol_body
        }
        impl $($generics)* $crate::ReductionCore for $ty where $($where_clause)* {
            $(#[$source_instance_attr])*
            type SourceInstance = $source_instance;
            $(#[$target_instance_attr])*
            type TargetInstance = $target_instance;
        }
        impl $($generics)* $crate::Indexer for $ty where $($where_clause)* {
            $(#[$index_attr])*
            type Index = $index;
            $(#[$prover_key_attr])*
            type ProverKey = $prover_key;
            $(#[$verifier_key_attr])*
            type VerifierKey = $verifier_key;
            $($methods)*
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __ia_core_emit_preprocessing_reduction_prover {
    (
        [$($generics:tt)*] [$ty:ty] [$($where_clause:tt)*] {
            $(#[$protocol_attr:meta])*
            fn protocol_id(&self) -> impl AsRef<[u8]> $protocol_body:block
            $(#[$source_instance_attr:meta])*
            type SourceInstance = $source_instance:ty;
            $(#[$target_instance_attr:meta])*
            type TargetInstance = $target_instance:ty;
            $(#[$source_witness_attr:meta])*
            type SourceWitness = $source_witness:ty;
            $(#[$target_witness_attr:meta])*
            type TargetWitness = $target_witness:ty;
            $(#[$prover_key_attr:meta])*
            type ProverKey = $prover_key:ty;
            $($methods:tt)*
        }
    ) => {
        impl $($generics)* $crate::ProtocolCore for $ty where $($where_clause)* {
            $(#[$protocol_attr])*
            fn protocol_id(&self) -> impl AsRef<[u8]> $protocol_body
        }
        impl $($generics)* $crate::ReductionCore for $ty where $($where_clause)* {
            $(#[$source_instance_attr])*
            type SourceInstance = $source_instance;
            $(#[$target_instance_attr])*
            type TargetInstance = $target_instance;
        }
        impl $($generics)* $crate::ReductionProverCore for $ty where $($where_clause)* {
            $(#[$source_witness_attr])*
            type SourceWitness = $source_witness;
            $(#[$target_witness_attr])*
            type TargetWitness = $target_witness;
        }
        impl $($generics)* $crate::PreprocessingInteractiveReductionProver for $ty
        where $($where_clause)*
        {
            $(#[$prover_key_attr])*
            type ProverKey = $prover_key;
            $($methods)*
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __ia_core_emit_preprocessing_reduction_verifier {
    (
        [$($generics:tt)*] [$ty:ty] [$($where_clause:tt)*] {
            $(#[$protocol_attr:meta])*
            fn protocol_id(&self) -> impl AsRef<[u8]> $protocol_body:block
            $(#[$source_instance_attr:meta])*
            type SourceInstance = $source_instance:ty;
            $(#[$target_instance_attr:meta])*
            type TargetInstance = $target_instance:ty;
            $(#[$verifier_key_attr:meta])*
            type VerifierKey = $verifier_key:ty;
            $($methods:tt)*
        }
    ) => {
        impl $($generics)* $crate::ProtocolCore for $ty where $($where_clause)* {
            $(#[$protocol_attr])*
            fn protocol_id(&self) -> impl AsRef<[u8]> $protocol_body
        }
        impl $($generics)* $crate::ReductionCore for $ty where $($where_clause)* {
            $(#[$source_instance_attr])*
            type SourceInstance = $source_instance;
            $(#[$target_instance_attr])*
            type TargetInstance = $target_instance;
        }
        impl $($generics)* $crate::PreprocessingInteractiveReductionVerifier for $ty
        where $($where_clause)*
        {
            $(#[$verifier_key_attr])*
            type VerifierKey = $verifier_key;
            $($methods)*
        }
    };
}

#[cfg(test)]
mod tests {
    use core::marker::PhantomData;

    use crate::{
        ArgumentCore, ArgumentProverCore, Indexer, PreprocessingInteractiveArgumentProver,
        PreprocessingInteractiveArgumentVerifier, PreprocessingInteractiveReductionProver,
        PreprocessingInteractiveReductionVerifier, ProtocolCore, ProverChannel, ReductionCore,
        ReductionProverCore, VerificationResult, VerifierChannel,
    };

    struct ArgProver;
    struct ArgVerifier;

    crate::impl_interactive_argument! {
        prover impl for ArgProver {
            fn protocol_id(&self) -> impl AsRef<[u8]> { b"macro-arg" }
            type Instance = u8;
            type Witness = u16;
            fn prove<C: ProverChannel<Unit = u8>>(
                &self, _: &mut C, _: &Self::Instance, _: &Self::Witness
            ) {}
        }
    }

    crate::impl_interactive_argument! {
        verifier impl for ArgVerifier {
            fn protocol_id(&self) -> impl AsRef<[u8]> { b"macro-arg" }
            type Instance = u8;
            fn verify<C: VerifierChannel<Unit = u8>>(
                &self, _: &mut C, _: &Self::Instance
            ) -> VerificationResult<()> { Ok(()) }
        }
    }

    struct ReductionProver;
    struct ReductionVerifier;

    crate::impl_interactive_reduction! {
        prover impl for ReductionProver {
            fn protocol_id(&self) -> impl AsRef<[u8]> { b"macro-reduction" }
            type SourceInstance = u8;
            type TargetInstance = u16;
            type SourceWitness = u32;
            type TargetWitness = u64;
            fn prove<C: ProverChannel<Unit = u8>>(
                &self, _: &mut C, _: &Self::SourceInstance, _: &Self::SourceWitness
            ) -> (Self::TargetInstance, Self::TargetWitness) { (0, 0) }
        }
    }

    crate::impl_interactive_reduction! {
        verifier impl for ReductionVerifier {
            fn protocol_id(&self) -> impl AsRef<[u8]> { b"macro-reduction" }
            type SourceInstance = u8;
            type TargetInstance = u16;
            fn verify<C: VerifierChannel<Unit = u8>>(
                &self, _: &mut C, _: &Self::SourceInstance
            ) -> VerificationResult<Self::TargetInstance> { Ok(0) }
        }
    }

    struct ArgumentIndexer;
    struct IndexedArgumentProver;
    struct IndexedArgumentVerifier;

    crate::impl_preprocessing_argument! {
        indexer impl for ArgumentIndexer {
            fn protocol_id(&self) -> impl AsRef<[u8]> { b"macro-indexed-arg" }
            type Instance = u8;
            type Index = ();
            type ProverKey = ();
            type VerifierKey = ();
            fn preprocess(&self, _: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
                ((), ())
            }
        }
    }

    crate::impl_preprocessing_argument! {
        prover impl for IndexedArgumentProver {
            fn protocol_id(&self) -> impl AsRef<[u8]> { b"macro-indexed-arg" }
            type Instance = u8;
            type Witness = u16;
            type ProverKey = ();
            fn prove<C: ProverChannel<Unit = u8>>(
                &self, _: &mut C, _: &Self::ProverKey, _: &Self::Instance, _: &Self::Witness
            ) {}
        }
    }

    crate::impl_preprocessing_argument! {
        verifier impl for IndexedArgumentVerifier {
            fn protocol_id(&self) -> impl AsRef<[u8]> { b"macro-indexed-arg" }
            type Instance = u8;
            type VerifierKey = ();
            fn verify<C: VerifierChannel<Unit = u8>>(
                &self, _: &mut C, _: &Self::VerifierKey, _: &Self::Instance
            ) -> VerificationResult<()> { Ok(()) }
        }
    }

    struct ReductionIndexer;
    struct IndexedReductionProver;
    struct IndexedReductionVerifier;

    crate::impl_preprocessing_reduction! {
        indexer impl for ReductionIndexer {
            fn protocol_id(&self) -> impl AsRef<[u8]> { b"macro-indexed-red" }
            type SourceInstance = u8;
            type TargetInstance = u16;
            type Index = ();
            type ProverKey = ();
            type VerifierKey = ();
            fn preprocess(&self, _: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
                ((), ())
            }
        }
    }

    crate::impl_preprocessing_reduction! {
        prover impl for IndexedReductionProver {
            fn protocol_id(&self) -> impl AsRef<[u8]> { b"macro-indexed-red" }
            type SourceInstance = u8;
            type TargetInstance = u16;
            type SourceWitness = u32;
            type TargetWitness = u64;
            type ProverKey = ();
            fn prove<C: ProverChannel<Unit = u8>>(
                &self,
                _: &mut C,
                _: &Self::ProverKey,
                _: &Self::SourceInstance,
                _: &Self::SourceWitness,
            ) -> (Self::TargetInstance, Self::TargetWitness) { (0, 0) }
        }
    }

    crate::impl_preprocessing_reduction! {
        verifier impl for IndexedReductionVerifier {
            fn protocol_id(&self) -> impl AsRef<[u8]> { b"macro-indexed-red" }
            type SourceInstance = u8;
            type TargetInstance = u16;
            type VerifierKey = ();
            fn verify<C: VerifierChannel<Unit = u8>>(
                &self, _: &mut C, _: &Self::VerifierKey, _: &Self::SourceInstance
            ) -> VerificationResult<Self::TargetInstance> { Ok(0) }
        }
    }

    struct GenericProver<T>(PhantomData<T>);

    crate::impl_interactive_argument! {
        prover impl<T> for GenericProver<T>
        where
            T: Copy,
        {
            fn protocol_id(&self) -> impl AsRef<[u8]> { b"macro-generic" }
            type Instance = T;
            type Witness = T;
            fn prove<C: ProverChannel<Unit = u8>>(
                &self, _: &mut C, _: &Self::Instance, _: &Self::Witness
            ) {}
        }
    }

    #[test]
    fn argument_roles_have_matching_public_shape() {
        fn check<
            P: ArgumentProverCore<Instance = u8, Witness = u16>,
            V: ArgumentCore<Instance = u8>,
        >(
            _: P,
            _: V,
        ) {
        }
        check(ArgProver, ArgVerifier);
    }

    #[test]
    fn argument_roles_keep_protocol_id() {
        assert_eq!(
            ArgProver.protocol_id().as_ref(),
            ArgVerifier.protocol_id().as_ref()
        );
    }

    #[test]
    fn reduction_roles_have_matching_public_shape() {
        fn check<
            P: ReductionProverCore<
                    SourceInstance = u8,
                    TargetInstance = u16,
                    SourceWitness = u32,
                    TargetWitness = u64,
                >,
            V: ReductionCore<SourceInstance = u8, TargetInstance = u16>,
        >(
            _: P,
            _: V,
        ) {
        }
        check(ReductionProver, ReductionVerifier);
    }

    #[test]
    fn argument_indexer_owns_public_shape_and_keys() {
        fn check<
            I: ArgumentCore<Instance = u8> + Indexer<Index = (), ProverKey = (), VerifierKey = ()>,
        >(
            _: I,
        ) {
        }
        check(ArgumentIndexer);
        assert!(ArgumentIndexer.preprocess_checked(&()).is_ok());
    }

    #[test]
    fn preprocessing_argument_roles_own_one_key_each() {
        fn check<
            P: PreprocessingInteractiveArgumentProver<Instance = u8, Witness = u16, ProverKey = ()>,
            V: PreprocessingInteractiveArgumentVerifier<Instance = u8, VerifierKey = ()>,
        >(
            _: P,
            _: V,
        ) {
        }
        check(IndexedArgumentProver, IndexedArgumentVerifier);
    }

    #[test]
    fn reduction_indexer_owns_public_shape_and_keys() {
        fn check<
            I: ReductionCore<SourceInstance = u8, TargetInstance = u16>
                + Indexer<Index = (), ProverKey = (), VerifierKey = ()>,
        >(
            _: I,
        ) {
        }
        check(ReductionIndexer);
    }

    #[test]
    fn preprocessing_reduction_roles_own_one_key_each() {
        fn check<
            P: PreprocessingInteractiveReductionProver<
                    SourceInstance = u8,
                    TargetInstance = u16,
                    SourceWitness = u32,
                    TargetWitness = u64,
                    ProverKey = (),
                >,
            V: PreprocessingInteractiveReductionVerifier<
                    SourceInstance = u8,
                    TargetInstance = u16,
                    VerifierKey = (),
                >,
        >(
            _: P,
            _: V,
        ) {
        }
        check(IndexedReductionProver, IndexedReductionVerifier);
    }

    #[test]
    fn macro_parser_accepts_generics_and_where_clauses() {
        fn check<P: ArgumentProverCore<Instance = u32, Witness = u32>>(_: P) {}
        check(GenericProver::<u32>(PhantomData));
    }

    #[test]
    fn indexer_exposes_no_execution_requirement() {
        fn accepts_indexer<I: Indexer>(_: &I) {}
        accepts_indexer(&ArgumentIndexer);
        accepts_indexer(&ReductionIndexer);
    }
}
