//! Authoring macros for the protocol trait hierarchy.

/// Implement a plain interactive argument using one author-facing impl block.
#[macro_export]
macro_rules! impl_interactive_argument {
    (impl $($rest:tt)*) => {
        $crate::__ia_core_parse_interactive_argument! { [] $($rest)* }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __ia_core_parse_interactive_argument {
    ([$($impl_generics:tt)*] InteractiveArgument for $ty:ty where $($tail:tt)*) => {
        $crate::__ia_core_parse_interactive_argument_where! {
            [$($impl_generics)*] [$ty] [] $($tail)*
        }
    };
    (
        [$($impl_generics:tt)*] InteractiveArgument for $ty:ty
        $(where $($where_clause:tt)+)?
        {
            $(#[$protocol_attr:meta])*
            fn protocol_id(&self) -> impl AsRef<[u8]> $protocol_body:block

            $(#[$instance_attr:meta])*
            type Instance = $instance:ty;

            $(#[$witness_attr:meta])*
            type Witness = $witness:ty;

            $($methods:tt)*
        }
    ) => {
        impl $($impl_generics)* $crate::ProtocolCore for $ty
        $(where $($where_clause)+)?
        {
            $(#[$protocol_attr])*
            fn protocol_id(&self) -> impl AsRef<[u8]> $protocol_body
        }

        impl $($impl_generics)* $crate::ArgumentCore for $ty
        $(where $($where_clause)+)?
        {
            $(#[$instance_attr])*
            type Instance = $instance;

            $(#[$witness_attr])*
            type Witness = $witness;
        }

        impl $($impl_generics)* $crate::InteractiveArgument for $ty
        $(where $($where_clause)+)?
        {
            $($methods)*
        }
    };
    ([$($impl_generics:tt)*] $next:tt $($rest:tt)*) => {
        $crate::__ia_core_parse_interactive_argument! {
            [$($impl_generics)* $next] $($rest)*
        }
    };
    ([$($impl_generics:tt)*]) => {
        compile_error!(
            "impl_interactive_argument! could not parse this block. Expected `impl ... InteractiveArgument for Type { fn protocol_id(&self) -> impl AsRef<[u8]> { ... } type Instance = ...; type Witness = ...; fn prove(...) { ... } fn verify(...) -> VerificationResult<()> { ... } }`."
        );
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __ia_core_parse_interactive_argument_where {
    (
        [$($impl_generics:tt)*] [$ty:ty] [$($where_clause:tt)*]
        {
            $(#[$protocol_attr:meta])*
            fn protocol_id(&self) -> impl AsRef<[u8]> $protocol_body:block

            $(#[$instance_attr:meta])*
            type Instance = $instance:ty;

            $(#[$witness_attr:meta])*
            type Witness = $witness:ty;

            $($methods:tt)*
        }
    ) => {
        impl $($impl_generics)* $crate::ProtocolCore for $ty
        where $($where_clause)*
        {
            $(#[$protocol_attr])*
            fn protocol_id(&self) -> impl AsRef<[u8]> $protocol_body
        }

        impl $($impl_generics)* $crate::ArgumentCore for $ty
        where $($where_clause)*
        {
            $(#[$instance_attr])*
            type Instance = $instance;

            $(#[$witness_attr])*
            type Witness = $witness;
        }

        impl $($impl_generics)* $crate::InteractiveArgument for $ty
        where $($where_clause)*
        {
            $($methods)*
        }
    };
    ([$($impl_generics:tt)*] [$ty:ty] [$($where_clause:tt)*] $next:tt $($rest:tt)*) => {
        $crate::__ia_core_parse_interactive_argument_where! {
            [$($impl_generics)*] [$ty] [$($where_clause)* $next] $($rest)*
        }
    };
    ([$($impl_generics:tt)*] [$ty:ty] [$($where_clause:tt)*]) => {
        compile_error!(
            "impl_interactive_argument! could not parse this block after the `where` clause. Put `fn protocol_id` first, followed by `type Instance`, `type Witness`, then `prove` and `verify`."
        );
    };
}

/// Implement a plain interactive reduction using one author-facing impl block.
#[macro_export]
macro_rules! impl_interactive_reduction {
    (impl $($rest:tt)*) => {
        $crate::__ia_core_parse_interactive_reduction! { [] $($rest)* }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __ia_core_parse_interactive_reduction {
    ([$($impl_generics:tt)*] InteractiveReduction for $ty:ty where $($tail:tt)*) => {
        $crate::__ia_core_parse_interactive_reduction_where! {
            [$($impl_generics)*] [$ty] [] $($tail)*
        }
    };
    (
        [$($impl_generics:tt)*] InteractiveReduction for $ty:ty
        $(where $($where_clause:tt)+)?
        {
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
        impl $($impl_generics)* $crate::ProtocolCore for $ty
        $(where $($where_clause)+)?
        {
            $(#[$protocol_attr])*
            fn protocol_id(&self) -> impl AsRef<[u8]> $protocol_body
        }

        impl $($impl_generics)* $crate::ReductionCore for $ty
        $(where $($where_clause)+)?
        {
            $(#[$source_instance_attr])*
            type SourceInstance = $source_instance;

            $(#[$target_instance_attr])*
            type TargetInstance = $target_instance;

            $(#[$source_witness_attr])*
            type SourceWitness = $source_witness;

            $(#[$target_witness_attr])*
            type TargetWitness = $target_witness;
        }

        impl $($impl_generics)* $crate::InteractiveReduction for $ty
        $(where $($where_clause)+)?
        {
            $($methods)*
        }
    };
    ([$($impl_generics:tt)*] $next:tt $($rest:tt)*) => {
        $crate::__ia_core_parse_interactive_reduction! {
            [$($impl_generics)* $next] $($rest)*
        }
    };
    ([$($impl_generics:tt)*]) => {
        compile_error!(
            "impl_interactive_reduction! could not parse this block. Expected `impl ... InteractiveReduction for Type { fn protocol_id(&self) -> impl AsRef<[u8]> { ... } type SourceInstance = ...; type TargetInstance = ...; type SourceWitness = ...; type TargetWitness = ...; fn prove(...) -> (...) { ... } fn verify(...) -> VerificationResult<_> { ... } }`."
        );
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __ia_core_parse_interactive_reduction_where {
    (
        [$($impl_generics:tt)*] [$ty:ty] [$($where_clause:tt)*]
        {
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
        impl $($impl_generics)* $crate::ProtocolCore for $ty
        where $($where_clause)*
        {
            $(#[$protocol_attr])*
            fn protocol_id(&self) -> impl AsRef<[u8]> $protocol_body
        }

        impl $($impl_generics)* $crate::ReductionCore for $ty
        where $($where_clause)*
        {
            $(#[$source_instance_attr])*
            type SourceInstance = $source_instance;

            $(#[$target_instance_attr])*
            type TargetInstance = $target_instance;

            $(#[$source_witness_attr])*
            type SourceWitness = $source_witness;

            $(#[$target_witness_attr])*
            type TargetWitness = $target_witness;
        }

        impl $($impl_generics)* $crate::InteractiveReduction for $ty
        where $($where_clause)*
        {
            $($methods)*
        }
    };
    ([$($impl_generics:tt)*] [$ty:ty] [$($where_clause:tt)*] $next:tt $($rest:tt)*) => {
        $crate::__ia_core_parse_interactive_reduction_where! {
            [$($impl_generics)*] [$ty] [$($where_clause)* $next] $($rest)*
        }
    };
    ([$($impl_generics:tt)*] [$ty:ty] [$($where_clause:tt)*]) => {
        compile_error!(
            "impl_interactive_reduction! could not parse this block after the `where` clause. Put `fn protocol_id` first, followed by source/target instance and witness types, then `prove` and `verify`."
        );
    };
}

/// Implement a preprocessing interactive argument using one author-facing impl block.
#[macro_export]
macro_rules! impl_preprocessing_argument {
    (impl $($rest:tt)*) => {
        $crate::__ia_core_parse_preprocessing_argument! { [] $($rest)* }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __ia_core_parse_preprocessing_argument {
    ([$($impl_generics:tt)*] IndexedInteractiveArgument for $ty:ty where $($tail:tt)*) => {
        compile_error!(
            "`IndexedInteractiveArgument` was renamed to `PreprocessingInteractiveArgument`. Use `impl_preprocessing_argument! { impl ... PreprocessingInteractiveArgument for Type { ... } }`."
        );
    };
    ([$($impl_generics:tt)*] IndexedInteractiveArgument for $ty:ty { $($body:tt)* }) => {
        compile_error!(
            "`IndexedInteractiveArgument` was renamed to `PreprocessingInteractiveArgument`. Use `impl_preprocessing_argument! { impl ... PreprocessingInteractiveArgument for Type { ... } }`."
        );
    };
    ([$($impl_generics:tt)*] PreprocessingInteractiveArgument for $ty:ty where $($tail:tt)*) => {
        $crate::__ia_core_parse_preprocessing_argument_where! {
            [$($impl_generics)*] [$ty] [] $($tail)*
        }
    };
    (
        [$($impl_generics:tt)*] PreprocessingInteractiveArgument for $ty:ty
        $(where $($where_clause:tt)+)?
        {
            $(#[$protocol_attr:meta])*
            fn protocol_id(&self) -> impl AsRef<[u8]> $protocol_body:block

            $(#[$instance_attr:meta])*
            type Instance = $instance:ty;

            $(#[$witness_attr:meta])*
            type Witness = $witness:ty;

            $(#[$index_attr:meta])*
            type Index = $index:ty;

            $(#[$prover_key_attr:meta])*
            type ProverKey = $prover_key:ty;

            $(#[$verifier_key_attr:meta])*
            type VerifierKey = $verifier_key:ty;

            $(#[$index_fn_attr:meta])*
            fn index(&self, $ix:ident: &Self::Index) -> (Self::ProverKey, Self::VerifierKey)
                $index_body:block

            $($methods:tt)*
        }
    ) => {
        impl $($impl_generics)* $crate::ProtocolCore for $ty
        $(where $($where_clause)+)?
        {
            $(#[$protocol_attr])*
            fn protocol_id(&self) -> impl AsRef<[u8]> $protocol_body
        }

        impl $($impl_generics)* $crate::ArgumentCore for $ty
        $(where $($where_clause)+)?
        {
            $(#[$instance_attr])*
            type Instance = $instance;

            $(#[$witness_attr])*
            type Witness = $witness;
        }

        impl $($impl_generics)* $crate::PreprocessingCore for $ty
        $(where $($where_clause)+)?
        {
            $(#[$index_attr])*
            type Index = $index;

            $(#[$prover_key_attr])*
            type ProverKey = $prover_key;

            $(#[$verifier_key_attr])*
            type VerifierKey = $verifier_key;

            $(#[$index_fn_attr])*
            fn index(&self, $ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey)
                $index_body
        }

        impl $($impl_generics)* $crate::PreprocessingInteractiveArgument for $ty
        $(where $($where_clause)+)?
        {
            $($methods)*
        }
    };
    ([$($impl_generics:tt)*] $next:tt $($rest:tt)*) => {
        $crate::__ia_core_parse_preprocessing_argument! {
            [$($impl_generics)* $next] $($rest)*
        }
    };
    ([$($impl_generics:tt)*]) => {
        compile_error!(
            "impl_preprocessing_argument! could not parse this block. Expected `impl ... PreprocessingInteractiveArgument for Type { fn protocol_id(...) { ... } type Instance = ...; type Witness = ...; type Index = ...; type ProverKey = ...; type VerifierKey = ...; fn index(...) -> (...) { ... } fn prove(...) { ... } fn verify(...) -> VerificationResult<()> { ... } }`."
        );
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __ia_core_parse_preprocessing_argument_where {
    (
        [$($impl_generics:tt)*] [$ty:ty] [$($where_clause:tt)*]
        {
            $(#[$protocol_attr:meta])*
            fn protocol_id(&self) -> impl AsRef<[u8]> $protocol_body:block

            $(#[$instance_attr:meta])*
            type Instance = $instance:ty;

            $(#[$witness_attr:meta])*
            type Witness = $witness:ty;

            $(#[$index_attr:meta])*
            type Index = $index:ty;

            $(#[$prover_key_attr:meta])*
            type ProverKey = $prover_key:ty;

            $(#[$verifier_key_attr:meta])*
            type VerifierKey = $verifier_key:ty;

            $(#[$index_fn_attr:meta])*
            fn index(&self, $ix:ident: &Self::Index) -> (Self::ProverKey, Self::VerifierKey)
                $index_body:block

            $($methods:tt)*
        }
    ) => {
        impl $($impl_generics)* $crate::ProtocolCore for $ty
        where $($where_clause)*
        {
            $(#[$protocol_attr])*
            fn protocol_id(&self) -> impl AsRef<[u8]> $protocol_body
        }

        impl $($impl_generics)* $crate::ArgumentCore for $ty
        where $($where_clause)*
        {
            $(#[$instance_attr])*
            type Instance = $instance;

            $(#[$witness_attr])*
            type Witness = $witness;
        }

        impl $($impl_generics)* $crate::PreprocessingCore for $ty
        where $($where_clause)*
        {
            $(#[$index_attr])*
            type Index = $index;

            $(#[$prover_key_attr])*
            type ProverKey = $prover_key;

            $(#[$verifier_key_attr])*
            type VerifierKey = $verifier_key;

            $(#[$index_fn_attr])*
            fn index(&self, $ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey)
                $index_body
        }

        impl $($impl_generics)* $crate::PreprocessingInteractiveArgument for $ty
        where $($where_clause)*
        {
            $($methods)*
        }
    };
    ([$($impl_generics:tt)*] [$ty:ty] [$($where_clause:tt)*] $next:tt $($rest:tt)*) => {
        $crate::__ia_core_parse_preprocessing_argument_where! {
            [$($impl_generics)*] [$ty] [$($where_clause)* $next] $($rest)*
        }
    };
    ([$($impl_generics:tt)*] [$ty:ty] [$($where_clause:tt)*]) => {
        compile_error!(
            "impl_preprocessing_argument! could not parse this block after the `where` clause. Put `fn protocol_id` first, then `Instance`/`Witness`, preprocessing key types, `index`, `prove`, and `verify`."
        );
    };
}

/// Implement a preprocessing interactive reduction using one author-facing impl block.
#[macro_export]
macro_rules! impl_preprocessing_reduction {
    (impl $($rest:tt)*) => {
        $crate::__ia_core_parse_preprocessing_reduction! { [] $($rest)* }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __ia_core_parse_preprocessing_reduction {
    ([$($impl_generics:tt)*] IndexedInteractiveReduction for $ty:ty where $($tail:tt)*) => {
        compile_error!(
            "`IndexedInteractiveReduction` was renamed to `PreprocessingInteractiveReduction`. Use `impl_preprocessing_reduction! { impl ... PreprocessingInteractiveReduction for Type { ... } }`."
        );
    };
    ([$($impl_generics:tt)*] IndexedInteractiveReduction for $ty:ty { $($body:tt)* }) => {
        compile_error!(
            "`IndexedInteractiveReduction` was renamed to `PreprocessingInteractiveReduction`. Use `impl_preprocessing_reduction! { impl ... PreprocessingInteractiveReduction for Type { ... } }`."
        );
    };
    ([$($impl_generics:tt)*] PreprocessingInteractiveReduction for $ty:ty where $($tail:tt)*) => {
        $crate::__ia_core_parse_preprocessing_reduction_where! {
            [$($impl_generics)*] [$ty] [] $($tail)*
        }
    };
    (
        [$($impl_generics:tt)*] PreprocessingInteractiveReduction for $ty:ty
        $(where $($where_clause:tt)+)?
        {
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

            $(#[$index_attr:meta])*
            type Index = $index:ty;

            $(#[$prover_key_attr:meta])*
            type ProverKey = $prover_key:ty;

            $(#[$verifier_key_attr:meta])*
            type VerifierKey = $verifier_key:ty;

            $(#[$index_fn_attr:meta])*
            fn index(&self, $ix:ident: &Self::Index) -> (Self::ProverKey, Self::VerifierKey)
                $index_body:block

            $($methods:tt)*
        }
    ) => {
        impl $($impl_generics)* $crate::ProtocolCore for $ty
        $(where $($where_clause)+)?
        {
            $(#[$protocol_attr])*
            fn protocol_id(&self) -> impl AsRef<[u8]> $protocol_body
        }

        impl $($impl_generics)* $crate::ReductionCore for $ty
        $(where $($where_clause)+)?
        {
            $(#[$source_instance_attr])*
            type SourceInstance = $source_instance;

            $(#[$target_instance_attr])*
            type TargetInstance = $target_instance;

            $(#[$source_witness_attr])*
            type SourceWitness = $source_witness;

            $(#[$target_witness_attr])*
            type TargetWitness = $target_witness;
        }

        impl $($impl_generics)* $crate::PreprocessingCore for $ty
        $(where $($where_clause)+)?
        {
            $(#[$index_attr])*
            type Index = $index;

            $(#[$prover_key_attr])*
            type ProverKey = $prover_key;

            $(#[$verifier_key_attr])*
            type VerifierKey = $verifier_key;

            $(#[$index_fn_attr])*
            fn index(&self, $ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey)
                $index_body
        }

        impl $($impl_generics)* $crate::PreprocessingInteractiveReduction for $ty
        $(where $($where_clause)+)?
        {
            $($methods)*
        }
    };
    ([$($impl_generics:tt)*] $next:tt $($rest:tt)*) => {
        $crate::__ia_core_parse_preprocessing_reduction! {
            [$($impl_generics)* $next] $($rest)*
        }
    };
    ([$($impl_generics:tt)*]) => {
        compile_error!(
            "impl_preprocessing_reduction! could not parse this block. Expected `impl ... PreprocessingInteractiveReduction for Type { fn protocol_id(...) { ... } type SourceInstance = ...; type TargetInstance = ...; type SourceWitness = ...; type TargetWitness = ...; type Index = ...; type ProverKey = ...; type VerifierKey = ...; fn index(...) -> (...) { ... } fn prove(...) -> (...) { ... } fn verify(...) -> VerificationResult<_> { ... } }`."
        );
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __ia_core_parse_preprocessing_reduction_where {
    (
        [$($impl_generics:tt)*] [$ty:ty] [$($where_clause:tt)*]
        {
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

            $(#[$index_attr:meta])*
            type Index = $index:ty;

            $(#[$prover_key_attr:meta])*
            type ProverKey = $prover_key:ty;

            $(#[$verifier_key_attr:meta])*
            type VerifierKey = $verifier_key:ty;

            $(#[$index_fn_attr:meta])*
            fn index(&self, $ix:ident: &Self::Index) -> (Self::ProverKey, Self::VerifierKey)
                $index_body:block

            $($methods:tt)*
        }
    ) => {
        impl $($impl_generics)* $crate::ProtocolCore for $ty
        where $($where_clause)*
        {
            $(#[$protocol_attr])*
            fn protocol_id(&self) -> impl AsRef<[u8]> $protocol_body
        }

        impl $($impl_generics)* $crate::ReductionCore for $ty
        where $($where_clause)*
        {
            $(#[$source_instance_attr])*
            type SourceInstance = $source_instance;

            $(#[$target_instance_attr])*
            type TargetInstance = $target_instance;

            $(#[$source_witness_attr])*
            type SourceWitness = $source_witness;

            $(#[$target_witness_attr])*
            type TargetWitness = $target_witness;
        }

        impl $($impl_generics)* $crate::PreprocessingCore for $ty
        where $($where_clause)*
        {
            $(#[$index_attr])*
            type Index = $index;

            $(#[$prover_key_attr])*
            type ProverKey = $prover_key;

            $(#[$verifier_key_attr])*
            type VerifierKey = $verifier_key;

            $(#[$index_fn_attr])*
            fn index(&self, $ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey)
                $index_body
        }

        impl $($impl_generics)* $crate::PreprocessingInteractiveReduction for $ty
        where $($where_clause)*
        {
            $($methods)*
        }
    };
    ([$($impl_generics:tt)*] [$ty:ty] [$($where_clause:tt)*] $next:tt $($rest:tt)*) => {
        $crate::__ia_core_parse_preprocessing_reduction_where! {
            [$($impl_generics)*] [$ty] [$($where_clause)* $next] $($rest)*
        }
    };
    ([$($impl_generics:tt)*] [$ty:ty] [$($where_clause:tt)*]) => {
        compile_error!(
            "impl_preprocessing_reduction! could not parse this block after the `where` clause. Put `fn protocol_id` first, then source/target instance and witness types, preprocessing key types, `index`, `prove`, and `verify`."
        );
    };
}

#[cfg(test)]
mod tests {
    use crate::{
        CommittedIndexBytes, Decoding, Encoding, InteractiveArgument, InteractiveReduction,
        NargSerialize, PreprocessingCore, PreprocessingInteractiveArgument, ProverChannel,
        ReducedArgument, VerificationError, VerificationResult, VerifierChannel,
        VerifierKeyCommitment, pad_protocol_id,
    };
    use alloc::vec::Vec;
    use core::marker::PhantomData;

    #[derive(Default)]
    struct TestProver {
        proof: Vec<u8>,
    }

    impl ProverChannel for TestProver {
        fn send_prover_message<PM: Encoding<[u8]> + NargSerialize>(&mut self, msg: &PM) {
            msg.serialize_into_narg(&mut self.proof);
        }

        fn read_verifier_message<VM: Decoding<[u8]>>(&mut self) -> VM {
            VM::decode(Default::default())
        }
    }

    struct TestVerifier<'a> {
        proof: &'a [u8],
    }

    impl VerifierChannel for TestVerifier<'_> {
        fn read_prover_message<PM: Encoding<[u8]> + crate::Deserialize>(
            &mut self,
        ) -> VerificationResult<PM> {
            PM::deserialize(&mut self.proof)
        }

        fn send_verifier_message<VM: Decoding<[u8]>>(&mut self) -> VM {
            VM::decode(Default::default())
        }
    }

    struct MacroArg<const OFFSET: u32>;

    crate::impl_interactive_argument! {
        impl<const OFFSET: u32> InteractiveArgument for MacroArg<OFFSET> {
            fn protocol_id(&self) -> impl AsRef<[u8]> {
                pad_protocol_id(b"macro-arg")
            }

            type Instance = u32;
            type Witness = u32;

            #[allow(non_snake_case)]
            fn prove<P: ProverChannel>(
                &self,
                ch: &mut P,
                x: &Self::Instance,
                w: &Self::Witness,
            ) {
                let M = *x + *w + OFFSET;
                ch.send_prover_message(&M);
            }

            fn verify<V: VerifierChannel>(
                &self,
                ch: &mut V,
                x: &Self::Instance,
            ) -> VerificationResult<()> {
                let m: u32 = ch.read_prover_message()?;
                if m >= *x { Ok(()) } else { Err(VerificationError) }
            }
        }
    }

    #[test]
    fn plain_argument_macro_runs_through_channel() {
        let ia = MacroArg::<2>;
        let mut prover = TestProver::default();
        ia.prove(&mut prover, &3, &4);
        let mut verifier = TestVerifier {
            proof: &prover.proof,
        };
        ia.verify(&mut verifier, &3).expect("macro IA verifies");
        assert!(verifier.proof.is_empty());
    }

    struct MacroReduction;

    crate::impl_interactive_reduction! {
        impl InteractiveReduction for MacroReduction {
            fn protocol_id(&self) -> impl AsRef<[u8]> {
                pad_protocol_id(b"macro-red")
            }

            type SourceInstance = u8;
            type TargetInstance = u8;
            type SourceWitness = u8;
            type TargetWitness = u8;

            fn prove<P: ProverChannel>(
                &self,
                _ch: &mut P,
                instance: &Self::SourceInstance,
                witness: &Self::SourceWitness,
            ) -> (Self::TargetInstance, Self::TargetWitness) {
                (instance + 1, witness + 1)
            }

            fn verify<V: VerifierChannel>(
                &self,
                _ch: &mut V,
                instance: &Self::SourceInstance,
            ) -> VerificationResult<Self::TargetInstance> {
                Ok(instance + 1)
            }
        }
    }

    #[test]
    fn plain_reduction_macro_returns_target() {
        let red = MacroReduction;
        let mut prover = TestProver::default();
        assert_eq!(red.prove(&mut prover, &10, &20), (11, 21));
        let mut verifier = TestVerifier { proof: &[] };
        assert_eq!(red.verify(&mut verifier, &10).expect("valid"), 11);
    }

    #[derive(Clone, PartialEq, Eq)]
    struct Vk(u32);

    impl VerifierKeyCommitment for Vk {
        fn committed_index(&self) -> CommittedIndexBytes {
            CommittedIndexBytes::new(alloc::vec![self.0 as u8])
        }
    }

    struct MacroPreArg;

    crate::impl_preprocessing_argument! {
        impl PreprocessingInteractiveArgument for MacroPreArg {
            fn protocol_id(&self) -> impl AsRef<[u8]> {
                pad_protocol_id(b"macro-pre-arg")
            }

            type Instance = u32;
            type Witness = u32;
            type Index = u32;
            type ProverKey = u32;
            type VerifierKey = Vk;

            fn index(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
                (*ix, Vk(*ix))
            }

            fn prove<P: ProverChannel>(
                &self,
                ch: &mut P,
                pk: &Self::ProverKey,
                instance: &Self::Instance,
                witness: &Self::Witness,
            ) {
                ch.send_prover_message(&(*pk + *instance + *witness));
            }

            fn verify<V: VerifierChannel>(
                &self,
                ch: &mut V,
                vk: &Self::VerifierKey,
                instance: &Self::Instance,
            ) -> VerificationResult<()> {
                let msg: u32 = ch.read_prover_message()?;
                if msg >= vk.0 + *instance { Ok(()) } else { Err(VerificationError) }
            }
        }
    }

    #[test]
    fn preprocessing_argument_macro_emits_keyed_prove_verify() {
        // The macro should emit PreprocessingCore (index) plus keyed prove/verify.
        let body = MacroPreArg;
        let (pk, vk) = body.index(&7u32);
        let mut prover = TestProver::default();
        body.prove(&mut prover, &pk, &2u32, &3u32);
        let mut verifier = TestVerifier {
            proof: &prover.proof,
        };
        body.verify(&mut verifier, &vk, &2u32)
            .expect("macro preprocessing IA verifies through the channel");
    }

    struct MacroPreReduction;

    crate::impl_preprocessing_reduction! {
        impl PreprocessingInteractiveReduction for MacroPreReduction {
            fn protocol_id(&self) -> impl AsRef<[u8]> {
                pad_protocol_id(b"macro-pre-red")
            }

            type SourceInstance = u32;
            type TargetInstance = u32;
            type SourceWitness = u32;
            type TargetWitness = u32;
            type Index = u32;
            type ProverKey = u32;
            type VerifierKey = Vk;

            fn index(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
                (*ix, Vk(*ix))
            }

            fn prove<P: ProverChannel>(
                &self,
                _ch: &mut P,
                pk: &Self::ProverKey,
                instance: &Self::SourceInstance,
                witness: &Self::SourceWitness,
            ) -> (Self::TargetInstance, Self::TargetWitness) {
                (instance + pk, witness + pk)
            }

            fn verify<V: VerifierChannel>(
                &self,
                _ch: &mut V,
                vk: &Self::VerifierKey,
                instance: &Self::SourceInstance,
            ) -> VerificationResult<Self::TargetInstance> {
                Ok(instance + vk.0)
            }
        }
    }

    #[test]
    fn preprocessing_reduction_macro_composes_with_preprocessing_argument() {
        let composed = ReducedArgument::new(MacroPreReduction, MacroPreArg);
        let (pk, vk) = composed.index(&(5, 5));
        let mut prover = TestProver::default();
        composed.prove(&mut prover, &pk, &1, &2);
        let mut verifier = TestVerifier {
            proof: &prover.proof,
        };
        composed
            .verify(&mut verifier, &vk, &1)
            .expect("composed preprocessing macro protocol verifies");
    }

    trait Marker {}
    impl Marker for u8 {}

    struct GenericMacroArg<T, const N: usize>(PhantomData<T>);

    crate::impl_interactive_argument! {
        impl<T, const N: usize> InteractiveArgument for GenericMacroArg<T, N>
        where
            T: Marker,
        {
            fn protocol_id(&self) -> impl AsRef<[u8]> {
                pad_protocol_id(b"generic-macro")
            }

            type Instance = u8;
            type Witness = u8;

            fn prove<P: ProverChannel>(
                &self,
                _ch: &mut P,
                _instance: &Self::Instance,
                _witness: &Self::Witness,
            ) {
                let _ = N;
            }

            fn verify<V: VerifierChannel>(
                &self,
                _ch: &mut V,
                _instance: &Self::Instance,
            ) -> VerificationResult<()> {
                Ok(())
            }
        }
    }

    #[test]
    fn macro_supports_generics_const_generics_and_where_clauses() {
        let arg = GenericMacroArg::<u8, 4>(PhantomData);
        let mut prover = TestProver::default();
        arg.prove(&mut prover, &0, &0);
        let mut verifier = TestVerifier { proof: &[] };
        arg.verify(&mut verifier, &0).expect("generic macro IA");
    }
}
