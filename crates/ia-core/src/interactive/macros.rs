//! Protocol authoring macros for paired and role-specific implementations.

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

#[doc(hidden)]
#[macro_export]
macro_rules! __ia_core_parse_role_pair {
    (
        [$emit:ident] [$($generics:tt)*]
        {
            prover: $prover:ty,
            verifier: $verifier:ty $(,)?
        }
        where $($tail:tt)*
    ) => {
        $crate::__ia_core_parse_role_pair_where!(
            [$emit] [$($generics)*] [$prover] [$verifier] [] $($tail)*
        );
    };
    (
        [$emit:ident] [$($generics:tt)*]
        {
            prover: $prover:ty,
            verifier: $verifier:ty $(,)?
        }
        { $($body:tt)* }
    ) => {
        $crate::$emit!([$($generics)*] [$prover] [$verifier] [] { $($body)* });
    };
    ([$emit:ident] [$($generics:tt)*] $next:tt $($rest:tt)*) => {
        $crate::__ia_core_parse_role_pair!([$emit] [$($generics)* $next] $($rest)*);
    };
    ([$emit:ident] [$($generics:tt)*]) => {
        compile_error!(
            "could not parse paired roles; expected `impl<...> { prover: ProverType, verifier: VerifierType } where ... { ... }`"
        );
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __ia_core_parse_role_pair_where {
    (
        [$emit:ident] [$($generics:tt)*] [$prover:ty] [$verifier:ty]
        [$($where_clause:tt)*] { $($body:tt)* }
    ) => {
        $crate::$emit!(
            [$($generics)*] [$prover] [$verifier] [$($where_clause)*] { $($body)* }
        );
    };
    (
        [$emit:ident] [$($generics:tt)*] [$prover:ty] [$verifier:ty]
        [$($where_clause:tt)*] $next:tt $($rest:tt)*
    ) => {
        $crate::__ia_core_parse_role_pair_where!(
            [$emit] [$($generics)*] [$prover] [$verifier]
            [$($where_clause)* $next] $($rest)*
        );
    };
    (
        [$emit:ident] [$($generics:tt)*] [$prover:ty] [$verifier:ty]
        [$($where_clause:tt)*]
    ) => {
        compile_error!("paired role declaration is missing its implementation body");
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __ia_core_parse_role_triple {
    (
        [$emit:ident] [$($generics:tt)*]
        {
            indexer: $indexer:ty,
            prover: $prover:ty,
            verifier: $verifier:ty $(,)?
        }
        where $($tail:tt)*
    ) => {
        $crate::__ia_core_parse_role_triple_where!(
            [$emit] [$($generics)*] [$indexer] [$prover] [$verifier] [] $($tail)*
        );
    };
    (
        [$emit:ident] [$($generics:tt)*]
        {
            indexer: $indexer:ty,
            prover: $prover:ty,
            verifier: $verifier:ty $(,)?
        }
        { $($body:tt)* }
    ) => {
        $crate::$emit!(
            [$($generics)*] [$indexer] [$prover] [$verifier] [] { $($body)* }
        );
    };
    ([$emit:ident] [$($generics:tt)*] $next:tt $($rest:tt)*) => {
        $crate::__ia_core_parse_role_triple!([$emit] [$($generics)* $next] $($rest)*);
    };
    ([$emit:ident] [$($generics:tt)*]) => {
        compile_error!(
            "could not parse preprocessing roles; expected `impl<...> { indexer: IndexerType, prover: ProverType, verifier: VerifierType } where ... { ... }`"
        );
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __ia_core_parse_role_triple_where {
    (
        [$emit:ident] [$($generics:tt)*] [$indexer:ty] [$prover:ty] [$verifier:ty]
        [$($where_clause:tt)*] { $($body:tt)* }
    ) => {
        $crate::$emit!(
            [$($generics)*] [$indexer] [$prover] [$verifier]
            [$($where_clause)*] { $($body)* }
        );
    };
    (
        [$emit:ident] [$($generics:tt)*] [$indexer:ty] [$prover:ty] [$verifier:ty]
        [$($where_clause:tt)*] $next:tt $($rest:tt)*
    ) => {
        $crate::__ia_core_parse_role_triple_where!(
            [$emit] [$($generics)*] [$indexer] [$prover] [$verifier]
            [$($where_clause)* $next] $($rest)*
        );
    };
    (
        [$emit:ident] [$($generics:tt)*] [$indexer:ty] [$prover:ty] [$verifier:ty]
        [$($where_clause:tt)*]
    ) => {
        compile_error!("preprocessing role declaration is missing its implementation body");
    };
}

/// Implement both native roles of a plain interactive argument.
#[macro_export]
macro_rules! impl_interactive_argument {
    (impl $($rest:tt)*) => {
        $crate::__ia_core_parse_role_pair!([__ia_core_emit_argument_pair] [] $($rest)*);
    };
    ($($invalid:tt)*) => {
        compile_error!(
            "expected `impl_interactive_argument! { impl<...> { prover: ProverType, verifier: VerifierType } where ... { ... } }`"
        );
    };
}

/// Implement the prover role of a plain interactive argument.
#[macro_export]
macro_rules! impl_interactive_argument_prover {
    (impl $($rest:tt)*) => {
        $crate::__ia_core_parse_role!([__ia_core_emit_argument_prover] [] $($rest)*);
    };
    ($($invalid:tt)*) => {
        compile_error!(
            "expected `impl_interactive_argument_prover! { impl<...> for ProverType where ... { ... } }`"
        );
    };
}

/// Implement the verifier role of a plain interactive argument.
#[macro_export]
macro_rules! impl_interactive_argument_verifier {
    (impl $($rest:tt)*) => {
        $crate::__ia_core_parse_role!([__ia_core_emit_argument_verifier] [] $($rest)*);
    };
    ($($invalid:tt)*) => {
        compile_error!(
            "expected `impl_interactive_argument_verifier! { impl<...> for VerifierType where ... { ... } }`"
        );
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

#[doc(hidden)]
#[macro_export]
macro_rules! __ia_core_emit_argument_pair {
    (
        [$($generics:tt)*] [$prover:ty] [$verifier:ty] [$($where_clause:tt)*] {
            $(#[$protocol_attr:meta])*
            fn protocol_id(&self) -> impl AsRef<[u8]> $protocol_body:block
            $(#[$instance_attr:meta])*
            type Instance = $instance:ty;
            $(#[$witness_attr:meta])*
            type Witness = $witness:ty;
            $($methods:tt)*
        }
    ) => {
        $crate::__ia_core_split_argument_methods!(
            [$($generics)*] [$prover] [$verifier] [$($where_clause)*]
            [
                $(#[$protocol_attr])*
                fn protocol_id(&self) -> impl AsRef<[u8]> $protocol_body
            ]
            [
                $(#[$instance_attr])*
                type Instance = $instance;
            ]
            [
                $(#[$witness_attr])*
                type Witness = $witness;
            ]
            []
            $($methods)*
        );
    };
    ($($invalid:tt)*) => {
        compile_error!(
            "paired interactive argument body must contain `protocol_id`, `Instance`, `Witness`, `prove`, then `verify`"
        );
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __ia_core_split_argument_methods {
    (
        [$($generics:tt)*] [$prover:ty] [$verifier:ty] [$($where_clause:tt)*]
        [$($protocol:tt)*] [$($instance:tt)*] [$($witness:tt)*]
        [$($prove:tt)*]
        $(#[$verify_attr:meta])* fn verify $($verify_tail:tt)*
    ) => {
        $crate::__ia_core_emit_argument_prover!(
            [$($generics)*] [$prover] [$($where_clause)*] {
                $($protocol)* $($instance)* $($witness)* $($prove)*
            }
        );
        $crate::__ia_core_emit_argument_verifier!(
            [$($generics)*] [$verifier] [$($where_clause)*] {
                $($protocol)* $($instance)*
                $(#[$verify_attr])* fn verify $($verify_tail)*
            }
        );
    };
    (
        [$($generics:tt)*] [$prover:ty] [$verifier:ty] [$($where_clause:tt)*]
        [$($protocol:tt)*] [$($instance:tt)*] [$($witness:tt)*]
        [$($prove:tt)*] $next:tt $($rest:tt)*
    ) => {
        $crate::__ia_core_split_argument_methods!(
            [$($generics)*] [$prover] [$verifier] [$($where_clause)*]
            [$($protocol)*] [$($instance)*] [$($witness)*]
            [$($prove)* $next] $($rest)*
        );
    };
    (
        [$($generics:tt)*] [$prover:ty] [$verifier:ty] [$($where_clause:tt)*]
        [$($protocol:tt)*] [$($instance:tt)*] [$($witness:tt)*] [$($prove:tt)*]
    ) => {
        compile_error!("paired interactive argument body is missing `fn verify`");
    };
}

/// Implement both native roles of a plain interactive reduction.
#[macro_export]
macro_rules! impl_interactive_reduction {
    (impl $($rest:tt)*) => {
        $crate::__ia_core_parse_role_pair!([__ia_core_emit_reduction_pair] [] $($rest)*);
    };
    ($($invalid:tt)*) => {
        compile_error!(
            "expected `impl_interactive_reduction! { impl<...> { prover: ProverType, verifier: VerifierType } where ... { ... } }`"
        );
    };
}

/// Implement the prover role of a plain interactive reduction.
#[macro_export]
macro_rules! impl_interactive_reduction_prover {
    (impl $($rest:tt)*) => {
        $crate::__ia_core_parse_role!([__ia_core_emit_reduction_prover] [] $($rest)*);
    };
    ($($invalid:tt)*) => {
        compile_error!(
            "expected `impl_interactive_reduction_prover! { impl<...> for ProverType where ... { ... } }`"
        );
    };
}

/// Implement the verifier role of a plain interactive reduction.
#[macro_export]
macro_rules! impl_interactive_reduction_verifier {
    (impl $($rest:tt)*) => {
        $crate::__ia_core_parse_role!([__ia_core_emit_reduction_verifier] [] $($rest)*);
    };
    ($($invalid:tt)*) => {
        compile_error!(
            "expected `impl_interactive_reduction_verifier! { impl<...> for VerifierType where ... { ... } }`"
        );
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

#[doc(hidden)]
#[macro_export]
macro_rules! __ia_core_emit_reduction_pair {
    (
        [$($generics:tt)*] [$prover:ty] [$verifier:ty] [$($where_clause:tt)*] {
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
        $crate::__ia_core_split_reduction_methods!(
            [$($generics)*] [$prover] [$verifier] [$($where_clause)*]
            [
                $(#[$protocol_attr])*
                fn protocol_id(&self) -> impl AsRef<[u8]> $protocol_body
            ]
            [
                $(#[$source_instance_attr])*
                type SourceInstance = $source_instance;
                $(#[$target_instance_attr])*
                type TargetInstance = $target_instance;
            ]
            [
                $(#[$source_witness_attr])*
                type SourceWitness = $source_witness;
                $(#[$target_witness_attr])*
                type TargetWitness = $target_witness;
            ]
            []
            $($methods)*
        );
    };
    ($($invalid:tt)*) => {
        compile_error!(
            "paired interactive reduction body must contain `protocol_id`, source/target instances, source/target witnesses, `prove`, then `verify`"
        );
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __ia_core_split_reduction_methods {
    (
        [$($generics:tt)*] [$prover:ty] [$verifier:ty] [$($where_clause:tt)*]
        [$($protocol:tt)*] [$($instances:tt)*] [$($witnesses:tt)*]
        [$($prove:tt)*]
        $(#[$verify_attr:meta])* fn verify $($verify_tail:tt)*
    ) => {
        $crate::__ia_core_emit_reduction_prover!(
            [$($generics)*] [$prover] [$($where_clause)*] {
                $($protocol)* $($instances)* $($witnesses)* $($prove)*
            }
        );
        $crate::__ia_core_emit_reduction_verifier!(
            [$($generics)*] [$verifier] [$($where_clause)*] {
                $($protocol)* $($instances)*
                $(#[$verify_attr])* fn verify $($verify_tail)*
            }
        );
    };
    (
        [$($generics:tt)*] [$prover:ty] [$verifier:ty] [$($where_clause:tt)*]
        [$($protocol:tt)*] [$($instances:tt)*] [$($witnesses:tt)*]
        [$($prove:tt)*] $next:tt $($rest:tt)*
    ) => {
        $crate::__ia_core_split_reduction_methods!(
            [$($generics)*] [$prover] [$verifier] [$($where_clause)*]
            [$($protocol)*] [$($instances)*] [$($witnesses)*]
            [$($prove)* $next] $($rest)*
        );
    };
    (
        [$($generics:tt)*] [$prover:ty] [$verifier:ty] [$($where_clause:tt)*]
        [$($protocol:tt)*] [$($instances:tt)*] [$($witnesses:tt)*] [$($prove:tt)*]
    ) => {
        compile_error!("paired interactive reduction body is missing `fn verify`");
    };
}

/// Implement all three native roles of a preprocessing interactive argument.
#[macro_export]
macro_rules! impl_preprocessing_argument {
    (impl $($rest:tt)*) => {
        $crate::__ia_core_parse_role_triple!(
            [__ia_core_emit_preprocessing_argument_triple] [] $($rest)*
        );
    };
    ($($invalid:tt)*) => {
        compile_error!(
            "expected `impl_preprocessing_argument! { impl<...> { indexer: IndexerType, prover: ProverType, verifier: VerifierType } where ... { ... } }`"
        );
    };
}

/// Implement the indexer role of a preprocessing interactive argument.
#[macro_export]
macro_rules! impl_preprocessing_argument_indexer {
    (impl $($rest:tt)*) => {
        $crate::__ia_core_parse_role!([__ia_core_emit_argument_indexer] [] $($rest)*);
    };
    ($($invalid:tt)*) => {
        compile_error!(
            "expected `impl_preprocessing_argument_indexer! { impl<...> for IndexerType where ... { ... } }`"
        );
    };
}

/// Implement the prover role of a preprocessing interactive argument.
#[macro_export]
macro_rules! impl_preprocessing_argument_prover {
    (impl $($rest:tt)*) => {
        $crate::__ia_core_parse_role!([__ia_core_emit_preprocessing_argument_prover] [] $($rest)*);
    };
    ($($invalid:tt)*) => {
        compile_error!(
            "expected `impl_preprocessing_argument_prover! { impl<...> for ProverType where ... { ... } }`"
        );
    };
}

/// Implement the verifier role of a preprocessing interactive argument.
#[macro_export]
macro_rules! impl_preprocessing_argument_verifier {
    (impl $($rest:tt)*) => {
        $crate::__ia_core_parse_role!([__ia_core_emit_preprocessing_argument_verifier] [] $($rest)*);
    };
    ($($invalid:tt)*) => {
        compile_error!(
            "expected `impl_preprocessing_argument_verifier! { impl<...> for VerifierType where ... { ... } }`"
        );
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

#[doc(hidden)]
#[macro_export]
macro_rules! __ia_core_emit_preprocessing_argument_triple {
    (
        [$($generics:tt)*] [$indexer:ty] [$prover:ty] [$verifier:ty]
        [$($where_clause:tt)*] {
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
            $($methods:tt)*
        }
    ) => {
        $crate::__ia_core_split_preprocessing_argument_indexer!(
            [$($generics)*] [$indexer] [$prover] [$verifier] [$($where_clause)*]
            [
                $(#[$protocol_attr])*
                fn protocol_id(&self) -> impl AsRef<[u8]> $protocol_body
            ]
            [
                $(#[$instance_attr])*
                type Instance = $instance;
            ]
            [
                $(#[$witness_attr])*
                type Witness = $witness;
            ]
            [
                $(#[$index_attr])*
                type Index = $index;
                $(#[$prover_key_attr])*
                type ProverKey = $prover_key;
                $(#[$verifier_key_attr])*
                type VerifierKey = $verifier_key;
            ]
            [$(#[$prover_key_attr])* type ProverKey = $prover_key;]
            [$(#[$verifier_key_attr])* type VerifierKey = $verifier_key;]
            []
            $($methods)*
        );
    };
    ($($invalid:tt)*) => {
        compile_error!(
            "preprocessing argument body must contain `protocol_id`, `Instance`, `Witness`, `Index`, both key types, `preprocess`, `prove`, then `verify`"
        );
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __ia_core_split_preprocessing_argument_indexer {
    (
        [$($generics:tt)*] [$indexer:ty] [$prover:ty] [$verifier:ty]
        [$($where_clause:tt)*] [$($protocol:tt)*] [$($instance:tt)*]
        [$($witness:tt)*] [$($index_types:tt)*] [$($prover_key:tt)*]
        [$($verifier_key:tt)*] [$($preprocess:tt)*]
        $(#[$prove_attr:meta])* fn prove $($prove_tail:tt)*
    ) => {
        $crate::__ia_core_split_preprocessing_argument_prover!(
            [$($generics)*] [$indexer] [$prover] [$verifier] [$($where_clause)*]
            [$($protocol)*] [$($instance)*] [$($witness)*] [$($index_types)*]
            [$($prover_key)*] [$($verifier_key)*] [$($preprocess)*]
            [$(#[$prove_attr])* fn prove] $($prove_tail)*
        );
    };
    (
        [$($generics:tt)*] [$indexer:ty] [$prover:ty] [$verifier:ty]
        [$($where_clause:tt)*] [$($protocol:tt)*] [$($instance:tt)*]
        [$($witness:tt)*] [$($index_types:tt)*] [$($prover_key:tt)*]
        [$($verifier_key:tt)*] [$($preprocess:tt)*] $next:tt $($rest:tt)*
    ) => {
        $crate::__ia_core_split_preprocessing_argument_indexer!(
            [$($generics)*] [$indexer] [$prover] [$verifier] [$($where_clause)*]
            [$($protocol)*] [$($instance)*] [$($witness)*] [$($index_types)*]
            [$($prover_key)*] [$($verifier_key)*] [$($preprocess)* $next]
            $($rest)*
        );
    };
    (
        [$($generics:tt)*] [$indexer:ty] [$prover:ty] [$verifier:ty]
        [$($where_clause:tt)*] [$($protocol:tt)*] [$($instance:tt)*]
        [$($witness:tt)*] [$($index_types:tt)*] [$($prover_key:tt)*]
        [$($verifier_key:tt)*] [$($preprocess:tt)*]
    ) => {
        compile_error!("preprocessing argument body is missing `fn prove`");
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __ia_core_split_preprocessing_argument_prover {
    (
        [$($generics:tt)*] [$indexer:ty] [$prover:ty] [$verifier:ty]
        [$($where_clause:tt)*] [$($protocol:tt)*] [$($instance:tt)*]
        [$($witness:tt)*] [$($index_types:tt)*] [$($prover_key:tt)*]
        [$($verifier_key:tt)*] [$($preprocess:tt)*] [$($prove:tt)*]
        $(#[$verify_attr:meta])* fn verify $($verify_tail:tt)*
    ) => {
        $crate::__ia_core_emit_argument_indexer!(
            [$($generics)*] [$indexer] [$($where_clause)*] {
                $($protocol)* $($instance)* $($index_types)* $($preprocess)*
            }
        );
        $crate::__ia_core_emit_preprocessing_argument_prover!(
            [$($generics)*] [$prover] [$($where_clause)*] {
                $($protocol)* $($instance)* $($witness)* $($prover_key)* $($prove)*
            }
        );
        $crate::__ia_core_emit_preprocessing_argument_verifier!(
            [$($generics)*] [$verifier] [$($where_clause)*] {
                $($protocol)* $($instance)* $($verifier_key)*
                $(#[$verify_attr])* fn verify $($verify_tail)*
            }
        );
    };
    (
        [$($generics:tt)*] [$indexer:ty] [$prover:ty] [$verifier:ty]
        [$($where_clause:tt)*] [$($protocol:tt)*] [$($instance:tt)*]
        [$($witness:tt)*] [$($index_types:tt)*] [$($prover_key:tt)*]
        [$($verifier_key:tt)*] [$($preprocess:tt)*] [$($prove:tt)*]
        $next:tt $($rest:tt)*
    ) => {
        $crate::__ia_core_split_preprocessing_argument_prover!(
            [$($generics)*] [$indexer] [$prover] [$verifier] [$($where_clause)*]
            [$($protocol)*] [$($instance)*] [$($witness)*] [$($index_types)*]
            [$($prover_key)*] [$($verifier_key)*] [$($preprocess)*]
            [$($prove)* $next] $($rest)*
        );
    };
    (
        [$($generics:tt)*] [$indexer:ty] [$prover:ty] [$verifier:ty]
        [$($where_clause:tt)*] [$($protocol:tt)*] [$($instance:tt)*]
        [$($witness:tt)*] [$($index_types:tt)*] [$($prover_key:tt)*]
        [$($verifier_key:tt)*] [$($preprocess:tt)*] [$($prove:tt)*]
    ) => {
        compile_error!("preprocessing argument body is missing `fn verify`");
    };
}

/// Implement all three native roles of a preprocessing interactive reduction.
#[macro_export]
macro_rules! impl_preprocessing_reduction {
    (impl $($rest:tt)*) => {
        $crate::__ia_core_parse_role_triple!(
            [__ia_core_emit_preprocessing_reduction_triple] [] $($rest)*
        );
    };
    ($($invalid:tt)*) => {
        compile_error!(
            "expected `impl_preprocessing_reduction! { impl<...> { indexer: IndexerType, prover: ProverType, verifier: VerifierType } where ... { ... } }`"
        );
    };
}

/// Implement the indexer role of a preprocessing interactive reduction.
#[macro_export]
macro_rules! impl_preprocessing_reduction_indexer {
    (impl $($rest:tt)*) => {
        $crate::__ia_core_parse_role!([__ia_core_emit_reduction_indexer] [] $($rest)*);
    };
    ($($invalid:tt)*) => {
        compile_error!(
            "expected `impl_preprocessing_reduction_indexer! { impl<...> for IndexerType where ... { ... } }`"
        );
    };
}

/// Implement the prover role of a preprocessing interactive reduction.
#[macro_export]
macro_rules! impl_preprocessing_reduction_prover {
    (impl $($rest:tt)*) => {
        $crate::__ia_core_parse_role!([__ia_core_emit_preprocessing_reduction_prover] [] $($rest)*);
    };
    ($($invalid:tt)*) => {
        compile_error!(
            "expected `impl_preprocessing_reduction_prover! { impl<...> for ProverType where ... { ... } }`"
        );
    };
}

/// Implement the verifier role of a preprocessing interactive reduction.
#[macro_export]
macro_rules! impl_preprocessing_reduction_verifier {
    (impl $($rest:tt)*) => {
        $crate::__ia_core_parse_role!([__ia_core_emit_preprocessing_reduction_verifier] [] $($rest)*);
    };
    ($($invalid:tt)*) => {
        compile_error!(
            "expected `impl_preprocessing_reduction_verifier! { impl<...> for VerifierType where ... { ... } }`"
        );
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

#[doc(hidden)]
#[macro_export]
macro_rules! __ia_core_emit_preprocessing_reduction_triple {
    (
        [$($generics:tt)*] [$indexer:ty] [$prover:ty] [$verifier:ty]
        [$($where_clause:tt)*] {
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
            $($methods:tt)*
        }
    ) => {
        $crate::__ia_core_split_preprocessing_reduction_indexer!(
            [$($generics)*] [$indexer] [$prover] [$verifier] [$($where_clause)*]
            [
                $(#[$protocol_attr])*
                fn protocol_id(&self) -> impl AsRef<[u8]> $protocol_body
            ]
            [
                $(#[$source_instance_attr])*
                type SourceInstance = $source_instance;
                $(#[$target_instance_attr])*
                type TargetInstance = $target_instance;
            ]
            [
                $(#[$source_witness_attr])*
                type SourceWitness = $source_witness;
                $(#[$target_witness_attr])*
                type TargetWitness = $target_witness;
            ]
            [
                $(#[$index_attr])*
                type Index = $index;
                $(#[$prover_key_attr])*
                type ProverKey = $prover_key;
                $(#[$verifier_key_attr])*
                type VerifierKey = $verifier_key;
            ]
            [$(#[$prover_key_attr])* type ProverKey = $prover_key;]
            [$(#[$verifier_key_attr])* type VerifierKey = $verifier_key;]
            []
            $($methods)*
        );
    };
    ($($invalid:tt)*) => {
        compile_error!(
            "preprocessing reduction body must contain `protocol_id`, source/target instances, source/target witnesses, `Index`, both key types, `preprocess`, `prove`, then `verify`"
        );
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __ia_core_split_preprocessing_reduction_indexer {
    (
        [$($generics:tt)*] [$indexer:ty] [$prover:ty] [$verifier:ty]
        [$($where_clause:tt)*] [$($protocol:tt)*] [$($instances:tt)*]
        [$($witnesses:tt)*] [$($index_types:tt)*] [$($prover_key:tt)*]
        [$($verifier_key:tt)*] [$($preprocess:tt)*]
        $(#[$prove_attr:meta])* fn prove $($prove_tail:tt)*
    ) => {
        $crate::__ia_core_split_preprocessing_reduction_prover!(
            [$($generics)*] [$indexer] [$prover] [$verifier] [$($where_clause)*]
            [$($protocol)*] [$($instances)*] [$($witnesses)*] [$($index_types)*]
            [$($prover_key)*] [$($verifier_key)*] [$($preprocess)*]
            [$(#[$prove_attr])* fn prove] $($prove_tail)*
        );
    };
    (
        [$($generics:tt)*] [$indexer:ty] [$prover:ty] [$verifier:ty]
        [$($where_clause:tt)*] [$($protocol:tt)*] [$($instances:tt)*]
        [$($witnesses:tt)*] [$($index_types:tt)*] [$($prover_key:tt)*]
        [$($verifier_key:tt)*] [$($preprocess:tt)*] $next:tt $($rest:tt)*
    ) => {
        $crate::__ia_core_split_preprocessing_reduction_indexer!(
            [$($generics)*] [$indexer] [$prover] [$verifier] [$($where_clause)*]
            [$($protocol)*] [$($instances)*] [$($witnesses)*] [$($index_types)*]
            [$($prover_key)*] [$($verifier_key)*] [$($preprocess)* $next]
            $($rest)*
        );
    };
    (
        [$($generics:tt)*] [$indexer:ty] [$prover:ty] [$verifier:ty]
        [$($where_clause:tt)*] [$($protocol:tt)*] [$($instances:tt)*]
        [$($witnesses:tt)*] [$($index_types:tt)*] [$($prover_key:tt)*]
        [$($verifier_key:tt)*] [$($preprocess:tt)*]
    ) => {
        compile_error!("preprocessing reduction body is missing `fn prove`");
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __ia_core_split_preprocessing_reduction_prover {
    (
        [$($generics:tt)*] [$indexer:ty] [$prover:ty] [$verifier:ty]
        [$($where_clause:tt)*] [$($protocol:tt)*] [$($instances:tt)*]
        [$($witnesses:tt)*] [$($index_types:tt)*] [$($prover_key:tt)*]
        [$($verifier_key:tt)*] [$($preprocess:tt)*] [$($prove:tt)*]
        $(#[$verify_attr:meta])* fn verify $($verify_tail:tt)*
    ) => {
        $crate::__ia_core_emit_reduction_indexer!(
            [$($generics)*] [$indexer] [$($where_clause)*] {
                $($protocol)* $($instances)* $($index_types)* $($preprocess)*
            }
        );
        $crate::__ia_core_emit_preprocessing_reduction_prover!(
            [$($generics)*] [$prover] [$($where_clause)*] {
                $($protocol)* $($instances)* $($witnesses)* $($prover_key)* $($prove)*
            }
        );
        $crate::__ia_core_emit_preprocessing_reduction_verifier!(
            [$($generics)*] [$verifier] [$($where_clause)*] {
                $($protocol)* $($instances)* $($verifier_key)*
                $(#[$verify_attr])* fn verify $($verify_tail)*
            }
        );
    };
    (
        [$($generics:tt)*] [$indexer:ty] [$prover:ty] [$verifier:ty]
        [$($where_clause:tt)*] [$($protocol:tt)*] [$($instances:tt)*]
        [$($witnesses:tt)*] [$($index_types:tt)*] [$($prover_key:tt)*]
        [$($verifier_key:tt)*] [$($preprocess:tt)*] [$($prove:tt)*]
        $next:tt $($rest:tt)*
    ) => {
        $crate::__ia_core_split_preprocessing_reduction_prover!(
            [$($generics)*] [$indexer] [$prover] [$verifier] [$($where_clause)*]
            [$($protocol)*] [$($instances)*] [$($witnesses)*] [$($index_types)*]
            [$($prover_key)*] [$($verifier_key)*] [$($preprocess)*]
            [$($prove)* $next] $($rest)*
        );
    };
    (
        [$($generics:tt)*] [$indexer:ty] [$prover:ty] [$verifier:ty]
        [$($where_clause:tt)*] [$($protocol:tt)*] [$($instances:tt)*]
        [$($witnesses:tt)*] [$($index_types:tt)*] [$($prover_key:tt)*]
        [$($verifier_key:tt)*] [$($preprocess:tt)*] [$($prove:tt)*]
    ) => {
        compile_error!("preprocessing reduction body is missing `fn verify`");
    };
}

#[cfg(test)]
mod tests {
    use core::marker::PhantomData;

    use crate::{
        ArgumentCore, ArgumentProverCore, CommittedIndex, Indexer,
        PreprocessingInteractiveArgumentProver, PreprocessingInteractiveArgumentVerifier,
        PreprocessingInteractiveReductionProver, PreprocessingInteractiveReductionVerifier,
        ProtocolCore, ProverChannel, ReductionCore, ReductionProverCore, VerificationResult,
        VerifierChannel,
    };

    struct ArgProver;
    struct ArgVerifier;

    crate::impl_interactive_argument_prover! {
    impl for ArgProver {
            fn protocol_id(&self) -> impl AsRef<[u8]> { b"macro-arg" }
            type Instance = u8;
            type Witness = u16;
            fn prove<C: ProverChannel<Unit = u8>>(
                &self, _: &mut C, _: &Self::Instance, _: &Self::Witness
            ) {}
        }
    }

    crate::impl_interactive_argument_verifier! {
    impl for ArgVerifier {
            fn protocol_id(&self) -> impl AsRef<[u8]> { b"macro-arg" }
            type Instance = u8;
            fn verify<C: VerifierChannel<Unit = u8>>(
                &self, _: &mut C, _: &Self::Instance
            ) -> VerificationResult<()> { Ok(()) }
        }
    }

    struct ReductionProver;
    struct ReductionVerifier;

    crate::impl_interactive_reduction_prover! {
    impl for ReductionProver {
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

    crate::impl_interactive_reduction_verifier! {
    impl for ReductionVerifier {
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

    crate::impl_preprocessing_argument_indexer! {
    impl for ArgumentIndexer {
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

    crate::impl_preprocessing_argument_prover! {
    impl for IndexedArgumentProver {
            fn protocol_id(&self) -> impl AsRef<[u8]> { b"macro-indexed-arg" }
            type Instance = u8;
            type Witness = u16;
            type ProverKey = ();
            fn prove<C: ProverChannel<Unit = u8>>(
                &self, _: &mut C, _: &Self::ProverKey, _: &Self::Instance, _: &Self::Witness
            ) {}
        }
    }

    crate::impl_preprocessing_argument_verifier! {
    impl for IndexedArgumentVerifier {
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

    crate::impl_preprocessing_reduction_indexer! {
    impl for ReductionIndexer {
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

    crate::impl_preprocessing_reduction_prover! {
    impl for IndexedReductionProver {
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

    crate::impl_preprocessing_reduction_verifier! {
    impl for IndexedReductionVerifier {
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

    crate::impl_interactive_argument_prover! {
        impl<T> for GenericProver<T>
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

    struct SharedArgProver<T>(PhantomData<T>);
    struct SharedArgVerifier<T>(PhantomData<T>);

    crate::impl_interactive_argument! {
        impl<T> {
            prover: SharedArgProver<T>,
            verifier: SharedArgVerifier<T>,
        }
        where
            T: Copy,
        {
            fn protocol_id(&self) -> impl AsRef<[u8]> { b"macro-shared-arg" }
            type Instance = T;
            type Witness = T;
            fn prove<C: ProverChannel<Unit = u8>>(
                &self, _: &mut C, _: &Self::Instance, _: &Self::Witness
            ) {}
            fn verify<C: VerifierChannel<Unit = u8>>(
                &self, _: &mut C, _: &Self::Instance
            ) -> VerificationResult<()> { Ok(()) }
        }
    }

    struct SharedReductionProver;
    struct SharedReductionVerifier;

    crate::impl_interactive_reduction! {
        impl {
            prover: SharedReductionProver,
            verifier: SharedReductionVerifier,
        }
        {
            fn protocol_id(&self) -> impl AsRef<[u8]> { b"macro-shared-reduction" }
            type SourceInstance = u8;
            type TargetInstance = u16;
            type SourceWitness = u32;
            type TargetWitness = u64;
            fn prove<C: ProverChannel<Unit = u8>>(
                &self, _: &mut C, _: &Self::SourceInstance, _: &Self::SourceWitness
            ) -> (Self::TargetInstance, Self::TargetWitness) { (0, 0) }
            fn verify<C: VerifierChannel<Unit = u8>>(
                &self, _: &mut C, _: &Self::SourceInstance
            ) -> VerificationResult<Self::TargetInstance> { Ok(0) }
        }
    }

    struct SharedArgumentIndexer;
    struct SharedIndexedArgumentProver;
    struct SharedIndexedArgumentVerifier;

    crate::impl_preprocessing_argument! {
        impl {
            indexer: SharedArgumentIndexer,
            prover: SharedIndexedArgumentProver,
            verifier: SharedIndexedArgumentVerifier,
        }
        {
            fn protocol_id(&self) -> impl AsRef<[u8]> { b"macro-shared-indexed-arg" }
            type Instance = u8;
            type Witness = u16;
            type Index = ();
            type ProverKey = ();
            type VerifierKey = ();
            fn preprocess(&self, _: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
                ((), ())
            }
            fn prove<C: ProverChannel<Unit = u8>>(
                &self, _: &mut C, _: &Self::ProverKey, _: &Self::Instance, _: &Self::Witness
            ) {}
            fn verify<C: VerifierChannel<Unit = u8>>(
                &self, _: &mut C, _: &Self::VerifierKey, _: &Self::Instance
            ) -> VerificationResult<()> { Ok(()) }
        }
    }

    struct SharedReductionIndexer;
    struct SharedIndexedReductionProver;
    struct SharedIndexedReductionVerifier;

    crate::impl_preprocessing_reduction! {
        impl {
            indexer: SharedReductionIndexer,
            prover: SharedIndexedReductionProver,
            verifier: SharedIndexedReductionVerifier,
        }
        {
            fn protocol_id(&self) -> impl AsRef<[u8]> { b"macro-shared-indexed-red" }
            type SourceInstance = u8;
            type TargetInstance = u16;
            type SourceWitness = u32;
            type TargetWitness = u64;
            type Index = ();
            type ProverKey = ();
            type VerifierKey = ();
            fn preprocess(&self, _: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
                ((), ())
            }
            fn prove<C: ProverChannel<Unit = u8>>(
                &self,
                _: &mut C,
                _: &Self::ProverKey,
                _: &Self::SourceInstance,
                _: &Self::SourceWitness,
            ) -> (Self::TargetInstance, Self::TargetWitness) { (0, 0) }
            fn verify<C: VerifierChannel<Unit = u8>>(
                &self, _: &mut C, _: &Self::VerifierKey, _: &Self::SourceInstance
            ) -> VerificationResult<Self::TargetInstance> { Ok(0) }
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
        let (pk, vk) = ArgumentIndexer.preprocess(&());
        assert_eq!(pk.committed_index(), vk.committed_index());
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
        check(SharedArgProver::<u32>(PhantomData));
        fn check_verifier<V: ArgumentCore<Instance = u32>>(_: V) {}
        check_verifier(SharedArgVerifier::<u32>(PhantomData));
    }

    #[test]
    fn shared_macros_emit_every_native_role() {
        fn plain_reduction<
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
        plain_reduction(SharedReductionProver, SharedReductionVerifier);

        fn preprocessing_argument<
            I: ArgumentCore<Instance = u8> + Indexer<Index = (), ProverKey = (), VerifierKey = ()>,
            P: PreprocessingInteractiveArgumentProver<Instance = u8, Witness = u16, ProverKey = ()>,
            V: PreprocessingInteractiveArgumentVerifier<Instance = u8, VerifierKey = ()>,
        >(
            _: I,
            _: P,
            _: V,
        ) {
        }
        preprocessing_argument(
            SharedArgumentIndexer,
            SharedIndexedArgumentProver,
            SharedIndexedArgumentVerifier,
        );

        fn preprocessing_reduction<
            I: ReductionCore<SourceInstance = u8, TargetInstance = u16>
                + Indexer<Index = (), ProverKey = (), VerifierKey = ()>,
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
            _: I,
            _: P,
            _: V,
        ) {
        }
        preprocessing_reduction(
            SharedReductionIndexer,
            SharedIndexedReductionProver,
            SharedIndexedReductionVerifier,
        );
    }

    #[test]
    fn indexer_exposes_no_execution_requirement() {
        fn accepts_indexer<I: Indexer>(_: &I) {}
        accepts_indexer(&ArgumentIndexer);
        accepts_indexer(&ReductionIndexer);
    }
}
