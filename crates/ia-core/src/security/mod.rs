//! Security metadata for plain and preprocessing protocols.

mod plain;
mod preprocessing;

pub use plain::{ArgumentSecurity, ReductionSecurity, SecurityErrorBound, SecurityProfile};
pub use preprocessing::{PreprocessingArgumentSecurity, PreprocessingReductionSecurity};
