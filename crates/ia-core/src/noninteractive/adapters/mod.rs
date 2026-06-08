//! Adapters around non-interactive protocol artifacts.

mod narg_to_interactive;

pub use narg_to_interactive::{NargProverAsInteractiveArgument, NargVerifierAsInteractiveArgument};
