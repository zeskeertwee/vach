#![allow(clippy::or_fun_call)]
mod tests;

pub(crate) mod global;
pub(crate) mod loader;
pub(crate) mod writer;

// Re-exports
pub use rand;
pub use bitflags;

// Global constants
pub const VERSION: u16 = 13;
pub const KEYPAIR_LENGTH: usize = 64;
pub const SECRET_KEY_LENGTH: usize = 32;
pub const PUBLIC_KEY_LENGTH: usize = 32;
pub const SIGNATURE_LENGTH: usize =  64;

// Simpler imports
pub mod prelude {
    pub use crate::global::{
        header::HeaderConfig,
        types::*,
    };
    pub use crate::loader::{
        archive::Archive,
        resource::Resource
    };
    pub use crate::writer::{
        builder::{Builder, BuilderConfig},
        leaf::Leaf
    };
}
