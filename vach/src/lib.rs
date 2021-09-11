#![allow(clippy::or_fun_call)]
mod tests;

pub(crate) mod global;
pub(crate) mod loader;
pub(crate) mod writer;

// Re-exports
pub use rand;
pub use bitflags;

// Global constants
/// Current file spec version
pub const VERSION: u16 = 13;

/// The size in bytes of a keypair: (secret + public)
pub const KEYPAIR_LENGTH: usize = 64;

/// The size in bytes of a secret key
pub const SECRET_KEY_LENGTH: usize = 32;

/// The size in bytes of a public key
pub const PUBLIC_KEY_LENGTH: usize = 32;

/// The size in bytes of a signature
pub const SIGNATURE_LENGTH: usize =  64;

pub mod prelude {
    //! All crate structures and logic is stored within
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
