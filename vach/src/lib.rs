#![allow(clippy::or_fun_call)]

/// All tests are included in this module.
mod tests;

pub(crate) mod global;
pub(crate) mod loader;
pub(crate) mod writer;

// Re-exports
pub use rand;
pub use bitflags;

// Global constants
/// Current file spec version, both `Loader` and `Builder`
pub const VERSION: u16 = 13;

/// Size of a keypair: (secret + public)
pub const KEYPAIR_LENGTH: usize = 64;

/// Size of a secret key
pub const SECRET_KEY_LENGTH: usize = 32;

/// Size of a public key
pub const PUBLIC_KEY_LENGTH: usize = 32;

/// Size of a signature
pub const SIGNATURE_LENGTH: usize =  64;

/// Maximum size for any ID
pub const MAX_ID_LENGTH: usize = 65535; // u16::MAX

/// Where all crate logic resides
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
