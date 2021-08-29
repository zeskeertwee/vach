#![allow(clippy::or_fun_call)]
mod tests;

pub(crate) mod global;
pub(crate) mod loader;
pub(crate) mod writer;

// Re-exports
pub use rand;
pub use anyhow;

// Global constants
pub const VERSION: u16 = 12;
pub const KEYPAIR_LENGTH: usize = ed25519_dalek::KEYPAIR_LENGTH;
pub const SECRET_KEY_LENGTH: usize = ed25519_dalek::SECRET_KEY_LENGTH;
pub const PUBLIC_KEY_LENGTH: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;
pub const SIGNATURE_LENGTH: usize =  ed25519_dalek::SIGNATURE_LENGTH;

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
        leaf::{Leaf, LeafConfig}
    };
}
