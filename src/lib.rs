#![allow(unused)]
#![allow(clippy::or_fun_call)]
mod tests;

pub mod global;
pub mod loader;
pub mod writer;

// Re-exports
pub use rand;
pub use anyhow;
pub use bitflags;

// Current archive version
pub const VERSION: u16 = 12;

// Simpler imports
pub mod prelude {
    pub use crate::global::{
        flags::Flags,
        header::{Header, HeaderConfig},
        registry::{Registry, RegistryEntry},
        types::*,
    };
    pub use crate::loader::{archive::Archive, resource::Resource};
    pub use crate::writer::{
        builder::{Builder, BuilderConfig},
        leaf::{Leaf, LeafConfig}
    };
}
