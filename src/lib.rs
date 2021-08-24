#![allow(unused)]
mod tests;

pub mod global;
pub mod loader;
pub mod writer;

// Current archive version
pub const VERSION: f32 = 0.1;

// Simplify imports
pub mod prelude {
    pub use crate::global::{
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
