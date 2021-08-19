#![allow(unused)]

pub(crate) mod global;
pub(crate) mod loader;

// Simplify imports
pub(crate) mod prelude {
    pub use crate::global::{
        header::{Header, HeaderConfig},
        registry::{Registry, RegistryEntry},
        types::*,
    };
    pub use crate::loader::{archive::Archive, resource::Resource};
}

#[cfg(test)]
mod tests {
    use crate::{global::{flags::RegEntryFlags, header::{Header, HeaderConfig}, registry::{Registry, RegistryEntry}}, loader::archive::Archive};
    use std::{
        fs::File,
        io::{Read, Seek, Write},
    };
    use ed25519_dalek as esdalek;

    #[test]
    fn defaults() {
        let _header_config = HeaderConfig::default();
        let _header = Header::empty();
        let _registry = Registry::empty();
        let _registry_entry = RegistryEntry::empty();
    }

    #[test]
    fn header_config() -> anyhow::Result<()> {
        let config = HeaderConfig::new(*b"VfACH", 0u16);
        let mut file = File::open("me.vach")?;
        format!("{}", &config);

        let mut _header = Header::from(&mut file)?;
        format!("{}", _header);

        Archive::validate(&mut file, &config)?;

        Ok(())
    }

    #[test]
    pub fn esdalek_test() -> anyhow::Result<()>{
        println!("Bytes per esdalek::Signature: {}", esdalek::SIGNATURE_LENGTH);
        Ok(())
    }
}
