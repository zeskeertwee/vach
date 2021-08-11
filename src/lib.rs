#![allow(unused)]

pub(crate) mod global;
pub(crate) mod loader;

// Simplify imports
pub(crate) mod prelude{
    pub use crate::global::{
        header::{Header, HeaderConfig},
        registry::{Registry, RegistryEntry},
        storage::Storage,
        types::*
    };
    pub use crate::loader::{
        Archive,
        resource::Resource
    };
}

#[cfg(test)]
mod test {
    use crate::{
        global::{header, registry},
        loader::Archive,
    };
    use std::{
        fs::File,
        io::{BufReader, BufWriter, Read, Seek, Write},
    };

    #[test]
    fn defaults() {
        let _header_config = header::HeaderConfig::default();
        let _header = header::Header::empty();
        let _registry = registry::Registry::empty();
        let _registry_entry = registry::RegistryEntry::empty();
    }

    #[test]
    fn header_config() ->anyhow::Result<()> {
        let config = header::HeaderConfig::new(*b"VfACH", 0u16);
        let file = File::open("me.vach")?;
        format!("{}", &config);

        let _header = header::Header::from_file(&file)?;
        format!("{}", _header);
        Archive::validate(&file, &config)?;

        Result::Ok(())
    }

    #[test]
    fn to_bytes() -> anyhow::Result<()> {
        let mut file = File::open("me.vach")?;

        let _header = header::Header::from_file(&file)?;
        assert_eq!(_header.bytes().len(), header::HeaderConfig::SIZE);

        let registry = registry::Registry::from_file(&file, &_header)?;

        let vector = registry.bytes();
        let vector: Vec<&[u8]> = vector.windows(registry::RegistryEntry::SIZE).collect();

        assert_eq!(vector.get(0).ok_or(anyhow::Error::msg("Vector out of bounds error"))?.len(), registry::RegistryEntry::SIZE);
        Result::Ok(())
    }

    #[test]
    fn write_example_file() -> anyhow::Result<()> {
        let file = File::create("me.vach")?;
        let mut writer = BufWriter::new(file);
        {
            let mut header = header::Header::empty();
            let mut registry = registry::Registry::empty();
            let entries = 2;
            header.capacity = entries;

            for i in 0..entries {
                registry.entries.push(registry::RegistryEntry::empty());
            };

            writer.write(header.bytes().as_slice())?;
            writer.write(&registry.bytes().as_slice());
        };
        writer.flush()?;

        Result::Ok(())
    }

    #[test]
    fn to_ne_bytes() {
        let num = 514u16;
        let array = num.to_ne_bytes();
        assert_eq!(
            array,
            if cfg!(target_endian = "big") {
                num.to_be_bytes()
            } else {
                num.to_le_bytes()
            }
        );

        let array = [2u8, 2u8];
        assert_eq!(num, u16::from_ne_bytes(array));
    }

    #[test]
    fn registry_tests() -> anyhow::Result<()>{
        let mut registry = registry::Registry::empty();
        let entries = 2;

        for i in 0..entries {
            registry.entries.push(registry::RegistryEntry::empty());
        };

        Ok(())
    }
}
