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
    use crate::{
        global::{
            header::{Header, HeaderConfig},
            registry::{Registry, RegistryEntry},
        },
        loader::archive::Archive
    };
    use std::{
        fs::File,
        io::{BufReader, BufWriter, Read, Seek, Write},
    };

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
        // Archive::validate(&mut file, &config)?;

        Result::Ok(())
    }
    
    #[test]
    fn to_bytes() -> anyhow::Result<()> {
        let mut reader = BufReader::new(File::open("me.vach")?);

        let _header = Header::from(&mut reader)?;
        assert_eq!(_header.bytes().len(), HeaderConfig::SIZE);

        let registry = Registry::from(&mut reader, &_header)?;

        let vector = registry.bytes();
        let vector: Vec<&[u8]> = vector.windows(RegistryEntry::SIZE).collect();

        assert_eq!(
            vector
                .get(0)
                .ok_or(anyhow::Error::msg("Vector out of bounds error"))?
                .len(),
            RegistryEntry::SIZE
        );
        Result::Ok(())
    }

    #[test]
    fn write_example_file() -> anyhow::Result<()> {
        let file = File::create("me.vach")?;
        let mut writer = BufWriter::new(file);
        {
            let mut header = Header::empty();
            let mut registry = Registry::empty();
            let entries = 2;
            header.capacity = entries;

            for i in 0..entries {
                registry.entries.push(RegistryEntry::empty());
            }

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
}
