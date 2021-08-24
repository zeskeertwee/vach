
#[cfg(test)]
pub(crate) mod tests {
    use crate::{global::{flags::RegEntryFlags, header::{Header, HeaderConfig}, registry::{Registry, RegistryEntry}}, loader::archive::Archive};
    use std::{
        fs::File,
        io::{Read, Seek, Write},
    };
    use ed25519_dalek as esdalek;

    #[test]
    pub(crate) fn defaults() {
        let _header_config = HeaderConfig::new();
        let _header = Header::default();
        let _registry = Registry::empty();
        let _registry_entry = RegistryEntry::empty();
    }

    #[test]
    pub(crate) fn header_config() -> anyhow::Result<()> {
        let config = HeaderConfig::from(*b"VfACH", 0u16, None);
        let mut file = File::open("me.vach")?;
        format!("{}", &config);

        let mut _header = Header::from(&mut file)?;
        format!("{}", _header);

        Archive::validate(&mut file, &config)?;

        Ok(())
    }

    #[test]
    pub(crate) fn esdalek_test() -> anyhow::Result<()>{
        println!("Bytes per esdalek::Signature: {}", esdalek::SIGNATURE_LENGTH);
        Ok(())
    }
}
