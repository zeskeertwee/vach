#[cfg(test)]
pub(crate) mod tests {
    use crate::prelude::*;
    use std::{fs::File, io::{Cursor, Read, Seek, Write}};
    use ed25519_dalek as esdalek;

    #[test]
    pub(crate) fn defaults() {
        let _header_config = HeaderConfig::new();
        let _header = Header::default();
        let _registry = Registry::empty();
        let _registry_entry = RegistryEntry::empty();
        let _resource = Resource::empty();
        let _leaf = Leaf::empty();
        let _leaf_config = LeafConfig::default();
        let _builder:Builder<Cursor<Vec<u8>>> = Builder::default();
        let _builder_config = BuilderConfig::default();
        let _flags = FlagType::empty();
    }

    #[test]
    pub(crate) fn header_config() -> anyhow::Result<()> {
        let config = HeaderConfig::from(*b"VfACH", 0u16, None);
        let mut file = File::open("test_data/me.vach")?;
        format!("{}", &config);

        let mut _header = Header::from(&mut file)?;
        format!("{}", _header);

        Archive::validate(&mut file, &config)?;
        Ok(())
    }

    #[test]
    pub(crate) fn writer_no_signature() -> anyhow::Result<()>{
        let mut builder = Builder::default();
        let mut build_config = BuilderConfig::default();
        builder.add_with_config(
            File::open("test_data/poem.txt")?,
            &LeafConfig::default()
                .compress(false)
                .version(12)
                .id(&"poem")
        );
        builder.add(File::open("test_data/song.txt")?, "song");

        let mut target = File::create("test_data/target.vach")?;
        builder.write(&mut target, &build_config)?;
        Ok(())
    }

    #[test]
    pub fn loader() -> anyhow::Result<()> {
        let mut handle = File::open("test_data/target.vach")?;
        let mut config = &HeaderConfig::default();
        let mut archive = Archive::from(handle)?;
        let resource = archive.fetch("song")?;
        println!("{}", std::str::from_utf8(resource.data.as_slice())?);
        Ok(())
    }
    #[test]
    pub(crate) fn esdalek_test() -> anyhow::Result<()>{
        println!("Bytes per esdalek::Signature: {}", esdalek::SIGNATURE_LENGTH);
        Ok(())
    }
}
