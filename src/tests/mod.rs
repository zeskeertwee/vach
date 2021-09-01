/// This is meant to mirror as closely as possible, how users should use the crate
#[cfg(test)]
pub(crate) mod tests {
    // The reason we are pulling the header and the registry from the global namespace is because they are not exposed outside of the crate, pub(crate)
    // We still need to conduct tests on them tho.
    use crate::global::{header::Header, registry::*};

    // Boring, average every day contemporary imports
    use crate::prelude::*;
    use std::{fs::{File}, io::{Cursor, Seek, SeekFrom}, str};

    // Contains both the public key and secret key in the same file:
    // secret -> [u8; crate::SECRET_KEY_LENGTH], public -> [u8; crate::PUBLIC_KEY_LENGTH]
    const KEYPAIR: &str = "test_data/pair.pub";

    // The paths to the Archives, to be written|loaded
    const SIGNED_TARGET: &str = "test_data/signed/target.vach";
    const SIMPLE_TARGET: &str = "test_data/simple/target.vach";

    #[test]
    pub(crate) fn log_constants() {
        dbg!(crate::VERSION);
        dbg!(crate::PUBLIC_KEY_LENGTH);
        dbg!(crate::SIGNATURE_LENGTH);
        dbg!(crate::SECRET_KEY_LENGTH);
    }

    #[test]
    pub(crate) fn defaults() {
        let _header_config = HeaderConfig::default();
        let _header = Header::default();
        let _registry = Registry::empty();
        let _registry_entry = RegistryEntry::empty();
        let _resource = Resource::default();
        let _leaf = Leaf::default();
        let _leaf_config = LeafConfig::default();
        let _builder: Builder<Cursor<Vec<u8>>> = Builder::new();
        let _builder_config = BuilderConfig::default();
        let _flags = FlagType::default();
    }

    #[test]
    pub(crate) fn header_config() -> anyhow::Result<()> {
        let config = HeaderConfig::from(*b"VfACH", 0, None);
        let mut file = File::open("test_data/simple/target.vach")?;
        format!("{}", &config);

        let mut _header = Header::from(&mut file)?;
        format!("{}", _header);

        Archive::validate(&mut file, &config)?;
        Ok(())
    }

    #[test]
    pub(crate) fn empty_test() -> anyhow::Result<()> {
        Ok(())
    }

    #[test]
    pub(crate) fn custom_bits() -> anyhow::Result<()> {
        todo!("Write this test")
    }

    #[test]
    pub fn loader_no_signature() -> anyhow::Result<()> {
        let target = File::open(SIMPLE_TARGET)?;
        let mut archive = Archive::from(target)?;
        let resource = archive.fetch("poem")?;
        println!("{}", str::from_utf8(resource.data.as_slice())?);
        Ok(())
    }

    #[test]
    pub(crate) fn writer_no_signature() -> anyhow::Result<()>{
        let mut builder = Builder::default();
        let build_config = BuilderConfig::default();

        builder.add(File::open("test_data/song.txt")?, "song")?;
        builder.add_with_config(
            File::open("test_data/poem.txt")?,
            &LeafConfig::default()
                .compress(false)
                .version(12)
                .id("poem")
        )?;

        let mut target = File::create(SIMPLE_TARGET)?;
        builder.write(&mut target, &build_config)?;
        Ok(())
    }

    #[test]
    pub(crate) fn loader_with_signature() -> anyhow::Result<()> {
        let target = File::open(SIGNED_TARGET)?;

        // Load keypair
        let mut config = HeaderConfig::default();
        let mut keypair = File::open(KEYPAIR)?;
        keypair.seek(SeekFrom::Start(crate::SECRET_KEY_LENGTH as u64))?;
        config.load_public_key(keypair)?;

        let mut archive = Archive::with_config(target, &config)?;
        let resource = archive.fetch("song")?;
        println!("{}", str::from_utf8(resource.data.as_slice())?);
        Ok(())
    }

    #[test]
    pub(crate) fn writer_with_signature() -> anyhow::Result<()>{
        let mut builder = Builder::default();
        let mut build_config = BuilderConfig::default();
        build_config.load_keypair(File::open(KEYPAIR)?)?;

        builder.add(File::open("test_data/song.txt")?, "song")?;
        builder.add(File::open("test_data/poem.txt")?, "poem")?;

        let mut target = File::create(SIGNED_TARGET)?;
        builder.write(&mut target, &build_config)?;
        Ok(())
    }

    #[test]
    pub(crate) fn fetch_write_with_signature() -> anyhow::Result<()> {
        let target = File::open(SIGNED_TARGET)?;

        // Load keypair
        let mut config = HeaderConfig::default();
        let mut keypair = File::open(KEYPAIR)?;
        keypair.seek(SeekFrom::Start(crate::SECRET_KEY_LENGTH as u64))?;
        config.load_public_key(keypair)?;

        let mut archive = Archive::with_config(target, &config)?;
        let mut string = Vec::new();
        archive.fetch_write("song", &mut string)?;
        println!("{}", str::from_utf8(&string)?);
        Ok(())
    }

    #[test]
    pub(crate) fn gen_keypair() -> anyhow::Result<()> {
        use rand::rngs::OsRng;
        use ed25519_dalek as esdalek;

        // NOTE: regenerating new keys will break some tests
        let regenerate = false;

        if regenerate {
            let mut rng = OsRng;
            let keypair = esdalek::Keypair::generate(&mut rng);
    
            std::fs::write( KEYPAIR, &keypair.to_bytes())?;
        };

        Ok(())
    }
}
