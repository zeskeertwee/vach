use crate::global::{types::FlagType, header::HeaderConfig};
use std::io;
use ed25519_dalek as esdalek;

#[derive(Debug)]
pub struct BuilderConfig {
    pub magic: [u8; HeaderConfig::MAGIC_LENGTH],
    pub content_version: u16,
    pub flags: FlagType,
    pub keypair: Option<esdalek::Keypair>,
}

impl BuilderConfig {
    // Helper functions
    pub fn keypair(mut self, keypair: esdalek::Keypair) -> Self { self.keypair = Some(keypair); self }
    pub fn version(mut self, version: u16) -> BuilderConfig { self.content_version = version; self }
    pub fn flags(mut self, flags: FlagType) -> Self { self.flags = flags; self }
    pub fn magic(mut self, magic: [u8; 5]) -> BuilderConfig { self.magic = magic; self }

    // Keypair helpers
    pub fn load_keypair<T: io::Read>(&mut self, mut handle: T) -> anyhow::Result<()> {
        let mut keypair_bytes = [4; crate::KEYPAIR_LENGTH];
        handle.read_exact(&mut keypair_bytes)?;
        self.keypair = Some(esdalek::Keypair::from_bytes(&keypair_bytes)?);
        Ok(())
    }
}

impl Default for BuilderConfig {
    fn default() -> BuilderConfig {
        BuilderConfig {
            flags: FlagType::default(),
            keypair: None,
            magic: *HeaderConfig::MAGIC,
            content_version: 0
        }
    }
}
