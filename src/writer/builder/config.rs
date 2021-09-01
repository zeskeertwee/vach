use crate::global::{types::FlagType, header::HeaderConfig};
use std::io;
use ed25519_dalek as esdalek;

#[derive(Debug)]
pub struct BuilderConfig {
    pub header_config: HeaderConfig,
    pub flags: FlagType,
    pub keypair: Option<esdalek::Keypair>,
}

impl BuilderConfig {
    pub fn keypair(mut self, keypair: esdalek::Keypair) -> Self {
        self.keypair = Some(keypair);
        self
    }
    pub fn flags(mut self, flags: FlagType) -> Self {
        self.flags = flags;
        self
    }
    pub fn header(mut self, header: HeaderConfig) -> Self {
        self.header_config = header;
        self
    }
    pub fn load_keypair<T: io::Read>(&mut self, mut handle: T) -> anyhow::Result<()> {
        let mut keypair_bytes = [4; crate::KEYPAIR_LENGTH];
        handle.read(&mut keypair_bytes)?;
        self.keypair = Some(esdalek::Keypair::from_bytes(&keypair_bytes)?);
        Ok(())
    }
}

impl Default for BuilderConfig {
    fn default() -> BuilderConfig {
        BuilderConfig { header_config: HeaderConfig::default(), flags: FlagType::default(), keypair: None }
    }
}
