use crate::global::{types::FlagType, header::HeaderConfig};
use ed25519_dalek as esdalek;

#[derive(Debug)]
pub struct BuilderConfig {
    pub header_config: HeaderConfig,
    pub flags: FlagType,
    pub keypair: Option<esdalek::Keypair>,
}

impl Default for BuilderConfig {
    fn default() -> BuilderConfig {
        BuilderConfig { header_config: HeaderConfig::default(), flags: FlagType::default(), keypair: None }
    }
}
