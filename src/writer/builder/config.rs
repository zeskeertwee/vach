use crate::global::{types::FlagType, header::HeaderConfig};
use ed25519_dalek as esdalek;

pub struct BuilderConfig {
    pub header: HeaderConfig,
    pub flags: FlagType,
    pub keypair: esdalek::Keypair,
}
