use crate::global::types::FlagType;

pub struct LeafConfig {
	pub flags: FlagType,
	pub path: String,
	pub version: u8,
}