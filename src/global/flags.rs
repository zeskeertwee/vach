use crate::global::types::*;

#[allow(non_snake_case)]
pub mod RegEntryFlags {
    use crate::global::types::*;

	pub const COMPRESSED: FlagType = 0b_1000_0000_0000_0000;
	pub const SIGNED: FlagType = 0b_0100_0000_0000_0000;
}