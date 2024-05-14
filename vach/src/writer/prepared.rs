// Unit of data ready to be inserted into a `Write + Clone` target during Building
pub(crate) struct Prepared {
	pub(crate) data: Vec<u8>,
	pub(crate) entry: super::RegistryEntry,
	#[cfg(feature = "crypto")]
	pub(crate) sign: bool,
}
