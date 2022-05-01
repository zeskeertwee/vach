/// Configures how `Leaf`s should be compressed.
/// Default is `CompressMode::Never`.
#[derive(Debug, Clone, Copy)]
#[cfg(feature = "compression")]
#[cfg_attr(docsrs, doc(cfg(feature = "compression")))]
pub enum CompressMode {
	/// The data will always be compressed
	Always,
	/// The compressed data is used, only if it is smaller than the original data.
	Detect,
	/// The data is never compressed and is embedded as is.
	Never,
}

#[cfg(feature = "compression")]
impl Default for CompressMode {
	fn default() -> CompressMode {
		CompressMode::Never
	}
}
