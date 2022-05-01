use std::{io, error};
use thiserror::Error;

/// All errors manifestable within `vach` collected into a neat enum
#[derive(Debug, Error)]
pub enum InternalError {
	/// Generic all encompassing error
	/// ```rust
	/// use vach::prelude::InternalError;
	///
	/// let error = InternalError::OtherError("I love errors, I think they are swell".into());
	/// ```
	#[error("[VachError::GenericError] {0}")]
	OtherError(Box<dyn error::Error + Send + Sync>),
	/// Produced when a cargo feature isn't available for a certain action: eg trying to decompress without the compression feature
	#[error("[VachError::MissingFeatureError] Unable to continue with operation, the cargo feature ({0}) is missing")]
	MissingFeatureError(String),
	/// An error that is returned when either a [Keypair](crate::crypto::Keypair), Signature, [PublicKey](crate::crypto::PublicKey) or [SecretKey](crate::crypto::SecretKey) fails to deserialize.
	#[error("[VachError::ParseError] {0}")]
	ParseError(String),
	/// A thin wrapper over [io::Error](std::io::Error), captures all IO errors
	#[error("[VachError::IOError] {0}")]
	IOError(#[from] io::Error),
	/// Thrown when the loader fails to validate an archive source
	#[error("[VachError::ValidationError] {0}")]
	ValidationError(String),
	/// Thrown by `Archive::fetch(---)` when a given resource is not found
	#[error("[VachError::MissingResourceError] {0}")]
	MissingResourceError(String),
	/// Thrown when a leaf with an identical ID to a queued leaf is add with the `Builder::add(---)` functions
	#[error("[VachError::LeafAppendError] A leaf with the ID: {0} already exists. Consider changing the ID to prevent collisions")]
	LeafAppendError(String),
	/// Thrown when no `Keypair` is provided and an encrypted [Leaf](crate::builder::Leaf) is encountered
	#[error("[VachError::NoKeypairError] {0}")]
	NoKeypairError(String),
	/// Thrown when decryption or encryption fails
	#[error("[VachError::CryptoError] {0}")]
	CryptoError(String),
	/// Thrown when an attempt is made to set a bit within the first four bits(restricted) of a [`Flags`](crate::prelude::Flags) instance
	#[error("[VachError::RestrictedFlagAccessError] Tried to set reserved bit(s)!")]
	RestrictedFlagAccessError,
	/// When a [`Leaf`](crate::builder::Leaf) has an ID that is longer than `crate::MAX_ID_LENGTH`
	#[error("[VachError::IDSizeOverflowError] The maximum size of any ID is: {}. The leaf with ID: {0} has an overflowing ID of length: {}", crate::MAX_ID_LENGTH, .0.len())]
	IDSizeOverflowError(String),
	/// An error that is thrown when the current loader attempts to load an incompatible version, contains the incompatible version
	#[error("The provided archive source has version: {}. While the loader has a spec-version: {}. The current loader is incompatible!", .0, crate::VERSION)]
	IncompatibleArchiveVersionError(u16),
	/// An error that is thrown when if `Mutex` is poisoned, when a message doesn't go though an `mspc::sync_channel` or other sync related issues
	#[error("[VachError::SyncError] {0}")]
	SyncError(String),
	/// Errors thrown  during compression or decompression
	#[cfg(feature = "compression")]
	#[error("[VachError::CompressorDecompressorError]: {0}")]
	DeCompressionError(String),
}

#[cfg(feature = "compression")]
use lz4_flex as lz4;

#[cfg(feature = "compression")]
impl From<lz4::frame::Error> for InternalError {
	fn from(err: lz4::frame::Error) -> InternalError {
		InternalError::DeCompressionError(err.to_string())
	}
}
