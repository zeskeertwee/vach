use std::{io, error};
use thiserror::Error;

/// All errors manifestable within `vach` collected into a neat enum
#[derive(Debug, Error)]
pub enum InternalError {
	/// Generic all encompassing error
	#[error("[VachError::GenericError] {0}")]
	OtherError(Box<dyn error::Error + Send + Sync>),
	/// Produced when a cargo feature isn't available for a certain action: eg trying to decompress without the compression feature
	#[error("[VachError::MissingFeatureError] Unable to continue with operation, the cargo feature ({0}) is missing")]
	MissingFeatureError(&'static str),
	/// An error that is returned when either a [Keypair](crate::crypto::Keypair), Signature, [PublicKey](crate::crypto::PublicKey) or [SecretKey](crate::crypto::SecretKey) fails to deserialize.
	#[error("[VachError::ParseError] {0}")]
	ParseError(String),
	/// A thin wrapper over [io::Error](std::io::Error), captures all IO errors
	#[error("[VachError::IOError] {0}")]
	IOError(#[from] io::Error),
	/// Thrown when the archive finds an invalid MAGIC sequence in the given source, hinting at corruption or possible incompatibility with the given source
	/// You can customize the MAGIC in the [`Builder`](crate::builder::BuilderConfig) and use in the the [`ArchiveConfig`](crate::archive::ArchiveConfig)
	#[error("[VachError::ValidationError] Invalid magic found in Header, possible incompatibility with given source. Magic found {0:?}")]
	MalformedArchiveSource([u8; crate::MAGIC_LENGTH]),
	/// Thrown by `Archive::fetch(---)` when a given resource is not found
	#[error("[VachError::MissingResourceError] Resource not found: {0}")]
	MissingResourceError(String),
	/// Thrown when a leaf with an identical ID to a queued leaf is add with the `Builder::add(---)` functions
	#[error("[VachError::LeafAppendError] A leaf with the ID: {0} already exists. Consider changing the ID to prevent collisions")]
	LeafAppendError(String),
	/// Thrown when no `Keypair` is provided and an encrypted [Leaf](crate::builder::Leaf) is encountered
	#[error("[VachError::NoKeypairError] Unable to continue with cryptographic operation, as no keypair was supplied")]
	NoKeypairError,
	/// Thrown when decryption or encryption fails
	#[cfg(feature = "crypto")]
	#[error("[VachError::CryptoError] {0}")]
	CryptoError(aes_gcm::Error),
	/// Thrown when an attempt is made to set a bit within the first four bits(restricted) of a [`Flags`](crate::prelude::Flags) instance
	#[error("[VachError::RestrictedFlagAccessError] Tried to set reserved bit(s)!")]
	RestrictedFlagAccessError,
	/// When a [`Leaf`](crate::builder::Leaf) has an ID that is longer than `crate::MAX_ID_LENGTH`, contains the overflowing `ID`
	#[error("[VachError::IDSizeOverflowError] The maximum size of any ID is: {}. The leaf with ID: {0} has an overflowing ID of length: {}", crate::MAX_ID_LENGTH, .0.len())]
	IDSizeOverflowError(String),
	/// An error that is thrown when the current archive attempts to load an incompatible version, contains the incompatible version
	#[error("The provided archive source has version: {}. While the current implementation has a spec-version: {}. The provided source is incompatible!", .0, crate::VERSION)]
	IncompatibleArchiveVersionError(u16),
	/// An error that is thrown when if `Mutex` is poisoned, when a message doesn't go though an `mspc::sync_channel` or other sync related issues
	#[error("[VachError::SyncError] {0}")]
	SyncError(String),
	/// Errors thrown  during compression or decompression
	#[error("[VachError::CompressorDecompressorError]: {0}")]
	#[cfg(feature = "compression")]
	DeCompressionError(#[from] lz4_flex::frame::Error)
}
