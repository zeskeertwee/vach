use std::{error, io, fmt};

#[cfg(feature = "compression")]
use lz4_flex as lz4;

/// All errors manifestable within `vach` collected into a neat enum
#[derive(Debug)]
pub enum InternalError {
	/// Variant that wraps over all other errors, unknown and undocumented.
	/// ```rust
	/// use vach::prelude::InternalError;
	///
	/// let error = InternalError::OtherError("I love errors, I think they are swell".into());
	/// ```
	OtherError(Box<dyn error::Error + Send + Sync>),
	/// Produced when a cargo feature isn't available for a certain action: eg trying to decompress without the compression feature
	MissingFeatureError(String),
	/// An error that is returned when either a [Keypair](crate::crypto::Keypair), Signature, [PublicKey](crate::crypto::PublicKey) or [SecretKey](crate::crypto::SecretKey) fails to deserialize.
	ParseError(String),
	/// A thin wrapper over [io::Error](std::io::Error), captures all IO errors
	IOError(io::Error),
	/// Thrown when the loader fails to validate an archive source
	ValidationError(String),
	/// Thrown by `Archive::fetch(---)` when a given resource is not found
	MissingResourceError(String),
	/// Thrown when a leaf with an identical ID to a queued leaf is add with the `Builder::add(---)` functions
	LeafAppendError(String),
	/// Thrown when no `Keypair` is provided and an encrypted [Leaf](crate::builder::Leaf) is encountered
	NoKeypairError(String),
	/// Thrown when decryption or encryption fails
	CryptoError(String),
	/// Thrown when an attempt is made to set a bit within the first four bits(restricted) of a [`Flags`](crate::prelude::Flags) instance
	RestrictedFlagAccessError,
	/// When a [`Leaf`](crate::builder::Leaf) has an ID that is longer than `crate::MAX_ID_LENGTH`
	IDSizeOverflowError(String),
	/// An error that is thrown when the current loader attempts to load an incompatible version, contains the incompatible version
	IncompatibleArchiveVersionError(u16),
	/// An error that is thrown when if `Mutex` is poisoned, when a message doesn't go though an `mspc::sync_channel` or other sync related issues
	SyncError(String),
	/// Errors thrown during compression or decompression
	DeCompressionError(String),
}

impl fmt::Display for InternalError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::OtherError(err) => write!(f, "[VachError::GenericError] {}", err),
			Self::MissingFeatureError(feature) => write!(f, "[VachError::MissingFeatureError] Unable to continue with operation, a cargo feature is missing: {}", feature),
			Self::ParseError(err) => write!(f, "[VachError::ParseError] {}", err),
			Self::IOError(err) => write!(f, "[VachError::IOError] {}", err),
			Self::ValidationError(err) => write!(f, "[VachError::ValidationError] {}", err),
			Self::CryptoError(err) => write!(f, "[VachError::CryptoError]	{}", err),
			Self::NoKeypairError(err) => write!(f, "{}", err),
			Self::IDSizeOverflowError(id_part) => write!(f, "[VachError::IDSizeOverflowError] The maximum size of any ID is: {}. The leaf with ID: {} has an overflowing ID of length: {}", crate::MAX_ID_LENGTH, id_part, id_part.len()),
			Self::RestrictedFlagAccessError => write!(f, "[VachError::RestrictedFlagAccessError] Tried to set reserved bit(s)!"),
			Self::MissingResourceError(id) => write!(f, "[VachError::MissingResourceError] {}", id),
			Self::LeafAppendError(id) => write!(f, "[VachError::LeafAppendError] A leaf with the ID: {} already exists. Consider changing the ID to prevent collisions", id),
			Self::IncompatibleArchiveVersionError(version) => write!(f, "The provided archive source has version: {}. While the loader has a spec-version: {}. The current loader is incompatible!", version, crate::VERSION),
			Self::SyncError(err) => write!(f, "[VachError::SyncError] {}", err),
			Self::DeCompressionError(err) => write!(f, "[VachError::DeCompressionError]: {}", err),
		}
	}
}

impl PartialEq for InternalError {
	fn eq(&self, other: &Self) -> bool {
		match (self, other) {
			(Self::ParseError(l0), Self::ParseError(r0)) => l0 == r0,
			(Self::ValidationError(l0), Self::ValidationError(r0)) => l0 == r0,
			(Self::MissingResourceError(l0), Self::MissingResourceError(r0)) => l0 == r0,
			(Self::LeafAppendError(l0), Self::LeafAppendError(r0)) => l0 == r0,
			(Self::NoKeypairError(l0), Self::NoKeypairError(r0)) => l0 == r0,
			(Self::CryptoError(l0), Self::CryptoError(r0)) => l0 == r0,
			(Self::IDSizeOverflowError(l0), Self::IDSizeOverflowError(r0)) => l0 == r0,
			_ => core::mem::discriminant(self) == core::mem::discriminant(other),
		}
	}
}

impl error::Error for InternalError {}

impl From<io::Error> for InternalError {
	fn from(err: io::Error) -> InternalError {
		InternalError::IOError(err)
	}
}

#[cfg(feature = "compression")]
impl From<lz4::frame::Error> for InternalError {
	fn from(err: lz4::frame::Error) -> InternalError {
		InternalError::DeCompressionError(err.to_string())
	}
}
