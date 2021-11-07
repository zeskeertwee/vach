use std::{error, io, fmt};

use lz4_flex as lz4;

/// All errors manifestable within `vach` collected into a neat enum
#[repr(u8)]
#[derive(Debug)]
pub enum InternalError {
	/// A one of error that collects all other errors and stores a `String` containing info about the error
	OtherError(String),
	/// An error that is returned when either a Keypair, Signatures or associated keys fail to deserialize.
	ParseError(String),
	/// A thin wrapper over `io::Error`s, meant to capture all io errors
	IOError(io::Error),
	/// Thrown when an archive fails to validate it's header and therefore fails to get parsed
	ValidationError(String),
	/// Thrown by `Archive::fetch(---)` when a given resource is not found
	MissingResourceError(String),
	/// Thrown when a leaf with an identical ID to a queued leaf is add with the `Builder::add(---)` functions
	LeafAppendError(String),
	/// Thrown when no keypair is provided and an encrypted leaf is encountered
	NoKeypairError(String),
	/// Thrown when decryption or decryption fails
	CryptoError(String),
	/// Thrown when a link leaf aliases another link leaf, potentially causing a cyclic link error
	CyclicLinkReferenceError(String, String),
	/// Thrown when an attempt is made to set a bit within the first four bits(restricted) of a `Flag` instance
	RestrictedFlagAccessError,
	/// When a `Leaf` has an ID that is longer than `crate::MAX_ID_LENGTH`
	IDSizeOverflowError(String),
	/// Errors thrown during compression or decompression
	LZ4Error(lz4::frame::Error),
}

impl fmt::Display for InternalError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::OtherError(err) => write!(f, "{}", err),
			Self::ParseError(err) => write!(f, "[VachError::ParseError] {}", err),
			Self::IOError(err) => write!(f, "[VachError::IOError] {}", err.to_string()),
			Self::ValidationError(err) => write!(f, "[VachError::ValidationError] {}", err),
			Self::CryptoError(err) => write!(f, "[VachError::CryptoError]	{}", err),
			Self::NoKeypairError(err) => write!(f, "{}", err),
			Self::IDSizeOverflowError(id_part) => write!(f, "[VachError::IDSizeOverflowError] The maximum size of any ID is: {}. The leaf with ID: {} has an overflowing ID", crate::MAX_ID_LENGTH, id_part),
			Self::CyclicLinkReferenceError(link, target) => {
				let message = format!("[VachError::CyclicLinkReferenceError], link leafs can't point to other link leafs. Leaf: {} points to another link leaf: {}", link, target);
				write!(f, "{}", message)
			},
			Self::RestrictedFlagAccessError => write!(f, "[VachError::RestrictedFlagAccessError] Tried to set reserved bit(s)!"),
			Self::MissingResourceError(id) => write!(f, "[VachError::MissingResourceError] {}", id),
			Self::LeafAppendError(id) => write!(f, "[VachError::LeafAppendError] A leaf with the ID: {} already exists. Consider changing the ID to prevent collisions", id),
			Self::LZ4Error(err) => write!(f, "[VachError::LZ4Error] Encountered an error during compression or decompression: {}", err),
		}
	}
}

impl error::Error for InternalError {}

impl From<io::Error> for InternalError {
	fn from(err: io::Error) -> Self {
		InternalError::IOError(err)
	}
}

impl From<lz4::frame::Error> for InternalError {
	fn from(err: lz4::frame::Error) -> Self {
		InternalError::LZ4Error(err)
	}
}
