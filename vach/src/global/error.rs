use std::{error, io, fmt};

use lz4_flex as lz4;

/// All errors manifestable within `vach` collected into a neat enum
#[repr(u8)]
#[derive(Debug)]
pub enum InternalError {
	/// Variant that wraps over all other errors, unknown and undocumented
	OtherError(String),
	/// An error that is returned when either a [Keypair](vach::crypto::Keypair), Signature, [PublicKey](vach::crypto::PublicKey) or [SecretKey](vach::crypto::SecretKey) fail to deserialize.
	ParseError(String),
	/// A thin wrapper over [io::Error](std::io::Error), captures all IO errors
	IOError(io::Error),
	/// Thrown when the loader fails to validate an archive source
	ValidationError(String),
	/// Thrown by `Archive::fetch(---)` when a given resource is not found
	MissingResourceError(String),
	/// Thrown when a leaf with an identical ID to a queued leaf is add with the `Builder::add(---)` functions
	LeafAppendError(String),
	/// Thrown when no `Keypair` is provided and an encrypted [Leaf](vach::builder::Leaf) is encountered
	NoKeypairError(String),
	/// Thrown when decryption or encryption fails
	CryptoError(String),
	/// Thrown when a link leaf aliases another link leaf, potentially causing a cyclic link error
	CyclicLinkReferenceError(String, String),
	/// Thrown when an attempt is made to set a bit within the first four bits(restricted) of a [`Flags`](crate::prelude::Flags) instance
	RestrictedFlagAccessError,
	/// When a [`Leaf`](crate::builder::Leaf) has an ID that is longer than `crate::MAX_ID_LENGTH`
	IDSizeOverflowError(String),
	/// Errors thrown during compression or decompression
	DeCompressionError(String),
	/// An error that is thrown when the current loader attempts to load an incompatible version
	IncompatibleArchiveVersionError(u16)
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
				f.write_str(message.as_str())
			},
			Self::RestrictedFlagAccessError => write!(f, "[VachError::RestrictedFlagAccessError] Tried to set reserved bit(s)!"),
			Self::MissingResourceError(id) => write!(f, "[VachError::MissingResourceError] {}", id),
			Self::LeafAppendError(id) => write!(f, "[VachError::LeafAppendError] A leaf with the ID: {} already exists. Consider changing the ID to prevent collisions", id),
			Self::DeCompressionError(err) => write!(f, "[VachError::DeCompressionError] Encountered an error during compression or decompression: {}", err),
			Self::IncompatibleArchiveVersionError(version) => write!(f, "The provided archive source has version: {}. While the loader has a spec-version: {}. The current loader is incompatible!", version, crate::VERSION)
		}
	}
}

impl PartialEq for InternalError {
	fn eq(&self, other: &Self) -> bool {
		match (self, other) {
			(Self::OtherError(l0), Self::OtherError(r0)) => l0 == r0,
			(Self::ParseError(l0), Self::ParseError(r0)) => l0 == r0,
			(Self::ValidationError(l0), Self::ValidationError(r0)) => l0 == r0,
			(Self::MissingResourceError(l0), Self::MissingResourceError(r0)) => l0 == r0,
			(Self::LeafAppendError(l0), Self::LeafAppendError(r0)) => l0 == r0,
			(Self::NoKeypairError(l0), Self::NoKeypairError(r0)) => l0 == r0,
			(Self::CryptoError(l0), Self::CryptoError(r0)) => l0 == r0,
			(Self::CyclicLinkReferenceError(l0, l1), Self::CyclicLinkReferenceError(r0, r1)) => {
				l0 == r0 && l1 == r1
			}
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

impl From<lz4::frame::Error> for InternalError {
	fn from(err: lz4::frame::Error) -> InternalError {
		InternalError::DeCompressionError(err.to_string())
	}
}
