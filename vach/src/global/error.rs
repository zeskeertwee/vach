use std::{error, io, fmt};

use lz4_flex as lz4;

#[repr(u8)]
#[derive(Debug)]
pub enum InternalError {
	UnknownError,
	OtherError(String),
	ParseError(String),
	IOError(io::Error),
	ValidationError(String),
	MissingResourceError(String),
	LeafAppendError(String),
	RequirementError(String),
	DecryptionError(String, String),
	EncryptionError(String, String),
	CyclicLinkReferenceError(String, String),
	RestrictedFlagAccessError,
	IDSizeOverflowError(String),
	NonExistentLeafError(String),
	LZ4Error(lz4::frame::Error)
}

impl fmt::Display for InternalError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::UnknownError => write!(f, "[VachError] Unknown error type!"),
			Self::OtherError(err) => write!(f, "{}", err),
			Self::ParseError(err) => write!(f, "[VachError::ParseError] {}", err),
			Self::IOError(err) => write!(f, "[VachError::IOError] {}", err.to_string()),
			Self::ValidationError(err) => write!(f, "[VachError::ValidationError] {}", err),
			Self::DecryptionError(id, err) => write!(f, "[VachError::DecryptionError]	Unable to decrypt resource: {}. Reason: {}", id, err),
			Self::EncryptionError(id, err) => write!(f, "[VachError::EncryptionError]	Unable to encrypt resource: {}. Reason: {}", id, err),
			Self::RequirementError(err) => write!(f, "{}", err),
			Self::IDSizeOverflowError(id_part) => write!(f, "[VachError::::IDSizeOverflowError] The maximum size of any ID is: {}. The leaf with ID: {} has an overflowing ID", crate::MAX_ID_LENGTH, id_part),
			Self::CyclicLinkReferenceError(link, target) => {
				let message = format!("[VachError::CyclicLinkReferenceError], link leafs can't point to other link leafs. Leaf: {} points to another link leaf: {}", link, target);
				write!(f, "{}", message)
			},
			Self::RestrictedFlagAccessError => write!(f, "[VachError::RestrictedFlagAccessError] Tried to set reserved bit(s)!"),
			_ => todo!("Unimplemented match branches!"),
		}
	}
}

impl error::Error for InternalError {}

impl From<io::Error> for  InternalError {
    fn from(err: io::Error) -> Self {
        InternalError::IOError(err)
    }
}

impl From<lz4::frame::Error> for  InternalError {
	fn from(err: lz4::frame::Error) -> Self {
		 InternalError::LZ4Error(err)
	}
}