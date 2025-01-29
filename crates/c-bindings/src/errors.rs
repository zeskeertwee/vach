use std::os::raw;
use vach::prelude;

/// One parameter passed to a function was NULL
pub const E_PARAMETER_IS_NULL: raw::c_int = -1;
/// Unable to parse a key or signature
pub const E_PARSE_ERROR: raw::c_int = -2;
/// String parameter was not valid UTF8 sequence
pub const E_INVALID_UTF8: raw::c_int = -3;
/// Generic IO error
pub const E_GENERIC_IO_ERROR: raw::c_int = -4;
/// Malformed archive source, invalid MAGIC or otherwise
pub const E_MALFORMED_ARCHIVE_SOURCE: raw::c_int = -5;
/// Resource not found
pub const E_RESOURCE_NOT_FOUND: raw::c_int = -6;
/// Unknown error
pub const E_UNKNOWN: raw::c_int = -7;
/// One or more necessary library features wasn't enabled during compilation
pub const E_MISSING_FEATURE_ERROR: raw::c_int = -8;
/// Generic cryptographic error, signature verification failed or otherwise
pub const E_CRYPTO_ERROR: raw::c_int = -9;

pub(crate) fn v_error_to_id<T>(error_p: *mut raw::c_int, error: prelude::InternalError) -> *mut T {
	if let Some(e) = unsafe { error_p.as_mut() } {
		*e = match error {
			prelude::InternalError::OtherError(_) => E_UNKNOWN,
			prelude::InternalError::MissingFeatureError(_) => E_MISSING_FEATURE_ERROR,
			prelude::InternalError::ParseError(_) => E_PARSE_ERROR,
			prelude::InternalError::IOError(_) => E_GENERIC_IO_ERROR,
			prelude::InternalError::MalformedArchiveSource(_) => E_MALFORMED_ARCHIVE_SOURCE,
			prelude::InternalError::MissingResourceError(_) => E_RESOURCE_NOT_FOUND,
			prelude::InternalError::CryptoError(_) | prelude::InternalError::NoKeypairError => E_CRYPTO_ERROR,
			prelude::InternalError::IncompatibleArchiveVersionError(_) => E_MALFORMED_ARCHIVE_SOURCE,
			prelude::InternalError::DeCompressionError(_) => E_GENERIC_IO_ERROR,
			_ => -7, // TODO: Builder Errors
		};
	}

	std::ptr::null_mut()
}

pub(crate) fn report<T>(error_p: *mut raw::c_int, code: raw::c_int) -> *mut T {
	if let Some(error) = unsafe { error_p.as_mut() } {
		*error = code;
	}

	std::ptr::null_mut()
}
