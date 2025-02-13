#![deny(clippy::from_raw_with_void_ptr)]
#![allow(non_camel_case_types)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::*;

mod errors;
pub mod reader;
pub mod writer;

// TODO: Document usage

/// A wrapper combining `fs::File` and `io::Cursor`, for static access over the C boundary.
/// Allowing both inner buffers and files to be used for data.
pub(crate) enum DataSource {
	File(fs::File),
	Buffer(io::Cursor<&'static [u8]>),
}

impl io::Read for DataSource {
	fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
		match self {
			DataSource::File(f) => f.read(buf),
			DataSource::Buffer(b) => b.read(buf),
		}
	}
}

impl io::Seek for DataSource {
	fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
		match self {
			DataSource::File(f) => f.seek(pos),
			DataSource::Buffer(b) => b.seek(pos),
		}
	}
}

/// The version of the library
#[no_mangle]
pub extern "C" fn version() -> u16 {
	vach::VERSION
}

/// The length of a public key
pub const V_VERIFYING_KEY_LENGTH: usize = 32;
/// The length of a secret
pub const V_SECRET_KEY_LENGTH: usize = 32;
