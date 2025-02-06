#![deny(clippy::from_raw_with_void_ptr)]
#![allow(non_camel_case_types)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

mod errors;
pub mod reader;
pub mod writer;

use std::{io, fs};

/// The version of the library
#[no_mangle]
pub extern "C" fn version() -> u16 {
	vach::VERSION
}

/// The length of the magic string in the file header
pub const V_MAGIC_LENGTH: usize = 5;
/// The length of a public key
pub const V_PUBLIC_KEY_LENGTH: usize = 32;

/// A wrapper combining `fs::File` and `io::Cursor`, over the C boundary.
/// Allowing both inner buffers and files to be used for data.
pub(crate) enum DataInner {
	File(fs::File),
	Buffer(io::Cursor<&'static [u8]>),
}

impl io::Read for DataInner {
	fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
		match self {
			DataInner::File(f) => f.read(buf),
			DataInner::Buffer(b) => b.read(buf),
		}
	}
}

impl io::Seek for DataInner {
	fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
		match self {
			DataInner::File(f) => f.seek(pos),
			DataInner::Buffer(b) => b.seek(pos),
		}
	}
}
