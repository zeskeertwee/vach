#![allow(non_camel_case_types)]

use std::{fs, io, slice, ffi};
use vach::prelude::*;
use super::errors;

/// The version of the library
#[no_mangle]
pub extern "C" fn version() -> u16 {
	vach::VERSION
}

/// The length of the magic string in the file header
pub const V_MAGIC_LENGTH: usize = 5;
/// The length of a public key
pub const V_PUBLIC_KEY_LENGTH: usize = 32;

/// Archive loader configuration
pub type v_archive_config = i8;

/// Create new loader configuration
#[no_mangle]
pub extern "C" fn new_archive_config(
	magic: *const [u8; V_MAGIC_LENGTH], pk_bytes: *const [u8; V_PUBLIC_KEY_LENGTH], error_p: *mut i32,
) -> *mut v_archive_config {
	let magic = match unsafe { magic.as_ref().map(|m| *m) } {
		Some(m) => m,
		None => vach::DEFAULT_MAGIC,
	};

	let mut config = ArchiveConfig::new(magic, None);
	if let Some(bytes) = unsafe { pk_bytes.as_ref() } {
		if let Err(e) = config.load_public_key(bytes.as_slice()) {
			return errors::v_error_to_id(error_p, e);
		};
	};

	Box::into_raw(Box::new(config)) as _
}

/// Free archive loader configuration
#[no_mangle]
pub extern "C" fn free_archive_config(config: *mut v_archive_config) {
	if !(config as *mut ArchiveConfig).is_null() {
		drop(unsafe { Box::from_raw(config) });
	}
}

pub(crate) enum ArchiveInner {
	File(fs::File),
	Buffer(io::Cursor<&'static [u8]>),
}

impl io::Read for ArchiveInner {
	fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
		match self {
			ArchiveInner::File(f) => f.read(buf),
			ArchiveInner::Buffer(b) => b.read(buf),
		}
	}
}

impl io::Seek for ArchiveInner {
	fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
		match self {
			ArchiveInner::File(f) => f.seek(pos),
			ArchiveInner::Buffer(b) => b.seek(pos),
		}
	}
}

/// An Archive instance, bound to either a file or a buffer
pub type v_archive = u8;

/// Create a new archive from a file
#[no_mangle]
pub extern "C" fn new_archive_from_file(
	path: *const i8, config: *const v_archive_config, error_p: *mut i32,
) -> *mut v_archive {
	let path = match unsafe { std::ffi::CStr::from_ptr(path).to_str() } {
		Ok(p) => p,
		Err(_) => return errors::report(error_p, errors::E_INVALID_UTF8),
	};

	let file = match fs::File::open(path) {
		Ok(file) => file,
		Err(e) => return errors::v_error_to_id(error_p, InternalError::IOError(e)),
	};

	let config = match unsafe { (config as *const ArchiveConfig).as_ref() } {
		Some(c) => c,
		None => &ArchiveConfig::default(),
	};

	let archive = match Archive::with_config(ArchiveInner::File(file), config) {
		Ok(archive) => archive,
		Err(err) => return errors::v_error_to_id(error_p, err),
	};

	Box::into_raw(Box::new(archive)) as _
}

/// Create a new archive from a buffer
#[no_mangle]
pub extern "C" fn new_archive_from_buffer(
	config: *const v_archive_config, data: *const u8, len: usize, error_p: *mut i32,
) -> *mut v_archive {
	if data.is_null() {
		return errors::report(error_p, errors::E_PARAMETER_IS_NULL);
	}

	let source = unsafe { slice::from_raw_parts(data, len) };
	let buffer = io::Cursor::new(source);

	let config = match unsafe { (config as *const ArchiveConfig).as_ref() } {
		Some(c) => c,
		None => return errors::report(error_p, errors::E_PARAMETER_IS_NULL),
	};

	let archive = match Archive::with_config(ArchiveInner::Buffer(buffer), config) {
		Ok(archive) => archive,
		Err(err) => return errors::v_error_to_id(error_p, err),
	};

	Box::into_raw(Box::new(archive)) as _
}

#[no_mangle]
pub extern "C" fn free_archive(archive: *mut v_archive) {
	if !(archive as *mut Archive<ArchiveInner>).is_null() {
		drop(unsafe { Box::from_raw(archive) });
	}
}

/// A list archive entry IDs
#[repr(C)]
pub struct v_entries {
	count: usize,
	list: *mut *mut i8,
}

/// Get a list of archive entry IDs
#[no_mangle]
pub extern "C" fn archive_get_entries(archive: *const v_archive, error_p: *mut i32) -> *mut v_entries {
	let archive = match unsafe { (archive as *const Archive<ArchiveInner>).as_ref() } {
		Some(a) => a,
		None => return errors::report(error_p, errors::E_PARAMETER_IS_NULL),
	};

	let list = archive
		.entries()
		.keys()
		.map(|k| ffi::CString::new(k.as_bytes()).unwrap().into_raw())
		.collect::<Vec<_>>();

	let list = list.into_boxed_slice();

	let entries = v_entries {
		count: list.len(),
		list: Box::leak(list).as_mut_ptr(),
	};

	Box::into_raw(Box::new(entries))
}

#[no_mangle]
pub extern "C" fn free_entries(entries: *mut v_entries) {
	if !entries.is_null() {
		let entries = unsafe { Box::from_raw(entries) };

		// reallocate box
		let slice = unsafe { slice::from_raw_parts_mut(entries.list, entries.count) };
		let list = unsafe { Box::from_raw(slice) };

		for entry in list {
			drop(unsafe { ffi::CString::from_raw(entry) });
		}
	}
}

/// An archive resource
#[repr(C)]
pub struct v_resource {
	data: *mut u8,
	len: usize,
	flags: ffi::c_uint,
	content_version: u8,
	verified: bool,
}

/// Fetch a resource, WITHOUT locking the internal Mutex
#[no_mangle]
pub extern "C" fn archive_fetch_resource(archive: *mut v_archive, id: *const i8, error_p: *mut i32) -> *mut v_resource {
	let path = match unsafe { std::ffi::CStr::from_ptr(id).to_str() } {
		Ok(p) => p,
		Err(_) => return errors::report(error_p, errors::E_INVALID_UTF8),
	};

	let archive = match unsafe { (archive as *mut Archive<ArchiveInner>).as_mut() } {
		Some(a) => a,
		None => return errors::report(error_p, errors::E_PARAMETER_IS_NULL),
	};

	let resource = match archive.fetch_mut(path) {
		Ok(resource) => resource,
		Err(err) => return errors::v_error_to_id(error_p, err),
	};

	let resource = v_resource {
		len: resource.data.len(),
		data: Box::leak(resource.data).as_mut_ptr(),
		flags: resource.flags.bits(),
		content_version: resource.content_version,
		verified: resource.verified,
	};

	Box::into_raw(Box::new(resource))
}

/// Fetch a resource, LOCKS the internal Mutex
#[no_mangle]
pub extern "C" fn archive_fetch_resource_lock(
	archive: *const v_archive, id: *const i8, error_p: *mut i32,
) -> *mut v_resource {
	let path = match unsafe { std::ffi::CStr::from_ptr(id).to_str() } {
		Ok(p) => p,
		Err(_) => return errors::report(error_p, errors::E_INVALID_UTF8),
	};

	let archive = match unsafe { (archive as *const Archive<ArchiveInner>).as_ref() } {
		Some(a) => a,
		None => return errors::report(error_p, errors::E_PARAMETER_IS_NULL),
	};

	let resource = match archive.fetch(path) {
		Ok(resource) => resource,
		Err(err) => return errors::v_error_to_id(error_p, err),
	};

	let resource = v_resource {
		len: resource.data.len(),
		data: Box::leak(resource.data).as_mut_ptr(),
		flags: resource.flags.bits(),
		content_version: resource.content_version,
		verified: resource.verified,
	};

	Box::into_raw(Box::new(resource))
}

#[no_mangle]
pub extern "C" fn free_resource(resource: *mut v_resource) {
	if let Some(resource) = unsafe { (resource as *mut v_resource).as_mut() } {
		let resource = unsafe { Box::from_raw(resource) };

		let data = unsafe { slice::from_raw_parts_mut(resource.data, resource.len) };
		drop(unsafe { Box::from_raw(data) });
	}
}
