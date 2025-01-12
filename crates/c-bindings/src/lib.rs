#![allow(non_camel_case_types)]

use std::{ffi, fs, io, mem, os::raw, slice};
use vach::prelude::*;

mod errors;

/// The version of the library
#[no_mangle]
pub extern "C" fn version() -> raw::c_ushort {
	vach::VERSION
}

/// The length of the magic string in the file header
pub const V_MAGIC_LENGTH: usize = 5;
/// The length of a public key
pub const V_PUBLIC_KEY_LENGTH: usize = 32;

/// Archive loader configuration
pub type v_archive_config = raw::c_char;

/// Create new loader configuration
#[no_mangle]
pub extern "C" fn new_archive_config(
	magic: *const [raw::c_uchar; V_MAGIC_LENGTH], pk_bytes: *const [raw::c_uchar; V_PUBLIC_KEY_LENGTH],
	error_p: *mut ffi::c_int,
) -> *mut v_archive_config {
	let magic = match unsafe { magic.as_ref().map(|m| *m) } {
		Some(m) => m,
		None => *vach::DEFAULT_MAGIC,
	};

	let pk = match unsafe { pk_bytes.as_ref() } {
		Some(bytes) => {
			let Ok(pk) = VerifyingKey::from_bytes(bytes) else {
				return errors::report(error_p, errors::E_PARSE_ERROR);
			};

			Some(pk)
		},
		None => None,
	};

	let config = ArchiveConfig::new(magic, pk);
	Box::into_raw(Box::new(config)) as _
}

/// Free archive loader configuration
#[no_mangle]
pub extern "C" fn free_archive_config(config: *mut v_archive_config) {
	if !(config as *mut ArchiveConfig).is_null() {
		let _ = unsafe { Box::from_raw(config) };
	}
}

pub(crate) enum ArchiveInner {
	File(fs::File),
	Buffer(mem::ManuallyDrop<io::Cursor<&'static [u8]>>),
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
pub type v_archive = raw::c_uchar;

/// Create a new archive from a file
#[no_mangle]
pub extern "C" fn new_archive_from_file(
	path: *const raw::c_char, config: *const v_archive_config, error_p: *mut ffi::c_int,
) -> *mut v_archive {
	let path = match unsafe { std::ffi::CStr::from_ptr(path).to_str() } {
		Ok(p) => p,
		Err(_) => return errors::report(error_p, errors::E_INVALID_UTF8),
	};

	let Ok(file) = fs::File::open(path) else {
		return errors::report(error_p, errors::E_GENERIC_IO_ERROR);
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
	config: *const v_archive_config, data: *const raw::c_uchar, len: raw::c_ulonglong, error_p: *mut ffi::c_int,
) -> *mut v_archive {
	if data.is_null() {
		return errors::report(error_p, errors::E_PARAMETER_IS_NULL);
	}

	let source = unsafe { slice::from_raw_parts(data, len as _) };
	let buffer = mem::ManuallyDrop::new(io::Cursor::new(source));

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
		let _ = unsafe { Box::from_raw(archive) };
	}
}

/// A list archive entry IDs
#[repr(C)]
pub struct v_entries {
	count: raw::c_ulong,
	list: *mut *mut raw::c_char,
}

/// Get a list of archive entry IDs
#[no_mangle]
pub extern "C" fn archive_get_entries(archive: *const v_archive, error_p: *mut ffi::c_int) -> *mut v_entries {
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
		count: list.len() as _,
		list: Box::leak(list).as_mut_ptr(),
	};

	Box::into_raw(Box::new(entries))
}

#[no_mangle]
pub extern "C" fn free_entries(entries: *mut v_entries) {
	if !entries.is_null() {
		let entries = unsafe { Box::from_raw(entries) };

		// reallocate box
		let slice = unsafe { slice::from_raw_parts_mut(entries.list, entries.count as _) };
		let list = unsafe { Box::from_raw(slice) };

		for entry in list {
			let _ = unsafe { ffi::CString::from_raw(entry) };
		}
	}
}

/// An archive resource
#[repr(C)]
pub struct v_resource {
	data: *mut raw::c_uchar,
	len: raw::c_ulonglong,
	flags: raw::c_uint,
	content_version: raw::c_uchar,
	verified: bool,
}

/// Fetch a resource, WITHOUT locking the internal Mutex
#[no_mangle]
pub extern "C" fn archive_fetch_resource(
	archive: *mut v_archive, id: *const raw::c_char, error_p: *mut ffi::c_int,
) -> *mut v_resource {
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
		len: resource.data.len() as _,
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
	archive: *const v_archive, id: *const raw::c_char, error_p: *mut ffi::c_int,
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
		len: resource.data.len() as _,
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

		// TODO: test if this leaks memory
		let data = unsafe { slice::from_raw_parts_mut(resource.data, resource.len as _) };
		let _ = unsafe { Box::from_raw(data) };
	}
}
