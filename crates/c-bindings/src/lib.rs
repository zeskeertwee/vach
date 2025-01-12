use std::{ffi, fs, io, mem, os::raw, slice};
use vach::prelude::*;

extern "C" {
	fn vach_error(msg: *const raw::c_char, len: raw::c_ulong);
}

fn report<'a, T>(msg: &'a str) -> *const T {
	unsafe {
		vach_error(msg.as_ptr() as _, msg.len() as _);
		std::ptr::null()
	}
}

#[no_mangle]
pub extern "C" fn version() -> raw::c_ushort {
	vach::VERSION
}

#[no_mangle]
pub extern "C" fn new_archive_config(
	magic: *const [u8; vach::MAGIC_LENGTH], pk_bytes: *const [u8; vach::PUBLIC_KEY_LENGTH],
) -> *const ArchiveConfig {
	let magic = match unsafe { magic.as_ref().map(|m| *m) } {
		Some(m) => m,
		None => {
			return report("Invalid magic, magic is NULL");
		},
	};

	let pk_bytes = match unsafe { pk_bytes.as_ref() } {
		Some(vk) => vk,
		None => return report("Invalid public key, public key is NULL"),
	};

	let Ok(pk) = VerifyingKey::from_bytes(pk_bytes) else {
		return report("Invalid public key, bytes are invalid");
	};

	let config = ArchiveConfig::new(magic, Some(pk));
	Box::into_raw(Box::new(config))
}

#[no_mangle]
pub extern "C" fn free_archive_config(config: *mut ArchiveConfig) {
	if !config.is_null() {
		let _ = unsafe { Box::from_raw(config) };
	}
}

pub enum ArchiveInner {
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

#[no_mangle]
pub extern "C" fn new_archive_from_file(
	path: *const raw::c_char, config: *const ArchiveConfig,
) -> *const Archive<ArchiveInner> {
	let path = match unsafe { std::ffi::CStr::from_ptr(path).to_str() } {
		Ok(p) => p,
		Err(msg) => return report(&msg.to_string()),
	};

	let Ok(file) = fs::File::open(path) else {
		return report("Unable to open file");
	};

	let config = match unsafe { config.as_ref() } {
		Some(c) => c,
		None => return report("Invalid config, config is NULL"),
	};

	let inner = ArchiveInner::File(file);
	let Ok(archive) = Archive::with_config(inner, config) else {
		return report("Unable to create archive");
	};

	Box::into_raw(Box::new(archive))
}

#[no_mangle]
pub extern "C" fn new_archive_from_buffer(
	config: *const ArchiveConfig, data: *const raw::c_uchar, len: raw::c_ulonglong,
) -> *const Archive<ArchiveInner> {
	if data.is_null() {
		return report("Invalid data, data is NULL");
	}

	let source = unsafe { slice::from_raw_parts(data, len as _) };
	let buffer = mem::ManuallyDrop::new(io::Cursor::new(source));

	let config = match unsafe { config.as_ref() } {
		Some(c) => c,
		None => return report("Invalid config, config is NULL"),
	};

	let inner = ArchiveInner::Buffer(buffer);
	let Ok(archive) = Archive::with_config(inner, config) else {
		return report("Unable to initialize archive");
	};

	Box::into_raw(Box::new(archive))
}

#[no_mangle]
pub extern "C" fn free_archive(archive: *mut Archive<ArchiveInner>) {
	if !archive.is_null() {
		let _ = unsafe { Box::from_raw(archive) };
	}
}

#[repr(C)]
pub struct Entries {
	count: raw::c_ulong,
	list: *mut *mut raw::c_char,
}

#[no_mangle]
pub extern "C" fn archive_get_entries(archive: *mut Archive<ArchiveInner>) -> *const Entries {
	let archive = match unsafe { archive.as_mut() } {
		Some(a) => a,
		None => return report("Invalid archive, archive is NULL"),
	};

	let mut entries = archive
		.entries()
		.keys()
		.map(|k| ffi::CString::new(k.as_bytes()).unwrap().into_raw())
		.collect::<Vec<_>>();

	// ensures capacity == len
	entries.shrink_to_fit();

	let entries = Entries {
		count: entries.len() as _,
		list: entries.as_mut_ptr(),
	};

	Box::into_raw(Box::new(entries))
}

#[no_mangle]
pub extern "C" fn free_entries(entries: *mut Entries) {
	if !entries.is_null() {
		let entries = unsafe { Box::from_raw(entries) };

		let list = unsafe { Vec::from_raw_parts(entries.list, entries.count as _, entries.count as _) };
		for entry in list {
			let _ = unsafe { ffi::CString::from_raw(entry) };
		}
	}
}

#[repr(C)]
pub struct Resource {
	data: *mut raw::c_uchar,
	len: raw::c_ulonglong,
	flags: raw::c_uint,
	content_version: raw::c_uchar,
	verified: bool,
}

#[no_mangle]
pub extern "C" fn archive_fetch_resource(
	archive: *mut Archive<ArchiveInner>, id: *const raw::c_char,
) -> *const Resource {
	let path = match unsafe { std::ffi::CStr::from_ptr(id).to_str() } {
		Ok(p) => p,
		Err(msg) => return report(&msg.to_string()),
	};

	let archive = match unsafe { archive.as_mut() } {
		Some(a) => a,
		None => return report("Invalid archive, archive is NULL"),
	};

	let resource = match archive.fetch_mut(path) {
		Ok(resource) => resource,
		Err(err) => {
			return report(&err.to_string());
		},
	};

	let resource = Resource {
		len: resource.data.len() as _,
		data: Box::leak(resource.data).as_mut_ptr(),
		flags: resource.flags.bits(),
		content_version: resource.content_version,
		verified: resource.verified,
	};

	Box::into_raw(Box::new(resource))
}

#[no_mangle]
pub extern "C" fn archive_fetch_resource_lock(
	archive: *const Archive<ArchiveInner>, id: *const raw::c_char,
) -> *const Resource {
	let path = match unsafe { std::ffi::CStr::from_ptr(id).to_str() } {
		Ok(p) => p,
		Err(msg) => return report(&msg.to_string()),
	};

	let archive = match unsafe { archive.as_ref() } {
		Some(a) => a,
		None => return report("Invalid archive, archive is NULL"),
	};

	let resource = match archive.fetch(path) {
		Ok(resource) => resource,
		Err(err) => {
			return report(&err.to_string());
		},
	};

	let resource = Resource {
		len: resource.data.len() as _,
		data: Box::leak(resource.data).as_mut_ptr(),
		flags: resource.flags.bits(),
		content_version: resource.content_version,
		verified: resource.verified,
	};

	Box::into_raw(Box::new(resource))
}

#[no_mangle]
pub extern "C" fn free_resource(resource: *mut Resource) {
	if let Some(resource) = unsafe { resource.as_mut() } {
		let resource = unsafe { Box::from_raw(resource) };

		// TODO: test if this leaks memory
		let data = unsafe { slice::from_raw_parts_mut(resource.data, resource.len as _) };
		let _ = unsafe { Box::from_raw(data) };
	}
}
