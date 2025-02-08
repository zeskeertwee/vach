use std::{fs, io, slice, ffi};
use vach::prelude::*;
use super::errors;

/// Archive Builder Configuration
pub type v_builder_leaf = ffi::c_void;

fn new_leaf<'a, T: io::Read + Sync + Send + 'a>(
	id: *const ffi::c_char, data: T, flags: u32, error_p: *mut i32,
) -> *mut Leaf<'a> {
	// get ID
	let c_str = unsafe { std::ffi::CStr::from_ptr(id).to_str() };
	let Ok(id) = c_str else {
		return errors::report(error_p, errors::E_INVALID_UTF8);
	};

	// create leaf
	let mut leaf = Leaf::new(data, id);

	// set Rust booleans from flags data
	leaf.encrypt = leaf.flags.contains(Flags::ENCRYPTED_FLAG);
	leaf.sign = leaf.flags.contains(Flags::SIGNED_FLAG);

	// check for compression flags
	if leaf.flags.contains(Flags::BROTLI_COMPRESSED) {
		leaf.compress = CompressMode::Detect;
		leaf.compression_algo = CompressionAlgorithm::Brotli(11);
	} else if leaf.flags.contains(Flags::SNAPPY_COMPRESSED) {
		leaf.compress = CompressMode::Detect;
		leaf.compression_algo = CompressionAlgorithm::Snappy;
	} else if leaf.flags.contains(Flags::LZ4_COMPRESSED) {
		leaf.compress = CompressMode::Detect;
		leaf.compression_algo = CompressionAlgorithm::LZ4;
	}

	// add extra flags
	leaf.flags = Flags::from_bits(flags);
	Box::into_raw(Box::new(leaf))
}

/// Creates a new `v_builder_leaf` from a buffer
#[no_mangle]
pub extern "C" fn new_leaf_from_buffer(
	id: *const ffi::c_char, data: *const u8, len: usize, flags: u32, error_p: *mut i32,
) -> *mut v_builder_leaf {
	if data.is_null() {
		errors::report(error_p, errors::E_PARAMETER_IS_NULL)
	} else {
		new_leaf(id, unsafe { slice::from_raw_parts(data, len) }, flags, error_p) as _
	}
}

/// Creates a new `v_builder_leaf` from a file
#[no_mangle]
pub extern "C" fn new_leaf_from_file(
	id: *const ffi::c_char, path: *const ffi::c_char, flags: u32, error_p: *mut i32,
) -> *mut v_builder_leaf {
	if path.is_null() {
		errors::report(error_p, errors::E_PARAMETER_IS_NULL)
	} else {
		match unsafe { std::ffi::CStr::from_ptr(path).to_str() } {
			Ok(path) => {
				let file = fs::File::open(path).unwrap();
				new_leaf(id, file, flags, error_p) as _
			},
			Err(_) => errors::report(error_p, errors::E_INVALID_UTF8),
		}
	}
}

/// Deallocates a `v_builder_leaf`
#[no_mangle]
pub extern "C" fn free_leaf(leaf: *mut v_builder_leaf) {
	if let Some(leaf) = unsafe { (leaf as *mut Leaf).as_mut() } {
		unsafe {
			drop(Box::from_raw(leaf));
		}
	}
}

/// Archive Builder Configuration
pub type v_builder_config = ffi::c_void;

/// Create new builder configuration
#[no_mangle]
pub extern "C" fn new_builder_config(
	magic: *const [u8; super::V_MAGIC_LENGTH], sk_bytes: *const [u8; super::V_SECRET_KEY_LENGTH], flags: u32,
) -> *mut v_builder_config {
	let magic = unsafe { magic.as_ref().map(|m| *m) }.unwrap_or(vach::DEFAULT_MAGIC);

	let signing_key = unsafe { sk_bytes.as_ref() }.map(SigningKey::from_bytes);
	let flags = Flags::from_bits(flags);

	let config = BuilderConfig {
		magic,
		flags,
		signing_key,
		..Default::default()
	};

	Box::into_raw(Box::new(config)) as _
}

/// free memory bound by `new_builder_config`
#[no_mangle]
pub extern "C" fn free_builder_config(config: *mut v_builder_config) {
	if let Some(config) = unsafe { (config as *mut BuilderConfig).as_mut() } {
		unsafe {
			drop(Box::from_raw(config));
		}
	}
}

/// Archive Builder Configuration, use `libffcall` to construct closures in C
pub type v_builder_callback =
	extern "C" fn(id: *const char, id_len: usize, data: *const char, len: usize, location: u64, offset: u64);

/// processed and writes leaves to a preallocated buffer, buffer must at least be big enough to fit data
#[no_mangle]
pub extern "C" fn write_leaves_to_buffer(
	target: *mut u8, len: usize, leaves: *mut v_builder_leaf, l_len: usize, config: *const v_builder_config,
	callback: v_builder_callback, error_p: *mut i32,
) -> usize {
	let slice = unsafe { slice::from_raw_parts_mut(target, len) };
	let target = io::Cursor::new(slice);

	let config = unsafe { (config as *const BuilderConfig).as_ref() };
	let Some(config) = config else {
		return errors::report::<()>(error_p, errors::E_PARAMETER_IS_NULL) as _;
	};

	// read leaves
	let leaves = unsafe { slice::from_raw_parts_mut(leaves as *mut Leaf<'static>, l_len) };

	// check if callback is NULL
	let mut cb = move |entry: &RegistryEntry, data: &[u8]| {
		let id = entry.id.as_ref();

		callback(
			id.as_ptr() as _,
			id.len(),
			data.as_ptr() as _,
			data.len(),
			entry.location,
			entry.offset,
		)
	};

	let wrapper = ((callback as usize) == 0).then_some(&mut cb as _);

	// write
	match dump(target, leaves, config, wrapper) {
		Ok(bytes_written) => bytes_written as _,
		Err(e) => errors::v_error_to_id::<()>(error_p, e) as _,
	}
}

/// processed and writes leaves to a preallocated buffer, buffer must at least be big enough to fit data
#[no_mangle]
pub extern "C" fn write_leaves_to_file(
	path: *const ffi::c_char, leaves: *mut v_builder_leaf, l_len: usize, config: *const v_builder_config,
	callback: v_builder_callback, error_p: *mut i32,
) -> usize {
	let path = unsafe { ffi::CStr::from_ptr(path) }.to_str();
	let Ok(path) = path else {
		return errors::report::<()>(error_p, errors::E_INVALID_UTF8) as _;
	};

	let config = unsafe { (config as *const BuilderConfig).as_ref() };
	let Some(config) = config else {
		return errors::report::<()>(error_p, errors::E_PARAMETER_IS_NULL) as _;
	};

	// read leaves
	let leaves = unsafe { slice::from_raw_parts_mut(leaves as *mut Leaf<'static>, l_len) };

	// check if callback is NULL
	let mut cb = move |entry: &RegistryEntry, data: &[u8]| {
		let id = entry.id.as_ref();

		callback(
			id.as_ptr() as _,
			id.len(),
			data.as_ptr() as _,
			data.len(),
			entry.location,
			entry.offset,
		)
	};

	let wrapper = ((callback as usize) == 0).then_some(&mut cb as _);

	// write
	let target = fs::File::create(path).unwrap();
	match dump(target, leaves, config, wrapper) {
		Ok(bytes_written) => bytes_written as _,
		Err(e) => errors::v_error_to_id::<()>(error_p, e) as _,
	}
}
