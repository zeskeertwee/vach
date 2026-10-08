#![no_main]

use libfuzzer_sys::fuzz_target;
use vach::prelude::*;

fuzz_target!(|data: Vec<u8>| {
	let mut target = std::io::Cursor::new(data);
	let _ = Archive::new(&mut target);
});
