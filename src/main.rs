#![allow(unused_variables)]
use std::{fs::File, io::{BufReader, Read}, str};

pub(crate) mod loader;

fn main(){
	let file = File::open("me.vach").unwrap();
	let mut reader = BufReader::new(file);
	let mut buffer = [0;5];

	reader.read(&mut buffer).unwrap();
	let magic = String::from(str::from_utf8(&buffer).unwrap());
	
	match magic == "VfACH" {
		 true => println!("That over there is some mighty fine archive file"),
		 false => println!("Invalid archive file")
	};
	
	// TODO: Put this in libs.rs under #[cfg(tests)]
	{
		let mut archive_opt = loader::ArchiveConfig::default();
		println!("{}", &archive_opt);

		assert_eq!(archive_opt.flags, 0);
		archive_opt.set_flags(16);
		
		assert_eq!(archive_opt.flags, 16);
		assert_eq!(archive_opt.magic, *b"VfACH");
		assert_eq!(archive_opt.minimum_version, 0);

		archive_opt.toggle_flag(0b10010101, true);
		assert_eq!(archive_opt.flags, 0b10010101);
		archive_opt.toggle_flag(0b10010101, false);
		assert_eq!(archive_opt.flags, 0);
		println!("ArchiveConfig test passed");
	}
}