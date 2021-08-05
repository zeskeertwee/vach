pub(crate) mod loader;

fn main(){	
	// TODO: Put this in libs.rs under #[cfg(tests)]
	{
		let mut archive_opt = loader::ArchiveConfig::default();
		format!("{}", &archive_opt);

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