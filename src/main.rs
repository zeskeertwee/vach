use std::fs::File;

pub(crate) mod loader;

fn main(){	
	// TODO: Put this in libs.rs under #[cfg(tests)]
	{
		let archive_opt: loader::ArchiveConfig = loader::ArchiveConfig::default().set_minimum_version(&451u16);
		let file = File::open("me.vach").unwrap();
		format!("{}", &archive_opt);

		let _header = loader::Header::from_file(&file, &false);

		loader::Archive::validate(&file, &archive_opt).unwrap();
	}
}