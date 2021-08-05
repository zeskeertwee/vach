use std::fs::File;

pub(crate) mod loader;

fn main(){	
	// TODO: Put this in libs.rs under #[cfg(tests)]
	{
		let archive_opt: loader::ArchiveConfig = loader::ArchiveConfig::default().set_minimum_version(&451u16);
		let file = File::open("me.vach").unwrap();
		format!("{}", &archive_opt);

		loader::Archive::validate(&file, &archive_opt).unwrap();
	}
}