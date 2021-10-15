/// This is meant to mirror as closely as possible, how users should use the crate
#[cfg(test)]
mod tests {
	// Boring, average every day contemporary imports
	use std::{
		fs::{File},
		io::{Cursor, Seek, SeekFrom},
		str,
	};

	use crate::prelude::*;

	// Contains both the public key and secret key in the same file:
	// secret -> [u8; crate::SECRET_KEY_LENGTH], public -> [u8; crate::PUBLIC_KEY_LENGTH]
	const KEYPAIR: &str = "test_data/pair.pub";

	// The paths to the Archives, to be written|loaded
	const SIGNED_TARGET: &str = "test_data/signed/target.vach";
	const SIMPLE_TARGET: &str = "test_data/simple/target.vach";

	#[test]
	fn log_constants() {
		dbg!(crate::VERSION);
		dbg!(crate::PUBLIC_KEY_LENGTH);
		dbg!(crate::SIGNATURE_LENGTH);
		dbg!(crate::SECRET_KEY_LENGTH);
		dbg!(crate::MAX_ID_LENGTH);
	}

	#[test]
	fn defaults() {
		// The reason we are pulling the header and the registry from the global namespace is because they are not exposed outside of the crate, pub(crate)
		// We still need to conduct tests on them tho.
		use crate::global::{header::Header, reg_entry::*};

		let _header_config = HeaderConfig::default();
		let _header = Header::default();
		let _registry_entry = RegistryEntry::empty();
		let _resource = Resource::default();
		let _leaf = Leaf::default();
		let _builder = Builder::new();
		let _builder_config = BuilderConfig::default();
		let _flags = Flags::default();
	}

	#[test]
	fn header_config() -> anyhow::Result<()> {
		// We need a private dependency, Header to test ot
		use crate::global::header::Header;
		let config = HeaderConfig::new(*b"VfACH", None);
		let mut file = File::open("test_data/simple/target.vach")?;
		format!("{}", &config);

		let header = Header::from_handle(&mut file)?;
		format!("{}", header);

		Header::validate(&header, &config)?;
		Ok(())
	}

	// Custom bitflag tests
	const CUSTOM_FLAG_1: u16 = 0b_0000_1000_0000_0000;
	const CUSTOM_FLAG_2: u16 = 0b_0000_0100_0000_0000;
	const CUSTOM_FLAG_3: u16 = 0b_0000_0000_1000_0000;
	const CUSTOM_FLAG_4: u16 = 0b_0000_0000_0001_0000;

	#[test]
	fn custom_bitflags() -> anyhow::Result<()> {
		let target = File::open(SIMPLE_TARGET)?;
		let mut archive = Archive::from_handle(target)?;
		let resource = archive.fetch("poem")?;
		let flags = Flags::from_bits(resource.flags.bits());
		assert_eq!(flags.bits(), resource.flags.bits());
		assert!(flags.contains(CUSTOM_FLAG_1 | CUSTOM_FLAG_2 | CUSTOM_FLAG_3 | CUSTOM_FLAG_4));

		Ok(())
	}

	#[test]
	fn fetch_no_signature() -> anyhow::Result<()> {
		let target = File::open(SIMPLE_TARGET)?;
		let mut archive = Archive::from_handle(target)?;
		dbg!(archive.entries());
		let resource = archive.fetch("poem")?;

		// Windows bullshit
		#[cfg(target_os = "windows")]
		{
			assert_eq!(resource.data.len(), 359);
		}
		#[cfg(not(any(target_os = "windows", target_os = "ios")))]
		{
			assert_eq!(resource.data.len(), 345);
		}

		assert!(!resource.secured);
		assert!(resource.flags.contains(Flags::COMPRESSED_FLAG));

		println!("{}", String::from_utf8(resource.data)?);

		let hello = archive.fetch("greeting")?;
		assert_eq!("Hello, Cassandra!", str::from_utf8(&hello.data)?);
		assert!(!hello.flags.contains(Flags::COMPRESSED_FLAG));

		Ok(())
	}

	#[test]
	fn builder_no_signature() -> anyhow::Result<()> {
		let mut builder = Builder::default();
		let build_config = BuilderConfig::default();

		builder.add(File::open("test_data/song.txt")?, "song")?;
		builder.add(File::open("test_data/lorem.txt")?, "lorem")?;
		builder.add(File::open("test_data/bee.script")?, "script")?;
		builder.add(File::open("test_data/quicksort.wasm")?, "wasm")?;

		let mut poem_flags = Flags::default();
		poem_flags.set(
			CUSTOM_FLAG_1 | CUSTOM_FLAG_2 | CUSTOM_FLAG_3 | CUSTOM_FLAG_4,
			true,
		)?;

		builder.add_leaf(
			Leaf::from_handle(File::open("test_data/poem.txt")?)
				.compress(CompressMode::Always)
				.version(10)
				.id("poem")
				.flags(poem_flags),
		)?;

		builder.add_leaf(
			Leaf::from_handle(Cursor::new(b"Hello, Cassandra!"))
				.compress(CompressMode::Never)
				.id("greeting"),
		)?;

		let mut target = File::create(SIMPLE_TARGET)?;
		builder.dump(&mut target, &build_config)?;

		Ok(())
	}

	#[test]
	fn fetch_with_signature() -> anyhow::Result<()> {
		let target = File::open(SIGNED_TARGET)?;

		// Load keypair
		let mut config = HeaderConfig::default();
		let mut keypair = File::open(KEYPAIR)?;
		keypair.seek(SeekFrom::Start(crate::SECRET_KEY_LENGTH as u64))?;
		config.load_public_key(keypair)?;

		let mut archive = Archive::with_config(target, &config)?;
		dbg!(archive.entries());
		let resource = archive.fetch("test_data/song.txt")?;
		let song = str::from_utf8(resource.data.as_slice())?;

		// Check identity of retrieved data
		println!("{}", song);

		// Windows bullshit
		#[cfg(target_os = "windows")]
		{
			assert_eq!(song.len(), 2041);
		}
		#[cfg(not(any(target_os = "windows", target_os = "ios")))]
		{
			assert_eq!(song.len(), 1977);
		}

		assert!(resource.secured);

		Ok(())
	}

	#[test]
	fn builder_with_signature() -> anyhow::Result<()> {
		let mut builder = Builder::default();

		let mut build_config = BuilderConfig::default();
		build_config.load_keypair(File::open(KEYPAIR)?)?;

		builder.add_dir("test_data", &Leaf::default().compress(CompressMode::Detect))?;

		let mut target = File::create(SIGNED_TARGET)?;
		println!(
			"Number of bytes written: {}, into signed archive.",
			builder.dump(&mut target, &build_config)?
		);

		Ok(())
	}

	#[test]
	fn fetch_write_with_signature() -> anyhow::Result<()> {
		let target = File::open(SIGNED_TARGET)?;

		// Load keypair
		let mut config = HeaderConfig::default();
		let mut keypair = File::open(KEYPAIR)?;
		keypair.seek(SeekFrom::Start(crate::SECRET_KEY_LENGTH as u64))?;
		config.load_public_key(keypair)?;

		let mut archive = Archive::with_config(target, &config)?;
		let mut song = Vec::new();

		let metadata = archive.fetch_write("test_data/poem.txt", &mut song)?;
		assert!(metadata.2);

		// Assert identity of retrieved data
		println!("{}", str::from_utf8(&song)?);

		// Windows bullshit
		#[cfg(target_os = "windows")]
		{
			assert_eq!(song.len(), 359);
		}
		#[cfg(not(any(target_os = "windows", target_os = "ios")))]
		{
			assert_eq!(song.len(), 345);
		}

		Ok(())
	}

	#[test]
	fn gen_keypair() -> anyhow::Result<()> {
		use crate::utils::gen_keypair;

		// NOTE: regenerating new keys will break some tests
		let regenerate = false;

		if regenerate {
			let keypair = gen_keypair();

			std::fs::write(KEYPAIR, &keypair.to_bytes())?;
		};

		Ok(())
	}

	#[test]
	#[should_panic]
	fn flag_restricted_access() {
		let mut flag = Flags::from_bits(0b1111_1000_0000_0000);
		flag.set(Flags::COMPRESSED_FLAG, true).unwrap();
	}

	#[test]
	fn flags_set_intersects() {
		let mut flag = Flags::empty();

		flag.force_set(Flags::COMPRESSED_FLAG, true);
		assert_eq!(flag.bits(), Flags::COMPRESSED_FLAG);

		flag.force_set(Flags::COMPRESSED_FLAG, true);
		assert_eq!(flag.bits(), Flags::COMPRESSED_FLAG);

		flag.force_set(Flags::SIGNED_FLAG, true);
		assert_eq!(flag.bits(), Flags::COMPRESSED_FLAG | Flags::SIGNED_FLAG);

		flag.force_set(Flags::COMPRESSED_FLAG, false);
		assert_eq!(flag.bits(), Flags::SIGNED_FLAG);

		flag.force_set(Flags::COMPRESSED_FLAG, false);
		assert_eq!(flag.bits(), Flags::SIGNED_FLAG);

		flag.force_set(Flags::COMPRESSED_FLAG | Flags::SIGNED_FLAG, true);
		assert_eq!(flag.bits(), Flags::COMPRESSED_FLAG | Flags::SIGNED_FLAG);
	}
}
