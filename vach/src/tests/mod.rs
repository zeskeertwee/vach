#![cfg(test)]
// This is meant to mirror as closely as possible, how users should use the crate

// Boring, average every day contemporary imports
use std::{fs::File, str};
use crate::prelude::*;

// Contains both the public key and secret key in the same file:
// secret -> [u8; crate::SECRET_KEY_LENGTH], public -> [u8; crate::PUBLIC_KEY_LENGTH]
const KEYPAIR: &[u8; crate::KEYPAIR_LENGTH] = include_bytes!("../../test_data/pair.pub");

// The paths to the Archives, to be written|loaded
const SIGNED_TARGET: &str = "test_data/signed/target.vach";
const SIMPLE_TARGET: &str = "test_data/simple/target.vach";
const ENCRYPTED_TARGET: &str = "test_data/encrypted/target.vach";

// Custom bitflag tests
const CUSTOM_FLAG_1: u32 = 0b0000_0000_0000_0000_0000_1000_0000_0000;
const CUSTOM_FLAG_2: u32 = 0b0000_0000_0000_0000_0000_0100_0000_0000;
const CUSTOM_FLAG_3: u32 = 0b0000_0000_0000_0000_0000_0000_1000_0000;
const CUSTOM_FLAG_4: u32 = 0b0000_0000_0000_0000_0000_0000_0001_0000;

#[test]
#[cfg(feature = "archive")]
fn custom_bitflags() -> InternalResult {
	let target = File::open(SIMPLE_TARGET)?;
	let archive = Archive::from_handle(target)?;
	let entry = archive.fetch_entry("poem").unwrap();
	let flags = entry.flags;

	assert_eq!(flags.bits(), entry.flags.bits());
	assert!(flags.contains(CUSTOM_FLAG_1 | CUSTOM_FLAG_2 | CUSTOM_FLAG_3 | CUSTOM_FLAG_4));

	dbg!(flags);

	Ok(())
}

#[test]
fn flag_restricted_access() {
	let mut flag = Flags::from_bits(0b1111_1000_0000_0000);

	// This should return an error
	if let Err(error) = flag.set(Flags::COMPRESSED_FLAG, true) {
		assert!(matches!(error, InternalError::RestrictedFlagAccessError));
	} else {
		panic!("Access to restricted flags has been allowed, this should not be feasible")
	};
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

#[test]
#[cfg(all(feature = "compression", feature = "builder"))]
fn builder_no_signature() -> InternalResult {
	let mut builder = Builder::default();
	let build_config = BuilderConfig::default();

	builder.add(File::open("test_data/song.txt")?, "song")?;
	builder.add(File::open("test_data/lorem.txt")?, "lorem")?;
	builder.add(File::open("test_data/bee.script")?, "script")?;
	builder.add(File::open("test_data/quicksort.wasm")?, "wasm")?;

	let mut poem_flags = Flags::default();
	poem_flags.set(CUSTOM_FLAG_1 | CUSTOM_FLAG_2 | CUSTOM_FLAG_3 | CUSTOM_FLAG_4, true)?;

	builder.add_leaf(
		Leaf::from_handle(File::open("test_data/poem.txt")?)
			.compress(CompressMode::Always)
			.version(10)
			.id("poem")
			.flags(poem_flags),
	)?;

	builder.add_leaf(
		Leaf::from_handle(b"Hello, Cassandra!" as &[u8])
			.compress(CompressMode::Never)
			.id("greeting"),
	)?;

	let mut target = File::create(SIMPLE_TARGET)?;
	builder.dump(&mut target, &build_config)?;

	Ok(())
}

#[test]
#[cfg(all(feature = "compression", feature = "archive"))]
fn simple_fetch() -> InternalResult {
	let target = File::open(SIMPLE_TARGET)?;
	let archive = Archive::from_handle(target)?;
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

	assert!(!resource.authenticated);
	assert!(resource.flags.contains(Flags::COMPRESSED_FLAG));

	println!("{}", String::from_utf8(resource.data).unwrap());

	let hello = archive.fetch("greeting")?;
	assert_eq!("Hello, Cassandra!", String::from_utf8(hello.data).unwrap());
	assert!(!hello.flags.contains(Flags::COMPRESSED_FLAG));

	Ok(())
}

#[test]
#[cfg(all(feature = "builder", feature = "crypto"))]
fn builder_with_signature() -> InternalResult {
	let mut builder = Builder::default();

	let cb = |_: &str, entry: &RegistryEntry| {
		dbg!(entry);
	};
	let mut build_config = BuilderConfig::default().callback(&cb);

	build_config.load_keypair(KEYPAIR.as_slice())?;

	builder.add_dir("test_data", Some(&Leaf::default().sign(true)))?;

	// Tests conditional signing
	builder.add_leaf(Leaf::default().id("not_signed").sign(false))?;

	let mut target = File::create(SIGNED_TARGET)?;
	println!(
		"Number of bytes written: {}, into signed archive.",
		builder.dump(&mut target, &build_config)?
	);

	Ok(())
}

#[test]
#[cfg(all(feature = "archive", feature = "crypto", feature = "compression"))]
fn fetch_with_signature() -> InternalResult {
	let target = File::open(SIGNED_TARGET)?;

	// Load keypair
	let mut config = ArchiveConfig::default();
	let keypair = &KEYPAIR[crate::SECRET_KEY_LENGTH..];
	config.load_public_key(keypair)?;

	let archive = Archive::with_config(target, &config)?;
	let resource = archive.fetch("test_data/song.txt")?;
	let song = str::from_utf8(resource.data.as_slice()).unwrap();

	// The adjacent resource was flagged to not be signed
	let not_signed_resource = archive.fetch("not_signed")?;
	assert!(!not_signed_resource.flags.contains(Flags::SIGNED_FLAG));
	assert!(!not_signed_resource.authenticated);

	// The adjacent resource was flagged to not be signed
	let not_signed_resource = archive.fetch("not_signed")?;
	assert!(!not_signed_resource.flags.contains(Flags::SIGNED_FLAG));
	assert!(!not_signed_resource.authenticated);

	// Check authenticity of retrieved data
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

	assert!(resource.authenticated);
	assert!(resource.flags.contains(Flags::SIGNED_FLAG));

	Ok(())
}

#[test]
#[cfg(all(feature = "archive", feature = "crypto"))]
fn fetch_write_with_signature() -> InternalResult {
	let target = File::open(SIGNED_TARGET)?;

	// Load keypair
	let mut config = ArchiveConfig::default();
	let keypair = &KEYPAIR[crate::SECRET_KEY_LENGTH..];
	config.load_public_key(keypair)?;

	let archive = Archive::with_config(target, &config)?;
	let mut song = Vec::new();

	let metadata = archive.fetch_write("test_data/poem.txt", &mut song)?;
	assert!(metadata.2);
	assert!(metadata.0.contains(Flags::SIGNED_FLAG));

	// Windows bullshit
	#[cfg(target_os = "windows")]
	{
		assert_eq!(song.len(), 359);
	}
	#[cfg(not(any(target_os = "windows", target_os = "ios")))]
	{
		assert_eq!(song.len(), 345);
	}

	// Assert identity of retrieved data
	println!("{}", String::from_utf8(song).unwrap());

	Ok(())
}

#[test]
#[cfg(feature = "crypto")]
fn edcryptor_test() -> InternalResult {
	use crate::crypto_utils::gen_keypair;

	let pk = gen_keypair().public;

	let crypt = Encryptor::new(&pk, crate::DEFAULT_MAGIC.clone());
	let data = vec![12, 12, 12, 12];

	let ciphertext = crypt.encrypt(&data)?;
	let plaintext = crypt.decrypt(&ciphertext)?;

	assert_ne!(&plaintext, &ciphertext);
	assert_eq!(&plaintext, &data);
	Ok(())
}

#[test]
#[cfg(all(feature = "compression", feature = "builder", feature = "crypto"))]
fn builder_with_encryption() -> InternalResult {
	let mut builder = Builder::new().template(Leaf::default().encrypt(true).compress(CompressMode::Never).sign(true));

	let mut build_config = BuilderConfig::default();
	build_config.load_keypair(KEYPAIR.as_slice())?;

	builder.add_dir("test_data", None)?;
	builder.add_leaf(
		Leaf::from_handle(b"Snitches get stitches, iOS sucks" as &[u8])
			.sign(false)
			.compression_algo(CompressionAlgorithm::Brotli(11))
			.compress(CompressMode::Always)
			.id("stitches.snitches"),
	)?;

	let mut target = File::create(ENCRYPTED_TARGET)?;
	println!(
		"Number of bytes written: {}, into encrypted and fully compressed archive.",
		builder.dump(&mut target, &build_config)?
	);

	Ok(())
}

#[test]
#[cfg(all(feature = "archive", feature = "crypto"))]
fn fetch_from_encrypted() -> InternalResult {
	let target = File::open(ENCRYPTED_TARGET)?;

	// Load keypair
	let mut config = ArchiveConfig::default();
	let public_key = &KEYPAIR[crate::SECRET_KEY_LENGTH..];
	config.load_public_key(public_key)?;

	let archive = Archive::with_config(target, &config)?;
	let resource = archive.fetch("test_data/song.txt")?;
	let song = str::from_utf8(resource.data.as_slice()).unwrap();

	// Windows bullshit
	#[cfg(target_os = "windows")]
	{
		assert_eq!(song.len(), 2041);
	}
	#[cfg(not(any(target_os = "windows", target_os = "ios")))]
	{
		assert_eq!(song.len(), 1977);
	}

	assert!(resource.authenticated);
	assert!(!resource.flags.contains(Flags::COMPRESSED_FLAG));
	assert!(resource.flags.contains(Flags::ENCRYPTED_FLAG));

	Ok(())
}

#[test]
#[cfg(all(feature = "builder", feature = "archive", feature = "crypto"))]
fn consolidated_example() -> InternalResult {
	use crate::crypto_utils::{gen_keypair, read_keypair};
	use std::{io::Cursor, time::Instant};

	const MAGIC: &[u8; crate::MAGIC_LENGTH] = b"CSDTD";
	let mut target = Cursor::new(Vec::<u8>::new());

	// Data to be written
	let data_1 = b"Around The World, Fatter wetter stronker" as &[u8];
	let data_2 = b"Imago" as &[u8];
	let data_3 = b"Fast-Acting Long-Lasting, *Bathroom Reader*" as &[u8];

	// Builder definition
	let keypair_bytes = gen_keypair().to_bytes();
	let config = BuilderConfig::default()
		.magic(*MAGIC)
		.keypair(read_keypair(&keypair_bytes as &[u8])?);
	let mut builder = Builder::new().template(Leaf::default().encrypt(true));

	// Add data
	let template = Leaf::default().encrypt(true).version(59);
	builder.add_leaf(Leaf::from_handle(data_1).id("d1").template(&template))?;
	builder.add_leaf(Leaf::from_handle(data_2).id("d2").template(&template))?;
	builder.add_leaf(Leaf::from_handle(data_3).id("d3").template(&template))?;

	// Dump data
	let then = Instant::now();
	builder.dump(&mut target, &config)?;

	// Just because
	println!("Building took: {}us", then.elapsed().as_micros());

	// Load data
	let mut config = ArchiveConfig::default().magic(*MAGIC);
	config.load_public_key(&keypair_bytes[32..])?;

	let then = Instant::now();
	let archive = Archive::with_config(target, &config)?;

	println!("Archive initialization took: {}us", then.elapsed().as_micros());

	// Quick assertions
	let then = Instant::now();
	assert_eq!(archive.fetch("d1")?.data.as_slice(), data_1);
	assert_eq!(archive.fetch("d2")?.data.as_slice(), data_2);
	assert_eq!(archive.fetch("d3")?.data.as_slice(), data_3);

	println!("Fetching took: {}us on average", then.elapsed().as_micros() / 4u128);

	// All seems ok
	Ok(())
}

#[test]
#[cfg(all(feature = "compression", feature = "builder"))]
fn test_compressors() -> InternalResult {
	use std::io::Cursor;
	const INPUT_LEN: usize = 4096;

	let input = [12u8; INPUT_LEN];
	let mut target = Cursor::new(vec![]);
	let mut builder = Builder::new();

	builder.add_leaf(
		Leaf::from_handle(input.as_slice())
			.id("LZ4")
			.compression_algo(CompressionAlgorithm::LZ4)
			.compress(CompressMode::Always),
	)?;
	builder.add_leaf(
		Leaf::from_handle(input.as_slice())
			.id("BROTLI")
			.compression_algo(CompressionAlgorithm::Brotli(9))
			.compress(CompressMode::Always),
	)?;
	builder.add_leaf(
		Leaf::from_handle(input.as_slice())
			.id("SNAPPY")
			.compression_algo(CompressionAlgorithm::Snappy)
			.compress(CompressMode::Always),
	)?;

	builder.dump(&mut target, &BuilderConfig::default())?;

	let archive = Archive::from_handle(&mut target)?;

	let d1 = archive.fetch("LZ4")?;
	let d2 = archive.fetch("BROTLI")?;
	let d3 = archive.fetch("SNAPPY")?;

	// Identity tests
	assert_eq!(d1.data.len(), INPUT_LEN);
	assert_eq!(d2.data.len(), INPUT_LEN);
	assert_eq!(d3.data.len(), INPUT_LEN);

	assert!(&d1.data[..] == &input);
	assert!(&d2.data[..] == &input);
	assert!(&d3.data[..] == &input);

	// Compression tests
	assert!(archive.fetch_entry("LZ4").unwrap().offset < INPUT_LEN as u64);
	assert!(archive.fetch_entry("BROTLI").unwrap().offset < INPUT_LEN as u64);
	assert!(archive.fetch_entry("SNAPPY").unwrap().offset < INPUT_LEN as u64);

	// A simple test to show that these are somehow not the same data
	assert!(archive.fetch_entry("SNAPPY").unwrap().offset != archive.fetch_entry("LZ4").unwrap().offset);
	assert!(archive.fetch_entry("BROTLI").unwrap().offset != archive.fetch_entry("LZ4").unwrap().offset);
	assert!(archive.fetch_entry("SNAPPY").unwrap().offset != archive.fetch_entry("BROTLI").unwrap().offset);

	Ok(())
}

#[test]
#[cfg(all(feature = "multithreaded", feature = "builder", feature = "archive"))]
fn test_batch_fetching() -> InternalResult {
	use std::{io::Cursor, collections::HashMap};
	use rayon::prelude::*;

	// Define input constants
	const INPUT_LEN: usize = 8;
	const INPUT: [u8; INPUT_LEN] = [69u8; INPUT_LEN];

	let mut target = Cursor::new(vec![]);
	let mut builder = Builder::new();

	// Define and queue data
	let mut ids = vec![];

	for i in 0..120 {
		let id = format!("ID {}", i);
		ids.push(id);

		builder.add(&INPUT[..], ids[i].as_str())?;
	}

	ids.push("ERRORS".to_string());

	// Process data
	builder.dump(&mut target, &BuilderConfig::default())?;

	let archive = Archive::from_handle(target)?;
	let mut resources = ids
		.as_slice()
		.par_iter()
		.map(|id| (id.as_str(), archive.fetch(&id)))
		.collect::<HashMap<_, _>>();

	// Tests and checks
	assert!(resources.get("NON_EXISTENT").is_none());
	assert!(resources.get("ERRORS").is_some());

	match resources.remove("ERRORS").unwrap() {
		Ok(_) => return Err(InternalError::OtherError("This should be an error".into())),
		Err(err) => match err {
			InternalError::MissingResourceError(_) => {
				resources.remove("ERRORS");
			},

			specific => return Err(specific),
		},
	};

	for (_, res) in resources {
		assert_eq!(res?.data.as_slice(), &INPUT[..]);
	}

	Ok(())
}
